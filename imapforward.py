#!/usr/bin/env python3
"""
imapforward.py – IMAP IDLE で一方のINBOXを監視し，新着メールを他方のINBOXにコピーする．

使い方:
  1. config.json を作成（--init で雛形生成）
  2. python imapforward.py config.json
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from imapclient import IMAPClient

# ---------------------------------------------------------------------------
# 設定
# ---------------------------------------------------------------------------

IDLE_TIMEOUT = 300  # IDLE 待機秒数（RFC 2177 は 29分以内を推奨）
RECONNECT_DELAY = 10  # 再接続までの待機秒数
MAX_RECONNECT_DELAY = 300  # 指数バックオフの上限

SAMPLE_CONFIG = {
    "source": {
        "host": "imap.example.com",
        "port": 993,
        "ssl": True,
        "username": "user@example.com",
        "password": "password",
        "folder": "INBOX",
        "done_folder": "DONE",
    },
    "destination": {
        "host": "imap.gmail.com",
        "port": 993,
        "ssl": True,
        "username": "user@example.org",
        "password": "app-password",
        "folder": "INBOX",
    },
    "log_level": "INFO",
}

logger = logging.getLogger("imapforward")


# ---------------------------------------------------------------------------
# データクラス
# ---------------------------------------------------------------------------


@dataclass
class ServerConfig:
    host: str
    port: int
    ssl: bool
    username: str
    password: str
    folder: str = "INBOX"
    done_folder: str = ""  # 空文字列なら移動しない


@dataclass
class MirrorState:
    """コピー済み UID を保持して重複転送を防ぐ."""

    copied_uids: set[int] = field(default_factory=set)
    running: bool = True


# ---------------------------------------------------------------------------
# IMAP 接続ヘルパー
# ---------------------------------------------------------------------------


def connect(cfg: ServerConfig) -> IMAPClient:
    """IMAP サーバに接続してフォルダを SELECT する."""
    logger.info("connecting: %s:%d (%s)", cfg.host, cfg.port, cfg.username)
    client = IMAPClient(cfg.host, port=cfg.port, ssl=cfg.ssl)
    client.login(cfg.username, cfg.password)
    client.select_folder(cfg.folder)
    logger.info("connected: %s/%s", cfg.host, cfg.folder)
    return client


def ensure_folder(client: IMAPClient, folder: str) -> None:
    """フォルダが存在しなければ作成する."""
    if not client.folder_exists(folder):
        client.create_folder(folder)
        logger.info("created: %s", folder)


def move_messages(client: IMAPClient, uids: list[int], dest_folder: str) -> None:
    """メッセージを dest_folder に移動する.

    MOVE 拡張 (RFC 6851) に対応していれば使い，
    非対応なら COPY → +FLAGS \\Deleted → EXPUNGE でフォールバック.
    """
    capabilities = client.capabilities()
    if b"MOVE" in capabilities:
        client.move(uids, dest_folder)
        logger.debug("MOVE 完了: UID %s → %s", uids, dest_folder)
    else:
        client.copy(uids, dest_folder)
        client.add_flags(uids, [b"\\Deleted"])
        client.expunge(uids)
        logger.debug("COPY+DELETE 完了: UID %s → %s", uids, dest_folder)


def safe_disconnect(client: IMAPClient | None, label: str) -> None:
    if client is None:
        return
    try:
        client.logout()
    except Exception:
        logger.debug("%s: logout 失敗（無視）", label)


# ---------------------------------------------------------------------------
# メール取得・転送
# ---------------------------------------------------------------------------


def fetch_and_copy(
    src: IMAPClient,
    dst: IMAPClient,
    src_cfg: ServerConfig,
    dst_cfg: ServerConfig,
    state: MirrorState,
) -> int:
    """Copy UNSEEN messages on src to dst, and return the number of copied messages."""
    uids = src.search(["UNSEEN"])
    if not uids:
        return 0

    # Exclude messages copied before
    new_uids = [u for u in uids if u not in state.copied_uids]
    if not new_uids:
        return 0

    logger.info("Detected %d new emails (UID: %s)", len(new_uids), new_uids)

    fetched = src.fetch(new_uids, ["RFC822", "INTERNALDATE", "FLAGS"])
    copied = 0
    move_targets: list[int] = []
    for uid, data in fetched.items():
        raw_msg: bytes = data[b"RFC822"]
        internal_date = data.get(b"INTERNALDATE")
        flags = data.get(b"FLAGS", ())
        # \Recent は append 時に指定できないので除外
        flags = tuple(f for f in flags if f not in (b"\\Recent", b"\\Seen"))

        try:
            dst.append(dst_cfg.folder, raw_msg, flags=flags, msg_time=internal_date)
            state.copied_uids.add(uid)
            copied += 1
            move_targets.append(uid)
            logger.info("Copied: UID %d (%d bytes)", uid, len(raw_msg))
        except Exception:
            logger.exception("Copy failed: UID %d", uid)

    # コピー成功分をソース側の done_folder に移動
    if move_targets and src_cfg.done_folder:
        try:
            ensure_folder(src, src_cfg.done_folder)
            move_messages(src, move_targets, src_cfg.done_folder)
            logger.info(
                "Moved: %d emails → %s", len(move_targets), src_cfg.done_folder
            )
            # INBOX から消えたので copied_uids に保持する必要がなくなる
            state.copied_uids -= set(move_targets)
        except Exception:
            logger.exception("Move failed: %s → %s", move_targets, src_cfg.done_folder)

    return copied


# ---------------------------------------------------------------------------
# メインループ
# ---------------------------------------------------------------------------


def mirror_loop(src_cfg: ServerConfig, dst_cfg: ServerConfig, state: MirrorState):
    """IDLE 監視 → 新着コピー のループ（1回の接続セッション分）."""
    src: IMAPClient | None = None
    dst: IMAPClient | None = None
    try:
        src = connect(src_cfg)
        dst = connect(dst_cfg)

        # 起動直後に未読を処理
        n = fetch_and_copy(src, dst, src_cfg, dst_cfg, state)
        if n:
            logger.info("Copied (init): %d emails", n)

        sys.exit(0)
        while state.running:
            logger.debug("IDLE 開始 (timeout=%ds)", IDLE_TIMEOUT)
            src.idle()

            try:
                responses = src.idle_check(timeout=IDLE_TIMEOUT)
            except Exception:
                logger.warning("IDLE 中にエラー発生")
                raise
            finally:
                try:
                    src.idle_done()
                except Exception:
                    logger.debug("idle_done 失敗（無視）")

            if responses:
                logger.debug("IDLE 応答: %s", responses)
                n = fetch_and_copy(src, dst, src_cfg, dst_cfg, state)
                if n:
                    logger.info("コピー: %d 件", n)
            else:
                # タイムアウト — NOOP で接続維持
                logger.debug("IDLE タイムアウト — NOOP 送信")
                src.noop()
                dst.noop()

    finally:
        safe_disconnect(src, "source")
        safe_disconnect(dst, "destination")


def run(src_cfg: ServerConfig, dst_cfg: ServerConfig):
    state = MirrorState()
    delay = RECONNECT_DELAY

    # SIGINT / SIGTERM でクリーンに停止
    def _stop(signum, frame):
        logger.info("Got signal %d - terminating", signum)
        state.running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while state.running:
        try:
            mirror_loop(src_cfg, dst_cfg, state)
        except KeyboardInterrupt:
            state.running = False
        except Exception:
            logger.exception("Error - retry after %d sec", delay)
            if state.running:
                time.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)
            continue
        delay = RECONNECT_DELAY

    logger.info("Terminated")



def load_config(path: str) -> tuple[ServerConfig, ServerConfig]:
    with open(path) as f:
        cfg = json.load(f)

    log_level = cfg.get("log_level", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    src = ServerConfig(**cfg["source"])
    dst = ServerConfig(**cfg["destination"])
    return src, dst


def main():
    parser = argparse.ArgumentParser(description="IMAP INBOX forwarder")
    parser.add_argument("config", nargs="?", help="config.json")
    parser.add_argument(
        "--init",
        metavar="PATH",
        help="Create an initial config and exit.",
    )
    args = parser.parse_args()

    if args.init:
        p = Path(args.init)
        p.write_text(json.dumps(SAMPLE_CONFIG, indent=2, ensure_ascii=False))
        print(f"Created: {p}")
        sys.exit(0)

    if not args.config:
        parser.print_help()
        sys.exit(1)

    src_cfg, dst_cfg = load_config(args.config)
    run(src_cfg, dst_cfg)


if __name__ == "__main__":
    main()
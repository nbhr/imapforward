#!/usr/bin/env python3
"""
imap_mirror.py – IMAP IDLE で一方のINBOXを監視し，新着メールを他方にコピーする．

コピー先 (destination) は IMAP または Gmail API (messages.import) を選択可能．
Gmail API を使うと push 通知が発火する．

使い方:
  1. config.json を作成（--init で雛形生成）
  2. Gmail API を使う場合:
       pip install google-api-python-client google-auth-oauthlib
       python imap_mirror.py config.json --auth   # 初回のみ: ブラウザで認可
  3. python imap_mirror.py config.json
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import signal
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from imapclient import IMAPClient

# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

IDLE_TIMEOUT = 300  # IDLE 待機秒数（RFC 2177 は 29分以内を推奨）
RECONNECT_DELAY = 10  # 再接続までの待機秒数
MAX_RECONNECT_DELAY = 300  # 指数バックオフの上限

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.insert"]

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
        "type": "gmail_api",
        "credentials_file": "credentials.json",
        "token_file": "token.json",
        "never_mark_spam": True,
    },
    "_destination_imap_example": {
        "type": "imap",
        "host": "imap.example.org",
        "port": 993,
        "ssl": True,
        "username": "user@example.org",
        "password": "password",
        "folder": "INBOX",
    },
    "log_level": "INFO",
}

logger = logging.getLogger("imap_mirror")


# ---------------------------------------------------------------------------
# データクラス
# ---------------------------------------------------------------------------


@dataclass
class SourceConfig:
    host: str
    port: int
    ssl: bool
    username: str
    password: str
    folder: str = "INBOX"
    done_folder: str = ""


@dataclass
class MirrorState:
    """コピー済み UID を保持して重複転送を防ぐ."""

    copied_uids: set[int] = field(default_factory=set)
    running: bool = True


# ---------------------------------------------------------------------------
# Destination 抽象クラス
# ---------------------------------------------------------------------------


class Destination(ABC):
    """コピー先の抽象インタフェース."""

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def deliver(self, raw_msg: bytes) -> None:
        """RFC822 メッセージを配送する."""

    @abstractmethod
    def keepalive(self) -> None:
        """接続維持のための操作."""

    @abstractmethod
    def disconnect(self) -> None: ...


# ---------------------------------------------------------------------------
# IMAP Destination
# ---------------------------------------------------------------------------


class ImapDestination(Destination):
    def __init__(self, host: str, port: int, ssl: bool,
                 username: str, password: str, folder: str = "INBOX",
                 **_kwargs):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.username = username
        self.password = password
        self.folder = folder
        self._client: IMAPClient | None = None

    def connect(self) -> None:
        logger.info("DST 接続中 (IMAP): %s:%d", self.host, self.port)
        self._client = IMAPClient(self.host, port=self.port, ssl=self.ssl)
        self._client.login(self.username, self.password)
        self._client.select_folder(self.folder)
        logger.info("DST 接続完了: %s/%s", self.host, self.folder)

    def deliver(self, raw_msg: bytes) -> None:
        assert self._client is not None
        self._client.append(self.folder, raw_msg, flags=(), msg_time=None)

    def keepalive(self) -> None:
        if self._client:
            self._client.noop()

    def disconnect(self) -> None:
        if self._client:
            try:
                self._client.logout()
            except Exception:
                logger.debug("DST logout 失敗（無視）")
            self._client = None


# ---------------------------------------------------------------------------
# Gmail API Destination
# ---------------------------------------------------------------------------


class GmailDestination(Destination):
    def __init__(self, credentials_file: str, token_file: str,
                 never_mark_spam: bool = True, **_kwargs):
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.never_mark_spam = never_mark_spam
        self._service = None

    def connect(self) -> None:
        creds = self._load_credentials()
        self._service = self._build_service(creds)
        # 接続確認
        profile = self._service.users().getProfile(userId="me").execute()
        logger.info("DST 接続完了 (Gmail API): %s", profile.get("emailAddress"))

    def deliver(self, raw_msg: bytes) -> None:
        assert self._service is not None
        encoded = base64.urlsafe_b64encode(raw_msg).decode("ascii")
        body = {"raw": encoded}
        result = self._service.users().messages().import_(
            userId="me",
            body=body,
            internalDateSource="dateHeader",
            neverMarkSpam=self.never_mark_spam,
        ).execute()
        logger.debug("Gmail import 完了: id=%s", result.get("id"))

    def keepalive(self) -> None:
        # HTTP ベースなので keepalive 不要
        pass

    def disconnect(self) -> None:
        self._service = None

    # -- 内部メソッド --

    def _load_credentials(self):
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials

        token_path = Path(self.token_file)
        creds = None
        if token_path.exists():
            creds = Credentials.from_authorized_user_file(
                str(token_path), GMAIL_SCOPES
            )
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            token_path.write_text(creds.to_json())
            logger.info("Gmail トークンを更新しました")
        if not creds or not creds.valid:
            raise RuntimeError(
                f"有効な認証トークンがありません: {self.token_file}\n"
                "  --auth オプションで認可を実行してください"
            )
        return creds

    @staticmethod
    def _build_service(creds):
        from googleapiclient.discovery import build

        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    @classmethod
    def authorize(cls, credentials_file: str, token_file: str) -> None:
        """OAuth2 認可フローを実行し token_file に保存する.

        ローカルにHTTPサーバを立てて認可コードを受け取る．
        headless 環境では表示された URL を手元のブラウザで開き，
        SSH ポートフォワーディングでリダイレクトを中継する．
        """
        from google_auth_oauthlib.flow import InstalledAppFlow

        AUTH_PORT = 8085

        flow = InstalledAppFlow.from_client_secrets_file(
            credentials_file, GMAIL_SCOPES
        )

        print(f"ポート {AUTH_PORT} でリダイレクトを待ち受けます．")
        print(f"リモートサーバの場合は別ターミナルで:")
        print(f"  ssh -L {AUTH_PORT}:localhost:{AUTH_PORT} <server>")
        print()

        creds = flow.run_local_server(
            port=AUTH_PORT,
            open_browser=False,
            authorization_prompt_message=(
                "以下の URL をブラウザで開いて認可してください:\n{url}"
            ),
            success_message="認可完了！ このタブを閉じてください．",
        )
        Path(token_file).write_text(creds.to_json())
        print(f"認可完了 — トークンを保存しました: {token_file}")


# ---------------------------------------------------------------------------
# Destination ファクトリ
# ---------------------------------------------------------------------------


def create_destination(cfg: dict) -> Destination:
    dst_type = cfg.get("type", "imap")
    params = {k: v for k, v in cfg.items() if k != "type"}
    if dst_type == "imap":
        return ImapDestination(**params)
    elif dst_type == "gmail_api":
        return GmailDestination(**params)
    else:
        raise ValueError(f"未対応の destination type: {dst_type}")


# ---------------------------------------------------------------------------
# ソース側 IMAP ヘルパー
# ---------------------------------------------------------------------------


def connect_source(cfg: SourceConfig) -> IMAPClient:
    logger.info("SRC 接続中: %s:%d (%s)", cfg.host, cfg.port, cfg.username)
    client = IMAPClient(cfg.host, port=cfg.port, ssl=cfg.ssl)
    client.login(cfg.username, cfg.password)
    client.select_folder(cfg.folder)
    logger.info("SRC 接続完了: %s/%s", cfg.host, cfg.folder)
    return client


def ensure_folder(client: IMAPClient, folder: str) -> None:
    if not client.folder_exists(folder):
        client.create_folder(folder)
        logger.info("フォルダ作成: %s", folder)


def move_messages(client: IMAPClient, uids: list[int], dest_folder: str) -> None:
    capabilities = client.capabilities()
    if b"MOVE" in capabilities:
        client.move(uids, dest_folder)
        logger.debug("MOVE 完了: UID %s → %s", uids, dest_folder)
    else:
        client.copy(uids, dest_folder)
        client.add_flags(uids, [b"\\Deleted"])
        client.expunge(uids)
        logger.debug("COPY+DELETE 完了: UID %s → %s", uids, dest_folder)


# ---------------------------------------------------------------------------
# メール取得・転送
# ---------------------------------------------------------------------------


def fetch_and_copy(
    src: IMAPClient,
    dst: Destination,
    src_cfg: SourceConfig,
    state: MirrorState,
) -> int:
    """src の UNSEEN メッセージを dst に配送する．件数を返す."""
    uids = src.search(["UNSEEN"])
    if not uids:
        return 0

    new_uids = [u for u in uids if u not in state.copied_uids]
    if not new_uids:
        return 0

    logger.info("新着 %d 件を検出 (UID: %s)", len(new_uids), new_uids)

    fetched = src.fetch(new_uids, ["RFC822"])
    copied = 0
    move_targets: list[int] = []
    for uid, data in fetched.items():
        raw_msg: bytes = data[b"RFC822"]
        try:
            dst.deliver(raw_msg)
            state.copied_uids.add(uid)
            copied += 1
            move_targets.append(uid)
            logger.info("配送完了: UID %d (%d bytes)", uid, len(raw_msg))
        except Exception:
            logger.exception("配送失敗: UID %d", uid)

    # コピー成功分をソース側の done_folder に移動
    if move_targets and src_cfg.done_folder:
        try:
            ensure_folder(src, src_cfg.done_folder)
            move_messages(src, move_targets, src_cfg.done_folder)
            logger.info(
                "移動完了: %d 件 → %s", len(move_targets), src_cfg.done_folder
            )
            state.copied_uids -= set(move_targets)
        except Exception:
            logger.exception("移動失敗: %s → %s", move_targets, src_cfg.done_folder)

    return copied


# ---------------------------------------------------------------------------
# メインループ
# ---------------------------------------------------------------------------


def mirror_loop(
    src_cfg: SourceConfig, dst: Destination, state: MirrorState
):
    src: IMAPClient | None = None
    try:
        src = connect_source(src_cfg)
        dst.connect()

        # 起動直後に未読を処理
        n = fetch_and_copy(src, dst, src_cfg, state)
        if n:
            logger.info("初回配送: %d 件", n)

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
                n = fetch_and_copy(src, dst, src_cfg, state)
                if n:
                    logger.info("配送: %d 件", n)
            else:
                logger.debug("IDLE タイムアウト — keepalive")
                src.noop()
                dst.keepalive()

    finally:
        if src:
            try:
                src.logout()
            except Exception:
                logger.debug("SRC logout 失敗（無視）")
        dst.disconnect()


def run(src_cfg: SourceConfig, dst: Destination):
    state = MirrorState()
    delay = RECONNECT_DELAY

    def _stop(signum, frame):
        logger.info("シグナル %d を受信 — 停止します", signum)
        state.running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while state.running:
        try:
            mirror_loop(src_cfg, dst, state)
        except KeyboardInterrupt:
            state.running = False
        except Exception:
            logger.exception("接続エラー — %d 秒後に再接続", delay)
            if state.running:
                time.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)
            continue
        delay = RECONNECT_DELAY

    logger.info("終了しました")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_config(path: str) -> tuple[SourceConfig, dict]:
    """設定ファイルを読み込み (SourceConfig, destination の生dict) を返す."""
    with open(path) as f:
        cfg = json.load(f)

    log_level = cfg.get("log_level", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    src = SourceConfig(**cfg["source"])
    return src, cfg["destination"]


def main():
    parser = argparse.ArgumentParser(description="IMAP INBOX ミラーリング")
    parser.add_argument("config", nargs="?", help="config.json のパス")
    parser.add_argument(
        "--init", metavar="PATH",
        help="設定ファイルの雛形を生成して終了",
    )
    parser.add_argument(
        "--auth", action="store_true",
        help="Gmail API の OAuth2 認可を実行して終了",
    )
    args = parser.parse_args()

    if args.init:
        p = Path(args.init)
        p.write_text(json.dumps(SAMPLE_CONFIG, indent=2, ensure_ascii=False))
        print(f"雛形を作成しました: {p}")
        sys.exit(0)

    if not args.config:
        parser.print_help()
        sys.exit(1)

    src_cfg, dst_raw = load_config(args.config)

    # --auth: Gmail API の認可フローのみ実行
    if args.auth:
        if dst_raw.get("type") != "gmail_api":
            print(
                "エラー: --auth は destination.type が gmail_api の場合のみ有効です",
                file=sys.stderr,
            )
            sys.exit(1)
        GmailDestination.authorize(
            dst_raw["credentials_file"], dst_raw["token_file"]
        )
        sys.exit(0)

    dst = create_destination(dst_raw)
    run(src_cfg, dst)


if __name__ == "__main__":
    main()
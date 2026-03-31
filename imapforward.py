#!/usr/bin/env python3
"""
imapforward.py – Monitor an IMAP INBOX via IDLE and forward new messages
to another destination.

Destination can be IMAP or Gmail API (messages.import).
Gmail API with explicit UNREAD label triggers push notifications.

Usage:
  1. Create config.json (use --init to generate a template)
  2. For Gmail API:
       pip install google-api-python-client google-auth-oauthlib
       python imapforward.py config.json --auth   # first time only
  3. python imapforward.py config.json
"""

from __future__ import annotations

import argparse
import base64
import datetime
import email
import email.header
import email.utils
import json
import logging
import signal
import socket
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from pathlib import Path

from imapclient import IMAPClient

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IDLE_TIMEOUT = 300  # IDLE wait in seconds (RFC 2177 recommends < 29 min)
RECONNECT_DELAY = 10  # Initial reconnect delay in seconds
MAX_RECONNECT_DELAY = 300  # Exponential backoff cap
PURGE_INTERVAL = 86400  # Run done_folder purge at most once per day
SOCKET_TIMEOUT = 60  # Timeout for individual socket operations (seconds)
TCP_KEEPALIVE_IDLE = 60  # Seconds before first keepalive probe
TCP_KEEPALIVE_INTERVAL = 15  # Seconds between keepalive probes
TCP_KEEPALIVE_COUNT = 4  # Failed probes before connection is dropped
GMAIL_HTTP_TIMEOUT = 300  # Timeout for Gmail API HTTP requests (seconds)
GMAIL_NUM_RETRIES = 3  # Retry count for transient Gmail API errors

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
        "done_retention_days": 365,
        "failed_folder": "FAILED",
        "notify_on_failure": True,
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

logger = logging.getLogger("imapforward")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SourceConfig:
    host: str
    port: int
    ssl: bool
    username: str
    password: str
    folder: str = "INBOX"
    done_folder: str = ""  # Empty string disables move-after-copy
    done_retention_days: int = 0  # 0 disables purging old messages
    failed_folder: str = ""  # Empty string leaves failed messages in source folder
    notify_on_failure: bool = True  # Deliver a notice to dst when messages fail


@dataclass
class MirrorState:
    """Track copied UIDs to prevent duplicate delivery."""

    copied_uids: set[int] = field(default_factory=set)
    running: bool = True
    last_purge: float = 0.0  # time.time() of last purge run


# ---------------------------------------------------------------------------
# Destination abstract class
# ---------------------------------------------------------------------------


class Destination(ABC):
    """Abstract interface for delivery backends."""

    @abstractmethod
    def connect(self) -> None: ...

    @abstractmethod
    def deliver(self, raw_msg: bytes) -> None:
        """Deliver an RFC822 message."""

    @abstractmethod
    def keepalive(self) -> None:
        """Keep the connection alive."""

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
        logger.info("DST connecting (IMAP): %s:%d", self.host, self.port)
        self._client = IMAPClient(self.host, port=self.port, ssl=self.ssl)
        self._client.login(self.username, self.password)
        configure_socket(self._client)
        self._client.select_folder(self.folder)
        logger.info("DST connected: %s/%s", self.host, self.folder)

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
                logger.debug("DST logout failed (ignored)")
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
        self._creds = None

    def connect(self) -> None:
        self._creds = self._load_credentials()
        self._service = self._build_service(self._creds)
        logger.info("DST connected (Gmail API)")

    def deliver(self, raw_msg: bytes) -> None:
        assert self._service is not None
        encoded = base64.urlsafe_b64encode(raw_msg).decode("ascii")
        body = {"raw": encoded, "labelIds": ["INBOX", "UNREAD"]}
        result = self._service.users().messages().import_(
            userId="me",
            body=body,
            internalDateSource="dateHeader",
            neverMarkSpam=self.never_mark_spam,
        ).execute(num_retries=GMAIL_NUM_RETRIES)
        logger.info(
            "Gmail import done: id=%s, labels=%s",
            result.get("id"),
            result.get("labelIds"),
        )
        # Persist refreshed token to disk so it survives restarts
        self._save_credentials()

    def keepalive(self) -> None:
        # HTTP-based; no keepalive needed
        pass

    def disconnect(self) -> None:
        # Save token one last time on disconnect
        self._save_credentials()
        self._service = None
        self._creds = None

    # -- Internal methods --

    def _save_credentials(self) -> None:
        """Write current credentials to disk if available."""
        if self._creds is not None:
            Path(self.token_file).write_text(self._creds.to_json())

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
            logger.info("Gmail token refreshed")
        if not creds or not creds.valid:
            raise RuntimeError(
                f"No valid auth token found: {self.token_file}\n"
                "  Run with --auth to authorize"
            )
        return creds

    @staticmethod
    def _build_service(creds):
        import google_auth_httplib2
        import httplib2
        from googleapiclient.discovery import build

        http = google_auth_httplib2.AuthorizedHttp(
            creds, http=httplib2.Http(timeout=GMAIL_HTTP_TIMEOUT)
        )
        return build("gmail", "v1", http=http, cache_discovery=False)

    @classmethod
    def authorize(cls, credentials_file: str, token_file: str) -> None:
        """Run the OAuth2 authorization flow and save the token.

        No local server required. After authorization, the browser
        redirects to a non-listening URL; the user copies the full
        redirect URL from the address bar and pastes it here.
        """
        from google_auth_oauthlib.flow import Flow
        from urllib.parse import urlparse, parse_qs

        REDIRECT_URI = "http://localhost:1"  # Not actually connected to

        flow = Flow.from_client_secrets_file(
            credentials_file,
            scopes=GMAIL_SCOPES,
            redirect_uri=REDIRECT_URI,
        )

        auth_url, state = flow.authorization_url(
            access_type="offline",
            prompt="consent",
        )

        print("Open the following URL in your browser to authorize:\n")
        print(auth_url)
        print()
        print('After authorization, the browser will show a')
        print('"site can\'t be reached" error. This is expected.')
        print("Copy the entire URL from the address bar and paste it below.")
        print()
        redirect_response = input("Redirect URL: ").strip()

        # Extract the authorization code from the URL
        parsed = urlparse(redirect_response)
        params = parse_qs(parsed.query)
        if "code" not in params:
            print("Error: no authorization code found in URL", file=sys.stderr)
            sys.exit(1)

        flow.fetch_token(code=params["code"][0])
        Path(token_file).write_text(flow.credentials.to_json())
        print(f"Authorization complete. Token saved to: {token_file}")


# ---------------------------------------------------------------------------
# Destination factory
# ---------------------------------------------------------------------------


def create_destination(cfg: dict) -> Destination:
    dst_type = cfg.get("type", "imap")
    params = {k: v for k, v in cfg.items() if k != "type"}
    if dst_type == "imap":
        return ImapDestination(**params)
    elif dst_type == "gmail_api":
        return GmailDestination(**params)
    else:
        raise ValueError(f"Unsupported destination type: {dst_type}")


# ---------------------------------------------------------------------------
# Source IMAP helpers
# ---------------------------------------------------------------------------


def configure_socket(client: IMAPClient) -> None:
    """Enable TCP keepalive and set socket timeout on an IMAP connection.

    TCP keepalive detects half-open connections at the OS level.
    Socket timeout prevents indefinite blocking on send/recv.
    """
    sock = client._imap.socket()

    # Socket-level operation timeout
    sock.settimeout(SOCKET_TIMEOUT)

    # TCP keepalive
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        # Linux
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, TCP_KEEPALIVE_IDLE)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, TCP_KEEPALIVE_INTERVAL)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, TCP_KEEPALIVE_COUNT)
    elif hasattr(socket, "TCP_KEEPALIVE"):
        # macOS
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, TCP_KEEPALIVE_IDLE)

    logger.debug(
        "Socket configured: timeout=%ds, keepalive idle=%ds intvl=%ds cnt=%d",
        SOCKET_TIMEOUT, TCP_KEEPALIVE_IDLE, TCP_KEEPALIVE_INTERVAL, TCP_KEEPALIVE_COUNT,
    )


def connect_source(cfg: SourceConfig) -> IMAPClient:
    logger.info("SRC connecting: %s:%d (%s)", cfg.host, cfg.port, cfg.username)
    client = IMAPClient(cfg.host, port=cfg.port, ssl=cfg.ssl)
    client.login(cfg.username, cfg.password)
    configure_socket(client)
    client.select_folder(cfg.folder)
    logger.info("SRC connected: %s/%s", cfg.host, cfg.folder)
    return client


def ensure_folder(client: IMAPClient, folder: str) -> None:
    """Create the folder if it does not exist."""
    if not client.folder_exists(folder):
        client.create_folder(folder)
        logger.info("Created folder: %s", folder)


def move_messages(client: IMAPClient, uids: list[int], dest_folder: str) -> None:
    """Move messages to dest_folder.

    Uses MOVE (RFC 6851) if available, otherwise falls back to
    COPY + \\Deleted flag + EXPUNGE.
    """
    capabilities = client.capabilities()
    if b"MOVE" in capabilities:
        client.move(uids, dest_folder)
        logger.debug("MOVE done: UID %s -> %s", uids, dest_folder)
    else:
        client.copy(uids, dest_folder)
        client.add_flags(uids, [b"\\Deleted"])
        client.expunge(uids)
        logger.debug("COPY+DELETE done: UID %s -> %s", uids, dest_folder)


def purge_done_folder(client: IMAPClient, src_cfg: SourceConfig) -> int:
    """Delete messages older than done_retention_days from done_folder.

    Temporarily selects done_folder, searches for old messages,
    deletes them, then re-selects the source folder.
    Returns the number of deleted messages.
    """
    if not src_cfg.done_folder or src_cfg.done_retention_days <= 0:
        return 0

    cutoff = datetime.date.today() - datetime.timedelta(days=src_cfg.done_retention_days)
    cutoff_str = cutoff.strftime("%d-%b-%Y")  # IMAP date format

    client.select_folder(src_cfg.done_folder)
    try:
        uids = client.search(["BEFORE", cutoff_str])
        if not uids:
            return 0

        client.add_flags(uids, [b"\\Deleted"])
        client.expunge(uids)
        logger.info(
            "Purged %d message(s) older than %s from %s",
            len(uids), cutoff_str, src_cfg.done_folder,
        )
        return len(uids)
    finally:
        # Re-select the source folder to resume IDLE
        client.select_folder(src_cfg.folder)


# ---------------------------------------------------------------------------
# Fetch and deliver
# ---------------------------------------------------------------------------


def decode_mime_header(value: str) -> str:
    """Decode an RFC 2047 MIME-encoded header into a readable string."""
    parts = email.header.decode_header(value)
    decoded = []
    for data, charset in parts:
        if isinstance(data, bytes):
            decoded.append(data.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(data)
    return "".join(decoded)


def build_failure_notice(
    failed_info: list[tuple[int, str, str, str]],
    src_cfg: SourceConfig,
) -> bytes:
    """Build an RFC822 notice listing messages that failed delivery.

    failed_info: list of (uid, subject, sender, reason) tuples.
    Returns raw RFC822 bytes.
    """
    lines = []
    for uid, subject, sender, reason in failed_info:
        lines.append(
            f"  UID {uid}:\n"
            f"    From:    {sender}\n"
            f"    Subject: {subject}\n"
            f"    Reason:  {reason}\n"
        )
    body = (
        f"{len(failed_info)} message(s) could not be delivered and "
        f"moved to '{src_cfg.failed_folder}' on {src_cfg.host}.\n"
        f"\n"
        + "\n".join(lines)
        + "Please check the folder manually.\n"
    )

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = f"[imapforward] {len(failed_info)} delivery failure(s)"
    msg["From"] = f"imapforward <{src_cfg.username}>"
    msg["To"] = src_cfg.username
    msg["Date"] = email.utils.formatdate(localtime=True)
    return msg.as_bytes()


def fetch_and_copy(
    src: IMAPClient,
    dst: Destination,
    src_cfg: SourceConfig,
    state: MirrorState,
) -> int:
    """Deliver UNSEEN messages from src to dst. Returns the count."""
    uids = src.search(["UNSEEN"])
    if not uids:
        return 0

    new_uids = [u for u in uids if u not in state.copied_uids]
    if not new_uids:
        return 0

    logger.info("Found %d new message(s) (UID: %s)", len(new_uids), new_uids)

    fetched = src.fetch(new_uids, ["RFC822"])
    copied = 0
    move_targets: list[int] = []
    failed_targets: list[int] = []
    failed_info: list[tuple[int, str, str, str]] = []
    for uid, data in fetched.items():
        raw_msg: bytes = data[b"RFC822"]
        try:
            dst.deliver(raw_msg)
            state.copied_uids.add(uid)
            copied += 1
            move_targets.append(uid)
            logger.info("Delivered: UID %d (%d bytes)", uid, len(raw_msg))
        except Exception as exc:
            logger.exception("Delivery failed: UID %d", uid)
            failed_targets.append(uid)
            # Extract headers for the failure notice
            parsed = email.message_from_bytes(raw_msg)
            failed_info.append((
                uid,
                decode_mime_header(parsed.get("Subject", "(no subject)")),
                decode_mime_header(parsed.get("From", "(unknown)")),
                str(exc),
            ))

    # Move successfully copied messages to done_folder on source
    if move_targets and src_cfg.done_folder:
        try:
            ensure_folder(src, src_cfg.done_folder)
            move_messages(src, move_targets, src_cfg.done_folder)
            logger.info(
                "Moved %d message(s) -> %s", len(move_targets), src_cfg.done_folder
            )
            # No longer in INBOX; safe to remove from tracking set
            state.copied_uids -= set(move_targets)
        except Exception:
            logger.exception(
                "Move failed: %s -> %s", move_targets, src_cfg.done_folder
            )

    # Move failed messages to failed_folder to prevent retry loops
    if failed_targets and src_cfg.failed_folder:
        try:
            ensure_folder(src, src_cfg.failed_folder)
            move_messages(src, failed_targets, src_cfg.failed_folder)
            logger.info(
                "Moved %d failed message(s) -> %s",
                len(failed_targets), src_cfg.failed_folder,
            )
        except Exception:
            logger.exception(
                "Move to failed_folder failed: %s -> %s",
                failed_targets, src_cfg.failed_folder,
            )

    # Deliver failure notice to destination
    if failed_info and src_cfg.notify_on_failure:
        try:
            notice = build_failure_notice(failed_info, src_cfg)
            dst.deliver(notice)
            logger.info("Failure notice delivered to destination")
        except Exception:
            logger.exception("Failed to deliver failure notice")

    return copied


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def mirror_loop(
    src_cfg: SourceConfig, dst: Destination, state: MirrorState
):
    """One connection session: connect, process, IDLE loop."""
    src: IMAPClient | None = None
    try:
        src = connect_source(src_cfg)
        dst.connect()

        # Process any existing unseen messages on startup
        n = fetch_and_copy(src, dst, src_cfg, state)
        if n:
            logger.info("Initial delivery: %d message(s)", n)

        while state.running:
            logger.info("IDLE waiting (timeout=%ds)", IDLE_TIMEOUT)
            src.idle()

            try:
                # Poll in short intervals for responsive signal handling
                responses = []
                elapsed = 0
                while state.running and elapsed < IDLE_TIMEOUT:
                    chunk = src.idle_check(timeout=5)
                    if chunk:
                        responses.extend(chunk)
                        break
                    elapsed += 5
            except Exception:
                logger.warning("Error during IDLE")
                raise
            finally:
                try:
                    src.idle_done()
                except Exception:
                    logger.debug("idle_done failed (ignored)")

            if not state.running:
                break

            if responses:
                logger.debug("IDLE response: %s", responses)
                n = fetch_and_copy(src, dst, src_cfg, state)
                if n:
                    logger.info("Delivered: %d message(s)", n)
            else:
                logger.debug("IDLE timeout — sending keepalive")
                src.noop()
                dst.keepalive()
                if time.time() - state.last_purge >= PURGE_INTERVAL:
                    purge_done_folder(src, src_cfg)
                    state.last_purge = time.time()

    finally:
        if src:
            try:
                src.logout()
            except Exception:
                logger.debug("SRC logout failed (ignored)")
        dst.disconnect()


def run(src_cfg: SourceConfig, dst: Destination):
    """Main entry point with automatic reconnection."""
    state = MirrorState()
    delay = RECONNECT_DELAY

    def _stop(signum, frame):
        logger.info("Received signal %d — shutting down", signum)
        state.running = False

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while state.running:
        try:
            mirror_loop(src_cfg, dst, state)
        except KeyboardInterrupt:
            state.running = False
        except Exception:
            logger.exception("Connection error — reconnecting in %ds", delay)
            if state.running:
                time.sleep(delay)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)
            continue
        delay = RECONNECT_DELAY

    logger.info("Shutdown complete")
    sys.exit(0)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_config(path: str) -> tuple[SourceConfig, dict]:
    """Load config file and return (SourceConfig, raw destination dict)."""
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
    parser = argparse.ArgumentParser(description="IMAP INBOX forwarder")
    parser.add_argument("config", nargs="?", help="Path to config.json")
    parser.add_argument(
        "--init", metavar="PATH",
        help="Generate a config template and exit",
    )
    parser.add_argument(
        "--auth", action="store_true",
        help="Run Gmail API OAuth2 authorization and exit",
    )
    args = parser.parse_args()

    if args.init:
        p = Path(args.init)
        p.write_text(json.dumps(SAMPLE_CONFIG, indent=2, ensure_ascii=False))
        print(f"Config template created: {p}")
        sys.exit(0)

    if not args.config:
        parser.print_help()
        sys.exit(1)

    src_cfg, dst_raw = load_config(args.config)

    # --auth: run Gmail API authorization flow only
    if args.auth:
        if dst_raw.get("type") != "gmail_api":
            print(
                "Error: --auth requires destination.type to be gmail_api",
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
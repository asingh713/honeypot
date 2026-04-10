"""Telnet honeypot: raw asyncio TCP server targeting IoT/Mirai-style scanners."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Optional

from honeypot.core.config import TelnetConfig
from honeypot.core.database import Database, EventData
from honeypot.core.geo import GeoLookup
from honeypot.services.base_service import BaseService
from honeypot.services.fake_shell import FakeShell

_MOTD_FILE = Path(__file__).parent.parent / "fake_data" / "telnet_motds.txt"


def _load_motds() -> list[str]:
    if _MOTD_FILE.exists():
        return [m.strip() for m in _MOTD_FILE.read_text().split("---") if m.strip()]
    return ["BusyBox v1.26.2 built-in shell (ash)\r\nEnter 'help' for a list of built-in commands.\r\n"]


class _TelnetSession:
    """Manages one client connection: banner → login → password → fake shell."""

    ENCODING = "utf-8"
    ERRORS = "replace"

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 service: "TelnetHoneypot", motds: list[str]) -> None:
        self._reader = reader
        self._writer = writer
        self._service = service
        self._motds = motds
        self._shell = FakeShell()
        self._session_id = str(uuid.uuid4())
        src = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        self._src_ip, self._src_port = src[0], src[1]

    def _write(self, text: str) -> None:
        self._writer.write(text.encode(self.ENCODING, errors=self.ERRORS))

    async def _readline(self, echo: bool = True) -> str:
        buf = bytearray()
        try:
            while True:
                ch = await asyncio.wait_for(self._reader.read(1), timeout=30)
                if not ch or ch in (b"\r", b"\n"):
                    break
                # Handle backspace
                if ch in (b"\x08", b"\x7f"):
                    if buf:
                        buf.pop()
                    continue
                buf.extend(ch)
                if echo:
                    self._write(ch.decode(self.ENCODING, errors=self.ERRORS))
        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        self._write("\r\n")
        return buf.decode(self.ENCODING, errors=self.ERRORS).strip()

    async def run(self) -> None:
        try:
            await self._greet()
            await self._auth_loop()
        except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
            pass
        finally:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass

    async def _greet(self) -> None:
        import random
        motd = random.choice(self._motds)
        self._write(motd + "\r\n")
        await self._writer.drain()

    async def _auth_loop(self) -> None:
        cfg = self._service._cfg
        for _ in range(3):
            self._write("login: ")
            await self._writer.drain()
            username = await self._readline()

            self._write("Password: ")
            await self._writer.drain()
            password = await self._readline(echo=False)

            self._service.record(EventData(
                service="telnet",
                src_ip=self._src_ip,
                src_port=self._src_port,
                username=username,
                password=password,
                session_id=self._session_id,
            ))

            is_trap = any(
                c.username == username and c.password == password
                for c in cfg.trap_credentials
            )

            if is_trap:
                await asyncio.sleep(0.5)
                self._write(self._shell.motd())
                await self._writer.drain()
                await self._shell_loop()
                return

            await asyncio.sleep(cfg.auth_fail_delay)
            self._write("\r\nLogin incorrect\r\n")
            await self._writer.drain()

        self._write("\r\nMaximum login attempts exceeded.\r\n")
        await self._writer.drain()

    async def _shell_loop(self) -> None:
        cmd_count = 0
        max_cmds = 30
        while cmd_count < max_cmds:
            self._write(self._shell.prompt())
            await self._writer.drain()
            cmd = await self._readline()
            if not cmd:
                continue
            cmd_count += 1
            self._service.record(EventData(
                service="telnet",
                src_ip=self._src_ip,
                src_port=self._src_port,
                command=cmd,
                session_id=self._session_id,
            ))
            response = self._shell.execute(cmd)
            self._write(response)
            await self._writer.drain()
            if cmd in ("exit", "logout"):
                break


class TelnetHoneypot(BaseService):
    service_name = "telnet"

    def __init__(self, cfg: TelnetConfig, db: Database, geo: GeoLookup,
                 max_events_per_ip_per_minute: int = 30) -> None:
        super().__init__(db, geo, max_events_per_ip_per_minute)
        self._cfg = cfg
        self._server: Optional[asyncio.AbstractServer] = None
        self._motds = _load_motds()

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host="0.0.0.0",
            port=self._cfg.port,
        )
        self._log.info("Telnet honeypot listening on port %d", self._cfg.port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = _TelnetSession(reader, writer, self, self._motds)
        await session.run()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._log.info("Telnet honeypot stopped")

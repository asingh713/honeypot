"""SSH honeypot: fake OpenSSH server with tarpit, credential logging, and interactive fake shell."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Optional

import asyncssh

from honeypot.core.config import SSHConfig, TrapCredential
from honeypot.core.database import Database, EventData
from honeypot.core.geo import GeoLookup
from honeypot.services.base_service import BaseService
from honeypot.services.fake_shell import FakeShell


class _HoneypotSSHServerSession(asyncssh.SSHServerSession):
    """Handles an interactive session inside the fake shell."""

    def __init__(self, shell: FakeShell, service: "SSHHoneypot", session_id: str,
                 src_ip: str, src_port: int) -> None:
        self._shell = shell
        self._service = service
        self._session_id = session_id
        self._src_ip = src_ip
        self._src_port = src_port
        self._cmd_count = 0
        self._chan: Optional[asyncssh.SSHServerChannel] = None

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan

    def shell_requested(self) -> bool:
        return True

    def session_started(self) -> None:
        self._chan.write(self._shell.motd())

    def data_received(self, data: str, datatype: asyncssh.DataType) -> None:
        cmd = data.strip()
        if not cmd:
            self._chan.write(self._shell.prompt())
            return

        self._cmd_count += 1
        self._service.record(EventData(
            service="ssh",
            src_ip=self._src_ip,
            src_port=self._src_port,
            command=cmd,
            session_id=self._session_id,
        ))

        if self._cmd_count >= self._service._cfg.max_session_commands:
            self._chan.write("\r\nConnection reset by peer\r\n")
            self._chan.close()
            return

        response = self._shell.execute(cmd)
        self._chan.write(response + self._shell.prompt())

    def eof_received(self) -> None:
        self._chan.close()


class _HoneypotServer(asyncssh.SSHServer):
    """Per-connection server object. Handles auth and session creation."""

    def __init__(self, service: "SSHHoneypot") -> None:
        self._service = service
        self._src_ip: str = ""
        self._src_port: int = 0
        self._session_id: str = str(uuid.uuid4())

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peername = conn.get_extra_info("peername")
        if peername:
            self._src_ip, self._src_port = peername[0], peername[1]

    def connection_lost(self, exc: Optional[Exception]) -> None:
        pass

    def begin_auth(self, username: str) -> bool:
        # Return True to require authentication (always)
        return True

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        cfg = self._service._cfg

        # Always log the attempt
        self._service.record(EventData(
            service="ssh",
            src_ip=self._src_ip,
            src_port=self._src_port,
            username=username,
            password=password,
            session_id=self._session_id,
        ))

        # Check if this is a trap credential
        is_trap = any(
            c.username == username and c.password == password
            for c in cfg.trap_credentials
        )

        if is_trap:
            # Small delay to simulate real auth processing
            await asyncio.sleep(0.5)
            return True

        # Tarpit: delay failed auth to waste scanner time
        await asyncio.sleep(cfg.auth_fail_delay)
        return False

    def session_requested(self) -> _HoneypotSSHServerSession:
        return _HoneypotSSHServerSession(
            shell=FakeShell(),
            service=self._service,
            session_id=self._session_id,
            src_ip=self._src_ip,
            src_port=self._src_port,
        )


class SSHHoneypot(BaseService):
    service_name = "ssh"

    def __init__(self, cfg: SSHConfig, db: Database, geo: GeoLookup,
                 max_events_per_ip_per_minute: int = 30) -> None:
        super().__init__(db, geo, max_events_per_ip_per_minute)
        self._cfg = cfg
        self._server: Optional[asyncssh.SSHAcceptor] = None

    async def start(self) -> None:
        key_path = Path("data/host_key")
        if not key_path.exists():
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
            key.write_private_key(str(key_path))
            self._log.info("Generated new SSH host key at %s", key_path)

        def server_factory() -> _HoneypotServer:
            return _HoneypotServer(self)

        self._server = await asyncssh.create_server(
            server_factory,
            host="0.0.0.0",
            port=self._cfg.port,
            server_host_keys=[str(key_path)],
            server_version=self._cfg.banner,
            # Allow any key type from client (we reject them all at password stage)
            known_client_hosts=None,
        )
        self._log.info("SSH honeypot listening on port %d", self._cfg.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._log.info("SSH honeypot stopped")

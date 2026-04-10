"""Fake interactive shell — returns realistic responses to common attacker commands."""

from __future__ import annotations

import random
from datetime import datetime, timezone


class FakeShell:
    """Simulates a Linux shell to keep attackers engaged and collect command data."""

    _HOSTNAME = "ubuntu-server"
    _USER = "root"
    _KERNEL = "Linux ubuntu-server 4.15.0-88-generic #88-Ubuntu SMP Tue Feb 11 20:11:34 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
    _DISTRO = 'Ubuntu 18.04.4 LTS "Bionic Beaver"'

    # Fake /etc/passwd
    _PASSWD = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
    )

    # Fake /etc/shadow (hashed-looking, not real)
    _SHADOW = (
        "root:$6$rounds=5000$randomsalt$FakeHashedPasswordString1234567890ABCDEFabcdef:18320:0:99999:7:::\n"
        "ubuntu:$6$rounds=5000$anothersalt$AnotherFakeHashString0987654321ZYXWzyx:18320:0:99999:7:::\n"
    )

    _CRONTAB = (
        "# m h  dom mon dow   command\n"
        "*/5 * * * * /usr/bin/collect_metrics.sh\n"
        "0 2 * * * /usr/bin/backup.sh\n"
    )

    _PROCESSES = (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:02 systemd\n"
        "  425 ?        00:00:00 sshd\n"
        "  612 ?        00:00:01 cron\n"
        " 1024 ?        00:00:00 apache2\n"
        " 2048 pts/0    00:00:00 bash\n"
        " 2049 pts/0    00:00:00 ps\n"
    )

    _IFCONFIG = (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
        "        ether 08:00:27:ab:cd:ef  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 12843  bytes 9823764 (9.3 MiB)\n"
        "        TX packets 8192   bytes 1234567 (1.1 MiB)\n"
    )

    def __init__(self) -> None:
        self._cwd = "/root"

    def prompt(self) -> str:
        return f"\r\n{self._USER}@{self._HOSTNAME}:{self._cwd}# "

    def motd(self) -> str:
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        return (
            f"Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-88-generic x86_64)\r\n\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f" * Support:        https://ubuntu.com/advantage\r\n\r\n"
            f"Last login: {now} from 192.168.1.100\r\n"
            + self.prompt()
        )

    def execute(self, cmd: str) -> str:
        """Return a plausible response for the given command."""
        parts = cmd.split()
        base = parts[0] if parts else ""

        handlers = {
            "uname":     self._uname,
            "id":        self._id,
            "whoami":    lambda _: f"\r\n{self._USER}",
            "pwd":       lambda _: f"\r\n{self._cwd}",
            "ls":        self._ls,
            "cat":       self._cat,
            "echo":      self._echo,
            "ps":        lambda _: f"\r\n{self._PROCESSES}",
            "ifconfig":  lambda _: f"\r\n{self._IFCONFIG}",
            "ip":        lambda _: f"\r\n{self._IFCONFIG}",
            "hostname":  lambda _: f"\r\n{self._HOSTNAME}",
            "w":         self._w,
            "who":       lambda _: f"\r\nroot     pts/0        2020-02-18 09:23 (192.168.1.100)",
            "crontab":   self._crontab,
            "wget":      self._wget,
            "curl":      self._curl,
            "cd":        self._cd,
            "mkdir":     lambda _: "",
            "chmod":     lambda _: "",
            "export":    lambda _: "",
            "env":       self._env,
            "history":   lambda _: f"\r\n    1  ls\r\n    2  cd /tmp\r\n    3  uname -a",
            "exit":      lambda _: "\r\nlogout",
            "logout":    lambda _: "\r\nlogout",
        }

        handler = handlers.get(base)
        if handler:
            return handler(parts)

        # Unknown command
        return f"\r\n{cmd}: command not found"

    def _uname(self, parts: list) -> str:
        if "-a" in parts or "--all" in parts:
            return f"\r\n{self._KERNEL}"
        return f"\r\nLinux"

    def _id(self, _: list) -> str:
        return f"\r\nuid=0(root) gid=0(root) groups=0(root)"

    def _ls(self, parts: list) -> str:
        path = parts[1] if len(parts) > 1 else self._cwd
        if "/tmp" in path or path == "/tmp":
            return "\r\n."
        if path in ("/root", "~", "."):
            return "\r\n.bash_history  .bashrc  .profile  .ssh"
        if path == "/etc":
            return "\r\napt  bash.bashrc  cron.d  crontab  group  hostname  hosts  motd  passwd  shadow  sudoers"
        return "\r\nbin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var"

    def _cat(self, parts: list) -> str:
        if len(parts) < 2:
            return ""
        target = parts[-1]
        if "passwd" in target:
            return f"\r\n{self._PASSWD}"
        if "shadow" in target:
            return f"\r\n{self._SHADOW}"
        if "crontab" in target or "cron" in target:
            return f"\r\n{self._CRONTAB}"
        if "hostname" in target:
            return f"\r\n{self._HOSTNAME}"
        if ".bash_history" in target:
            return "\r\nuname -a\r\nid\r\nwhoami\r\nls /tmp\r\ncat /etc/passwd"
        if "hosts" in target:
            return "\r\n127.0.0.1 localhost\r\n127.0.1.1 ubuntu-server"
        return f"\r\ncat: {target}: No such file or directory"

    def _echo(self, parts: list) -> str:
        text = " ".join(parts[1:]) if len(parts) > 1 else ""
        return f"\r\n{text}"

    def _w(self, _: list) -> str:
        now = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return (
            f"\r\n {now} up 12 days,  3:24,  1 user,  load average: 0.08, 0.05, 0.01\r\n"
            f"USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\r\n"
            f"root     pts/0    192.168.1.100    09:23    0.00s  0.04s 0.00s w"
        )

    def _crontab(self, parts: list) -> str:
        if "-l" in parts:
            return f"\r\n{self._CRONTAB}"
        return ""

    def _wget(self, parts: list) -> str:
        url = parts[-1] if len(parts) > 1 else ""
        return (
            f"\r\n--{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n"
            f"Connecting to {url.split('/')[2] if '//' in url else 'host'}... failed: Connection refused."
        )

    def _curl(self, parts: list) -> str:
        return f"\r\ncurl: (7) Failed to connect: Connection refused"

    def _cd(self, parts: list) -> str:
        if len(parts) < 2 or parts[1] in ("~", "/root"):
            self._cwd = "/root"
        elif parts[1] == "/tmp":
            self._cwd = "/tmp"
        elif parts[1] == "/etc":
            self._cwd = "/etc"
        elif parts[1] == "..":
            self._cwd = "/" if self._cwd.count("/") <= 1 else self._cwd.rsplit("/", 1)[0]
        else:
            return f"\r\nbash: cd: {parts[1]}: No such file or directory"
        return ""

    def _env(self, _: list) -> str:
        return (
            "\r\nSHELL=/bin/bash\r\nTERM=xterm-256color\r\nUSER=root\r\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
            "HOME=/root\r\nLOGNAME=root"
        )

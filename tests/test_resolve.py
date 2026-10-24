import struct

from titan.accesses import Access, resolve
from titan.pam import decode_access_list, encode_list_ssh
from titan.thriftbin import STRING, STRUCT, Writer


def _access(id_, name, resource, ip):
    return Access(id_, name, resource, ip)


def test_resolve_one_by_access_name():
    rows = [_access("id-1", "web", "vm-a", "10.0.0.1")]
    assert resolve(rows, "WEB") == rows


def test_resolve_one_by_resource_name():
    rows = [_access("id-1", "web", "vm-a", "10.0.0.1")]
    assert resolve(rows, "VM-A") == rows


def test_resolve_exact_id_is_case_sensitive():
    rows = [_access("AbC", "web", "vm-a", "10.0.0.1")]
    assert resolve(rows, "AbC") == rows
    assert resolve(rows, "abc") == []


def test_resolve_many_and_none():
    rows = [
        _access("1", "same", "vm-a", "10.0.0.1"),
        _access("2", "other", "same", "10.0.0.2"),
    ]
    assert len(resolve(rows, "same")) == 2
    assert resolve(rows, "missing") == []


def test_resolve_exact_ip():
    rows = [_access("id-1", "web", "vm-a", "192.168.105.226")]
    assert resolve(rows, "192.168.105.226") == rows


def test_resolve_ip_tail_octets():
    rows = [_access("id-1", "web", "vm-a", "192.168.105.226")]
    assert resolve(rows, "105.226") == rows
    assert resolve(rows, "168.105.226") == rows


def test_resolve_ip_tail_rejects_partial_octet_and_prefix():
    rows = [_access("id-1", "web", "vm-a", "192.168.105.226")]
    assert resolve(rows, "5.226") == []
    assert resolve(rows, "192.168") == []
    assert resolve(rows, "105.") == []


def test_resolve_shared_ip_tail_returns_both():
    rows = [
        _access("id-1", "web", "vm-a", "192.168.105.226"),
        _access("id-2", "db", "vm-b", "10.1.105.226"),
    ]
    assert resolve(rows, "105.226") == rows


def test_resolve_name_and_ip_count_row_once():
    rows = [_access("id-1", "192.168.105.226", "vm-a", "192.168.105.226")]
    assert resolve(rows, "192.168.105.226") == rows


def test_resolve_blank_ip_ignores_tail():
    rows = [_access("id-1", "web", "vm-a", "")]
    assert resolve(rows, "105.226") == []


def test_list_body_filters_ssh_servers():
    body = encode_list_ssh(0, 100)
    assert b"getSelfAllowedAccess" in body
    assert struct.pack(">i", 1) in body
    assert struct.pack(">i", 2) in body
    assert struct.pack(">i", 3) in body


def test_decode_one_access_hit():
    writer = Writer()
    writer.message("getSelfAllowedAccess", 2, 1)
    writer.field(12, 0)
    writer.field(8, 1)
    writer.i32(1)
    writer.field(15, 2)
    writer.list(STRUCT, 1)
    writer.field(STRING, 1)
    writer.string("id-9")
    writer.field(STRING, 2)
    writer.string("shell")
    writer.field(STRING, 3)
    writer.string("vm")
    writer.field(STRING, 4)
    writer.string("10.1.1.1")
    writer.stop()
    writer.stop()
    writer.stop()
    total, hits = decode_access_list(writer.bytes())
    assert total == 1
    assert hits[0].id == "id-9"
    assert hits[0].name == "shell"
    assert hits[0].resource_name == "vm"
    assert hits[0].resource_ip == "10.1.1.1"

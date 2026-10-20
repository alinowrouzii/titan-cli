"""Strict Thrift binary protocol. Enough for the PAM calls this CLI makes."""

from __future__ import annotations

import struct
from typing import List, Tuple, Union

STOP = 0
BOOL = 2
BYTE = 3
DOUBLE = 4
I16 = 6
I32 = 8
I64 = 10
STRING = 11
STRUCT = 12
MAP = 13
SET = 14
LIST = 15

CALL = 1
REPLY = 2
EXCEPTION = 3

Value = Union[bool, int, float, str, List["Value"], List[Tuple[int, "Value"]]]


class Writer:
    def __init__(self) -> None:
        self.buf = bytearray()

    def bytes(self) -> bytes:
        return bytes(self.buf)

    def message(self, name: str, mtype: int, seqid: int) -> None:
        self.buf += struct.pack(">I", 0x80010000 | mtype)
        self.string(name)
        self.i32(seqid)

    def field(self, ttype: int, fid: int) -> None:
        self.buf.append(ttype & 0xFF)
        self.i16(fid)

    def stop(self) -> None:
        self.buf.append(STOP)

    def i16(self, value: int) -> None:
        self.buf += struct.pack(">h", value)

    def i32(self, value: int) -> None:
        self.buf += struct.pack(">i", value)

    def boolean(self, value: bool) -> None:
        self.buf.append(1 if value else 0)

    def string(self, value: str) -> None:
        raw = value.encode("utf-8")
        self.i32(len(raw))
        self.buf += raw

    def list(self, elem_type: int, size: int) -> None:
        self.buf.append(elem_type & 0xFF)
        self.i32(size)


class ThriftError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def message(self) -> Tuple[str, int, int]:
        header = self.i32()
        if header > 0:
            raise ThriftError("expected a strict Thrift message")
        name = self.string()
        seqid = self.i32()
        mtype = header & 0xFF
        return name, mtype, seqid

    def read_value(self, ttype: int) -> Value:
        if ttype == BOOL:
            return self.u8() != 0
        if ttype == BYTE:
            return self.u8()
        if ttype == DOUBLE:
            return struct.unpack(">d", self._take(8))[0]
        if ttype == I16:
            return self.i16()
        if ttype == I32:
            return self.i32()
        if ttype == I64:
            return struct.unpack(">q", self._take(8))[0]
        if ttype == STRING:
            return self.string()
        if ttype == STRUCT:
            fields: List[Tuple[int, Value]] = []
            while True:
                ftype = self.u8()
                if ftype == STOP:
                    break
                fid = self.i16()
                fields.append((fid, self.read_value(ftype)))
            return fields
        if ttype == MAP:
            key_type = self.u8()
            val_type = self.u8()
            size = self.i32()
            return [(self.read_value(key_type), self.read_value(val_type)) for _ in range(size)]
        if ttype in (LIST, SET):
            elem = self.u8()
            size = self.i32()
            return [self.read_value(elem) for _ in range(size)]
        raise ThriftError("unknown type %s" % ttype)

    def u8(self) -> int:
        return self._take(1)[0]

    def i16(self) -> int:
        return struct.unpack(">h", self._take(2))[0]

    def i32(self) -> int:
        return struct.unpack(">i", self._take(4))[0]

    def string(self) -> str:
        size = self.i32()
        if size < 0:
            raise ThriftError("negative string length")
        return self._take(size).decode("utf-8")

    def _take(self, size: int) -> bytes:
        end = self.pos + size
        if end > len(self.data):
            raise ThriftError("truncated thrift message")
        chunk = self.data[self.pos:end]
        self.pos = end
        return chunk


def field_map(fields: Value) -> dict:
    if not isinstance(fields, list):
        raise ThriftError("expected a struct")
    return {fid: value for fid, value in fields}

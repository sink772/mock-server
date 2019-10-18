# Copyright 2019 ICON Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from copy import copy
from typing import Tuple, Any, Union


def int_to_bytes(v: int) -> bytes:
    n_bytes = ((v + (v < 0)).bit_length() + 8) // 8
    return v.to_bytes(n_bytes, byteorder="big", signed=True)


def bytes_to_int(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=True)


class TypeTag(object):
    NIL = 0
    DICT = 1
    LIST = 2
    BYTES = 3
    STRING = 4
    BOOL = 5

    CUSTOM = 10
    INT = CUSTOM + 1
    ADDRESS = CUSTOM


class Address(object):
    def __init__(self, obj):
        if isinstance(obj, bytes):
            if len(obj) != 21:
                raise Exception("IllegalFormat")
            self.__bytes = copy(obj)
            self.__check_prefix()
        elif isinstance(obj, str):
            if len(obj) != 42:
                raise Exception("IllegalFormat")
            prefix = bytes([obj[:2] == "cx"])
            body = bytes.fromhex(obj[2:])
            self.__bytes = prefix + body
        else:
            raise Exception(f"IllegalFormat: type={type(obj)}")

    @staticmethod
    def from_str(s: str) -> 'Address':
        if len(s) != 42:
            raise Exception("IllegalFormat")
        prefix = bytes([s[:2] == "cx"])
        body = bytes.fromhex(s[2:])
        return Address(prefix + body)

    def to_bytes(self):
        return copy(self.__bytes)

    def __repr__(self):
        body = self.__bytes[1:].hex()
        if self.__bytes[0] == 0:
            return "hx" + body
        else:
            return "cx" + body

    def __check_prefix(self):
        prefix = self.__bytes[0]
        if prefix != 0 and prefix != 1:
            raise Exception(f"IllegalFormat: prefix={hex(prefix)}")


def encode_any(o: Any) -> Tuple[int, Any]:
    if o is None:
        return TypeTag.NIL, b''
    elif isinstance(o, dict):
        m = {}
        for k, v in o.items():
            m[k] = encode_any(v)
        return TypeTag.DICT, m
    elif isinstance(o, list) or isinstance(o, tuple):
        lst = []
        for v in o:
            lst.append(encode_any(v))
        return TypeTag.LIST, lst
    elif isinstance(o, bytes):
        return TypeTag.BYTES, o
    elif isinstance(o, str):
        return TypeTag.STRING, o.encode('utf-8')
    elif isinstance(o, bool):
        if o:
            return TypeTag.BOOL, b'\x01'
        else:
            return TypeTag.BOOL, b'\x00'
    elif isinstance(o, int):
        return TypeTag.INT, int_to_bytes(o)
    elif isinstance(o, Address):
        return TypeTag.ADDRESS, o.to_bytes()
    else:
        raise Exception(f"UnknownType: {type(o)}")


def decode(tag: int, val: bytes) -> 'Any':
    if tag == TypeTag.BYTES:
        return val
    elif tag == TypeTag.STRING:
        return val.decode('utf-8')
    elif tag == TypeTag.INT:
        return bytes_to_int(val)
    elif tag == TypeTag.BOOL:
        if val == b'\x00':
            return False
        elif val == b'\x01':
            return True
        else:
            raise Exception(f'IllegalBoolBytes{val.hex()})')
    elif tag == TypeTag.ADDRESS:
        return Address(val)
    else:
        raise Exception(f"UnknownType: {tag}")


def decode_any(to: list) -> Any:
    tag: int = to[0]
    val: Union[bytes, dict, list] = to[1]
    if tag == TypeTag.NIL:
        return None
    elif tag == TypeTag.DICT:
        obj = {}
        for k, v in val.items():
            if isinstance(k, bytes):
                k = k.decode('utf-8')
            obj[k] = decode_any(v)
        return obj
    elif tag == TypeTag.LIST:
        obj = []
        for v in val:
            obj.append(decode_any(v))
        return obj
    else:
        return decode(tag, val)


def decode_param(typ: str, val: bytes) -> Any:
    # print(f'  ** typ={typ} val={val} len={len(val)}')
    if typ == 'Address':
        return decode(TypeTag.ADDRESS, val)
    elif typ == 'int':
        return decode(TypeTag.INT, val)
    elif typ == 'bytes':
        return decode(TypeTag.BYTES, val)

# Copyright 2018 ICON Foundation
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

from typing import Any, Tuple

import msgpack
import socket


def int_to_bytes(v: int) -> bytes:
    n_bytes = ((v + (v < 0)).bit_length() + 8) // 8
    return v.to_bytes(n_bytes, byteorder="big", signed=True)


def bytes_to_int(v: bytes) -> int:
    return int.from_bytes(v, "big", signed=True)


class Message(object):
    CONNECT = 0
    INVOKE = 1
    RESULT = 2
    GETVALUE = 3
    SETVALUE = 4
    CALL = 5
    EVENT = 6
    GETINFO = 7
    GETBALANCE = 8
    GETAPI = 9
    LOG = 10
    CLOSE = 11


class MessageHandler(object):
    """ Message format
        msg: uint16
        data: any
    """
    def __init__(self, conn: socket):
        self._conn = conn

    def write(self, b: bytes) -> None:
        self._conn.sendall(b)

    def read(self, n=None) -> bytes:
        if n is None:
            n = 1024
        return self._conn.recv(n)

    def _send(self, msg: int, data: Any):
        payload = [msg, data]
        msgpack.dump(payload, self)

    def _recv(self) -> Tuple[int, Any]:
        msg = msgpack.load(self)
        return msg[0], msg[1]

    def send_msg(self, msg: int, data: Any):
        self._send(msg, data)

    def recv_msg(self) -> Tuple[int, Any]:
        return self._recv()

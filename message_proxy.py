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


class MessageProxy(object):
    """ Message format
        msg: uint16
        data: any
    """
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer

    def write(self, b: bytes) -> None:
        self._writer.write(b)

    async def read(self, n=None) -> bytes:
        if n is None:
            n = 8192
        return await self._reader.read(n)

    def send_msg(self, msg: int, data: Any):
        payload = [msg, data]
        self.write(msgpack.packb(payload))

    async def recv_msg(self) -> Tuple[int, Any]:
        data = await self.read()
        msg = msgpack.unpackb(data)
        return msg[0], msg[1]
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

import os
import re
import socket
import sys
import time
from copy import copy
from typing import Any, Tuple, Union

import plyvel
from mock_server.message_handler import Message, MessageHandler, int_to_bytes, bytes_to_int

server_address = '/tmp/ee.socket'
number_of_connections = 1
version_number = 1

STEP_TYPE_CONTRACT_CALL = 'contractCall'
STEP_TYPE_GET = 'get'
STEP_TYPE_SET = 'set'
STEP_TYPE_REPLACE = 'replace'
STEP_TYPE_DELETE = 'delete'
STEP_TYPE_INPUT = 'input'
STEP_TYPE_EVENT_LOG = 'eventLog'
STEP_TYPE_API_CALL = 'apiCall'


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


class Info(object):
    BLOCK_TIMESTAMP = "B.timestamp"
    BLOCK_HEIGHT = "B.height"
    TX_HASH = "T.hash"
    TX_INDEX = "T.index"
    TX_FROM = "T.from"
    TX_TIMESTAMP = "T.timestamp"
    TX_NONCE = "T.nonce"
    STEP_COSTS = "StepCosts"
    CONTRACT_OWNER = "C.owner"


class Address(object):
    def __init__(self, obj):
        if isinstance(obj, bytes):
            if len(obj) < 21:
                raise Exception("IllegalFormat")
            self.__bytes = copy(obj)
        elif isinstance(obj, str):
            if len(obj) < 42:
                raise Exception("IllegalFormat")
            prefix = bytes([obj[:2] == "cx"])
            body = bytes.fromhex(obj[2:])
            self.__bytes = prefix + body
        else:
            raise Exception(f"IllegalFormat: type={type(obj)}")

    @staticmethod
    def from_str(s: str) -> 'Address':
        if len(s) < 42:
            raise Exception("IllegalFormat")
        prefix = bytes([s[:2] == "cx"])
        body = bytes.fromhex(s[2:])
        return Address(prefix + body)

    def to_bytes(self):
        return copy(self.__bytes)

    def __str__(self):
        body = self.__bytes[1:].hex()
        if self.__bytes[0] == 0:
            return "hx" + body
        else:
            return "cx" + body


PLYVEL_DB_PATH = '/ws/core2/java-executor/target/sample_token/db'

token_jar_path = '/ws/core2/java-executor/target/sample_token/sample_token-optimized.jar'
hello_jar_path = '/ws/core2/java-executor/target/hello2/hello-1.0-SNAPSHOT.jar'

token_score_path = '/ws/docker/test_pyexec/test_score/sample_token'
token_score_address = Address('cx784b61a531e819838e1f308287f953015020000a')
crowdsale_path = '/ws/docker/test1/test_score/sample_crowdsale'
crowdsale_address = Address('cx0000abcd31e819838e1f308287f9530150200000')

owner_address = Address('hxe7af5fcfd8dfc67530a01a0e403882687528dfcb')
alice_address = Address('hxca1b18d749e4339e9661061af7e1e6cabcef8a19')

requests_sample_token = [
    # deploy jar
    [
        token_jar_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        '<install>',
        []
    ],
    # TODO: initialize the contract (this should be combined with the '<install>' command later
    [
        token_jar_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'onInstall',
        ['MySampleToken', 'MST', 9, 1000]
    ],
    [
        token_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'balanceOf',
        [owner_address]
    ],
    # transfer some tokens to Alice
    [
        token_jar_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'transfer',
        [alice_address, 1_000_000]
    ],
    [
        token_jar_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'transfer',
        [Address('hx' + 'b'*40), 1_000_000]
    ],
    [
        token_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'balanceOf',
        [owner_address]
    ],
]

requests_hello = [
    [
        hello_jar_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        '<install>',
        ['Hello World']
    ],
    [
        hello_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'sayHello',
        []
    ],
    [
        hello_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'greet',
        ['Alice']
    ],
    [
        hello_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'getString',
        []
    ],
    [
        hello_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'setString',
        ['Hello Alice']
    ],
    [
        hello_jar_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'getString',
        []
    ],
]


def get_requests():
    for req in requests_sample_token:
        yield req


class MessageHandlerServer(MessageHandler):

    def __init__(self, conn: socket):
        super().__init__(conn)
        self._uid = 0
        self._db = plyvel.DB(PLYVEL_DB_PATH, create_if_missing=True)
        self._requests = get_requests()
        self._req_stack = []

    def close(self):
        self._db.close()

    def encode_any(self, o: Any) -> Tuple[int, Any]:
        if o is None:
            return TypeTag.NIL, b''
        elif isinstance(o, dict):
            m = {}
            for k, v in o.items():
                m[k] = self.encode_any(v)
            return TypeTag.DICT, m
        elif isinstance(o, list) or isinstance(o, tuple):
            lst = []
            for v in o:
                lst.append(self.encode_any(v))
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

    def decode(self, tag: int, val: bytes) -> 'Any':
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

    def decode_any(self, to: list) -> Any:
        tag: int = to[0]
        val: Union[bytes, dict, list] = to[1]
        if tag == TypeTag.NIL:
            return None
        elif tag == TypeTag.DICT:
            obj = {}
            for k, v in val.items():
                if isinstance(k, bytes):
                    k = k.decode('utf-8')
                obj[k] = self.decode_any(v)
            return obj
        elif tag == TypeTag.LIST:
            obj = []
            for v in val:
                obj.append(self.decode_any(v))
            return obj
        else:
            return self.decode(tag, val)

    def decode_param(self, typ: str, val: bytes) -> Any:
        # print(f'  ** typ={typ} val={val} len={len(val)}')
        if typ == 'Address':
            return self.decode(TypeTag.ADDRESS, val)
        elif typ == 'int':
            return self.decode(TypeTag.INT, val)
        elif typ == 'bytes':
            return self.decode(TypeTag.BYTES, val)

    def _handle_connect(self, data) -> bool:
        print('[handle_connect]', data)
        version = data[0]
        if version != version_number:
            print(f'Error: version should be {version_number}, but {version}')
            return False
        self._uid = data[1]
        print(f'version: {version}, uid: {self._uid}, eetype: {data[2]}')
        return True

    def _handle_result(self, data):
        print('[handle_result]', data)
        status = data[0]
        step_used = self.decode(TypeTag.INT, data[1])
        ret = self.decode_any(data[2])
        print(f'  <<< {status}, {step_used}, {ret}')

    def _handle_getinfo(self, data):
        print('[handle_getinfo]', data)
        info = {
            Info.TX_INDEX: 0,
            Info.TX_HASH: bytes.fromhex('49a1149d2e607c1b08f17f587d8a99c5a675f8e7eaae13d33a7df57aefeeae4f'),
            Info.TX_FROM: owner_address,
            Info.TX_TIMESTAMP: int(time.time() * 10**6),
            Info.TX_NONCE: 1,
            Info.BLOCK_HEIGHT: 0x100,
            Info.BLOCK_TIMESTAMP: int(time.time() * 10**6),
            Info.CONTRACT_OWNER: owner_address,
            Info.STEP_COSTS: {
                STEP_TYPE_CONTRACT_CALL: 25_000,
                STEP_TYPE_GET: 0,
                STEP_TYPE_SET: 320,
                STEP_TYPE_REPLACE: 80,
                STEP_TYPE_DELETE: -240,
                STEP_TYPE_INPUT: 200,
                STEP_TYPE_EVENT_LOG: 100,
                STEP_TYPE_API_CALL: 10000,
            }
        }
        print(f'info -> {self.encode_any(info)}')
        self.send_msg(Message.GETINFO, self.encode_any(info))

    def _handle_call(self, data):
        print('\n[handle_call]', data)
        addr_to: Address = self.decode(TypeTag.ADDRESS, data[0])
        value = self.decode(TypeTag.INT, data[1])
        limit = self.decode(TypeTag.INT, data[2])
        method = self.decode(TypeTag.STRING, data[3])
        params = self.decode_any(data[4])
        print(f'  -- to={addr_to} value={value} limit={limit} method={method} params={params}')

        if addr_to == crowdsale_address:
            req = [
                crowdsale_path,
                False,
                token_score_address.to_bytes(),
                addr_to.to_bytes(),
                int_to_bytes(value),
                int_to_bytes(limit),
                method,
                params
            ]
            self._send_request(req)
        elif method == 'fallback':
            print(f'[ICX Transfer] value={value}')
            self.send_msg(Message.RESULT, [
                0, int_to_bytes(1000), self.encode_any(None)
            ])
        else:
            self.send_msg(Message.RESULT, [
                1, int_to_bytes(100),
                self.encode_any({'error': {'code': 32601, 'message': 'Method not found'}})
            ])

    def _handle_getvalue(self, key):
        print('[handle_getvalue]', key)
        value = self._db.get(key)
        if value is not None:
            success = True
        else:
            success = False
            value = b''
        print(f'  -- getvalue -> {success}, {value}')
        self.send_msg(Message.GETVALUE, [
            success, value
        ])

    def _handle_setvalue(self, data):
        print('[handle_setvalue]', data)
        key = data[0]
        is_delete = data[1]
        value = data[2]
        print(f'  -- setvalue -> {key}, {is_delete}, {value}')
        if is_delete:
            self._db.delete(key)
        else:
            self._db.put(key, value)

    def _send_request(self, req):
        print('\n[send_request]', req)
        print(f'  >>> method: {req[6]}')
        print(f'      params: {req[7]}')
        if isinstance(req[7], list):
            req[7] = self.encode_any(req[7])
        self.send_msg(Message.INVOKE, req)
        self._req_stack.append(req)

    def _send_getapi(self, code_path):
        print('[send_getapi]', code_path)
        self.send_msg(Message.GETAPI, code_path)
        msg, data = self.recv_msg()
        if msg != Message.GETAPI:
            raise Exception(f'Unexpected Msg: {msg} != {Message.GETAPI}')
        print(f'getapi ->')
        status: int = data[0]
        info: list = data[1]
        if status == 0:
            for api in info:
                print(f"  - {api}")
        else:
            print(f'getapi FAILED: {status}')

        # send first invoke request
        self._send_request(next(self._requests))

    def _handle_getbalance(self, data):
        print('[handle_getbalance]')
        addr = Address(data)
        print(f'  -- address = {addr}')
        self.send_msg(Message.GETBALANCE, int_to_bytes(10**18))

    def _handle_event(self, events):
        print(f'[handle_event] -> {events}')
        indexed = events[0]
        data = events[1]
        sig = indexed[0]
        print('Indexed:')
        print(f'  -- {sig.decode()}')
        result = re.match('(\\S+?)\\((.+)\\)', sig.decode())
        params: list = result.group(2).split(',')
        for v in indexed[1:]:
            print(f'  -- {self.decode_param(params.pop(0), v)}')
        print('Data:')
        for v in data:
            print(f'  -- {self.decode_param(params.pop(0), v)}')

    def process(self):
        while True:
            msg, data = self.recv_msg()
            if msg == Message.CONNECT:
                ret = self._handle_connect(data)
                if ret:
                    self._send_getapi(token_score_path)
            elif msg == Message.RESULT:
                self._handle_result(data)
                self._req_stack.pop()
                if len(self._req_stack) > 0:
                    self.send_msg(Message.RESULT, data)
                else:
                    try:
                        self._send_request(next(self._requests))
                    except StopIteration:
                        print('End of requests')
                        # break
            elif msg == Message.GETINFO:
                self._handle_getinfo(data)
            elif msg == Message.CALL:
                self._handle_call(data)
            elif msg == Message.GETVALUE:
                self._handle_getvalue(data)
            elif msg == Message.SETVALUE:
                self._handle_setvalue(data)
            elif msg == Message.GETBALANCE:
                self._handle_getbalance(data)
            elif msg == Message.EVENT:
                self._handle_event(data)
            else:
                print(f'Invalid message received: {msg}')
                break


def main():
    # make sure the socket does not already exist
    if os.path.exists(server_address):
        os.unlink(server_address)

    # create a UNIX domain socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # bind the socket to the address
    print(f'starting up on {server_address}')
    sock.bind(server_address)

    # listen for incoming connections
    sock.listen(number_of_connections)

    while True:
        # wait for a connection
        print('waiting for a connection')
        conn, addr = sock.accept()
        print(f'connection from {addr.encode()}...')
        handler = MessageHandlerServer(conn)
        try:
            handler.process()
        finally:
            # clean up the connection
            handler.close()
            conn.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("exit")

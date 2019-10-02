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

import asyncio
import os
import re
import time
import uuid
from typing import Any, Tuple

import plyvel
from .message_proxy import Message, ManagerMessage, MessageProxy
from .utils import int_to_bytes, encode_any, TypeTag, Address, decode, decode_any, decode_param

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


TARGET_ROOT = '/ws/core2/java-executor/target'

SAMPLE_TOKEN = TARGET_ROOT + '/sample_token'
PLYVEL_DB_PATH = SAMPLE_TOKEN + '/db'
token_score_origin = SAMPLE_TOKEN + '/dapp.jar'
token_score_path = SAMPLE_TOKEN + '/optimized-debug.jar'

token_score_address = Address('cx784b61a531e819838e1f308287f953015020000a')
crowdsale_path = '/ws/docker/test1/test_score/sample_crowdsale'
crowdsale_address = Address('cx0000abcd31e819838e1f308287f9530150200000')

owner_address = Address('hxe7af5fcfd8dfc67530a01a0e403882687528dfcb')
alice_address = Address('hxca1b18d749e4339e9661061af7e1e6cabcef8a19')

requests_sample_token = [
    # === Java deployment ===
    [
        token_score_path,
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
        token_score_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'onInstall',
        ['MySampleToken', 'MST', 18, 1000]
    ],
    [
        token_score_path,
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
        token_score_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'transfer',
        [alice_address, 10**18, b'Hello']
    ],
    [
        token_score_path,
        False,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'transfer',
        [Address('hx' + 'b'*40), 10**18, b'']
    ],
    [
        token_score_path,
        True,
        owner_address.to_bytes(),
        token_score_address.to_bytes(),
        int_to_bytes(0),
        int_to_bytes(10_000_000),
        'balanceOf',
        [owner_address]
    ],
]

# # === Python deployment ===
# requests_sample_token_py = [
#     [
#         token_score_path,
#         False,
#         owner_address.to_bytes(),
#         token_score_address.to_bytes(),
#         int_to_bytes(0),
#         int_to_bytes(10_000_000),
#         'on_install',
#         [1000, 9]
#     ],
# ]


def get_requests():
    for req in requests_sample_token:
        yield req


class Proxy(object):
    def __init__(self, proxy):
        self._proxy = proxy

    def send_msg(self, msg: int, data: Any):
        self._proxy.send_msg(msg, data)

    async def recv_msg(self) -> Tuple[int, Any]:
        return await self._proxy.recv_msg()


class AsyncMessageHandler(Proxy):
    def __init__(self, proxy):
        super().__init__(proxy)
        self._db = plyvel.DB(PLYVEL_DB_PATH, create_if_missing=True)
        self._requests = get_requests()
        self._req_stack = []

    def close(self):
        self._db.close()

    async def _send_getapi(self, code_path):
        print('[send_getapi]', code_path)
        self.send_msg(Message.GETAPI, code_path)
        msg, data = await self.recv_msg()
        if msg != Message.GETAPI:
            raise Exception(f'Unexpected Msg: {msg} != {Message.GETAPI}')
        print(f'getapi ->')
        status: int = data[0]
        info: list = data[1]
        if status == 0:
            for api in info:
                print(f"  - {api}")
        else:
            raise Exception(f'GETAPI failed: {status}')

    def _send_request(self, req):
        print('\n[send_request]', req)
        print(f'  >>> method: {req[6]}')
        print(f'      params: {req[7]}')
        if isinstance(req[7], list):
            req[7] = encode_any(req[7])
        self.send_msg(Message.INVOKE, req)
        self._req_stack.append(req)

    def _handle_result(self, data):
        print('[handle_result]', data)
        status = data[0]
        step_used = decode(TypeTag.INT, data[1])
        ret = decode_any(data[2])
        print(f'  <<< {status}, {step_used}, {ret}')
        return status

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
        print(f'info -> {encode_any(info)}')
        self.send_msg(Message.GETINFO, encode_any(info))

    def _handle_call(self, data):
        print('\n[handle_call]', data)
        addr_to: Address = decode(TypeTag.ADDRESS, data[0])
        value = decode(TypeTag.INT, data[1])
        limit = decode(TypeTag.INT, data[2])
        method = decode(TypeTag.STRING, data[3])
        params = decode_any(data[4])
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
                0, int_to_bytes(1000), encode_any(None)
            ])
        else:
            self.send_msg(Message.RESULT, [
                1, int_to_bytes(100),
                encode_any({'error': {'code': 32601, 'message': 'Method not found'}})
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
            print(f'  -- {decode_param(params.pop(0), v)}')
        print('Data:')
        for v in data:
            print(f'  -- {decode_param(params.pop(0), v)}')

    async def process(self):
        # send GETAPI first
        await self._send_getapi(token_score_origin)

        # send first invoke request
        self._send_request(next(self._requests))

        while True:
            msg, data = await self.recv_msg()
            if msg == Message.RESULT:
                failed = self._handle_result(data)
                self._req_stack.pop()
                if len(self._req_stack) > 0:
                    self.send_msg(Message.RESULT, data)
                else:
                    if failed:
                        print('Request has failed!')
                        break
                    try:
                        self._send_request(next(self._requests))
                    except StopIteration:
                        print('End of requests.\n')
                        self.send_msg(Message.CLOSE, b'')
                        break
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
            elif msg == Message.LOG:
                print('[LOG]', data)
            else:
                print(f'Invalid message received: {msg}')
                break

        # cleanup
        self.close()


class AsyncManagerHandler(Proxy):
    def __init__(self, proxy):
        super().__init__(proxy)
        self._executors = []

    def _run_executor(self, uuid1):
        print('[run_executor]', uuid1)
        self._executors.append(str(uuid1))
        self.send_msg(ManagerMessage.RUN, str(uuid1))

    async def process(self):
        # send RUN message to spawn a new executor
        self._run_executor(uuid.uuid4())

        while True:
            msg, data = await self.recv_msg()
            if msg == ManagerMessage.END:
                print('[END]', data)
                uuid1 = data.decode()
                if uuid1 in self._executors:
                    print('  - remove from list')
                    self._executors.remove(uuid1)
                else:
                    print('  - cannot find the uuid')


async def handle_connect(reader, writer):
    print(f'New connection reader={reader}')
    proxy = MessageProxy(reader, writer)
    msg, data = await proxy.recv_msg()
    print(f'[connect] {msg} {data}')
    if msg == ManagerMessage.VERSION:
        version = data[0]
        if version != version_number:
            print(f'Error: version should be {version_number}, but {version}')
            return
        print(f'  - version: {version}, eetype: {data[1]}')
        handler = AsyncManagerHandler(proxy)
        asyncio.get_event_loop().create_task(handler.process())
    elif msg == Message.VERSION:
        version = data[0]
        if version != version_number:
            print(f'Error: version should be {version_number}, but {version}')
            return
        uuid = data[1]
        print(f'  - version: {version}, uuid: {uuid}, eetype: {data[2]}')
        handler = AsyncMessageHandler(proxy)
        asyncio.get_event_loop().create_task(handler.process())


def async_main():
    # make sure the socket does not already exist
    if os.path.exists(server_address):
        os.unlink(server_address)

    print(f'waiting for a connection, sockaddr={server_address}')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.start_unix_server(handle_connect, server_address))
    try:
        loop.run_forever()
    finally:
        loop.close()

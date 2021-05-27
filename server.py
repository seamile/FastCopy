#!/usr/bin/env python

import socket
from argparse import ArgumentParser
from functools import wraps
from struct import unpack
from threading import Lock, Thread
from typing import Dict

from const import Flag
from network import NetworkMixin
from transfer import Sender, Receiver, Transfer


def singleton(cls):
    '''Singleton Pattern Decorator'''
    obj = None

    @wraps(cls)
    def wrapper(*args, **kwargs):
        nonlocal obj
        if isinstance(obj, cls):
            return obj
        else:
            obj = cls(*args, **kwargs)
            return obj
    return wrapper


class WatchDog(Thread, NetworkMixin):
    def __init__(self, server: 'Server', sock: socket.socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            print('waiting for the first packet from %s:%d' % self.sock.getpeername())
            self.sock.settimeout(10)
            cli_flag, *_, payload = self.recv_msg()
            self.sock.settimeout(None)
        except socket.timeout:
            # 超时退出
            print('waiting timeout')
            self.sock.close()
            return

        if cli_flag == Flag.PULL or cli_flag == Flag.PUSH:
            # 创建 Transfer
            dst_path = payload.decode('utf8')
            transfer = self.server.create_transfer(cli_flag, dst_path)
            transfer.conn_pool.add(self.sock)
            transfer.start()

            # 将 SID 发送给客户端
            self.send_msg(Flag.SID, transfer.sid)

        elif cli_flag == Flag.ATTACH:
            print('run as a follower')
            sid = unpack('>H', payload)[0]
            transfer = self.server.transfers[sid]
            transfer.conn_pool.add(self.sock)

        else:
            # 对于错误的类型，直接关闭连接
            print('close conn')
            self.sock.close()


@singleton
class Server(Thread):
    def __init__(self, host: str, port: int, max_conn=256) -> None:
        super().__init__(daemon=True)
        self.addr = (host, port)
        self.max_transfers = 65535  # 最大 Transfer 数量，与 Session ID 相关
        self.max_conn = max_conn  # 一个 Transfer 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.next_id = 1
        self.transfers: Dict[int, Transfer] = {}

    def geneate_sid(self) -> int:
        with self.mutex:
            if len(self.transfers) >= self.max_transfers:
                raise ValueError('已达到最大 Transfer 数量，无法创建')

            while self.next_id in self.transfers:
                if self.next_id < self.max_transfers:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def create_transfer(self, cli_flag: Flag, dst_path: str) -> Transfer:
        '''创建新 Transfer'''
        sid = self.geneate_sid()
        if cli_flag == Flag.PULL:
            print(f'Create Sender({sid}, {dst_path})')
            self.transfers[sid] = Sender(sid, dst_path)
        else:
            print(f'Create Receiver({sid}, {dst_path})')
            self.transfers[sid] = Receiver(sid, dst_path)
        return self.transfers[sid]

    def close_all_transfers(self):
        '''关闭所有 Transfer'''
        print('closing transfers')
        for transfer in self.transfers.values():
            transfer.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        print('Server is running at %s:%d' % self.addr)
        while self.is_running:
            # wait for new connection
            print('waitting for new connections')
            cli_sock, cli_addr = self.srv_sock.accept()
            print('new connection: %s:%s' % cli_addr)

            # launch a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


if __name__ == '__main__':
    # Server 启动方式: fcpd -h host -p port -c 128
    parser = ArgumentParser()
    parser.add_argument('-b', dest='bind', type=str, default='0.0.0.0',
                        help='')
    parser.add_argument('-p', dest='port', type=int, default=7325,
                        help='')
    parser.add_argument('-c', dest='concurrency', type=int, default=256,
                        help='')
    args = parser.parse_args()
    server = Server(args.bind, args.port, args.concurrency)
    server.start()
    server.join()

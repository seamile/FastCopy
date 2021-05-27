#!/usr/bin/env python

import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from socket import socket, create_connection
from textwrap import dedent
from typing import Optional

from const import Flag
from network import NetworkMixin, Packet
from transfer import Sender, Receiver, Transfer


class Client(NetworkMixin):
    def __init__(self, src: str, dst: str, port: int, n_conn: int) -> None:
        self.src = src
        self.dst = dst
        self.host = ''
        self.port = port
        self.user = ''
        self.sid = 0
        self.n_conn = n_conn

        # create by self.connect()
        self.sock: Optional[socket] = None  # type: ignore
        self.transfer: Optional[Transfer] = None

    def handshake(self, flag: Flag, remote_dir: str):
        '''握手'''
        self.send_msg(flag, remote_dir.encode('utf8'))
        packet = self.recv_msg()
        self.sid, = packet.unpack_body()

    def parse_remote(self, remote):
        netloc, path = remote.split(':')
        user, host = netloc.split('@') if '@' in netloc else '', netloc
        return user, host, path

    def init_conn(self):
        '''初始化连接'''
        if ':' in self.src:
            # 解析远程主机地址
            user, self.host, self.src = self.parse_remote(self.src)
            print(f'PULL: {user}@{self.host}:{self.port}:{self.src} -> {self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PULL, self.src)
            self.transfer = Receiver(self.sid, self.dst)

        elif ':' in self.dst:
            # 解析远程主机地址
            user, self.host, self.dst = self.parse_remote(self.dst)
            print(f'PUSH: {self.src} -> {user}@{self.host}:{self.port}:{self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PUSH, self.dst)
            self.transfer = Sender(self.sid, self.src)

        else:
            parser.print_help()
            sys.exit(1)

        self.transfer.conn_pool.add(self.sock)

    def create_parallel_connections(self, num):
        '''创建并行连接'''
        attach_pkt = Packet.load(Flag.ATTACH, self.sid)
        datagram = attach_pkt.pack()
        for i in range(self.n_conn - 1):
            sock = create_connection((self.host, self.port))
            sock.send(datagram)
            self.transfer.conn_pool.add(sock)

    def launch(self):
        self.init_conn()
        self.transfer.start()
        self.transfer.join()


if __name__ == '__main__':
    # Client 启动方式: fcp -c 100 host:/foo/bar ./loc/
    parser = ArgumentParser(
        prog='fcp',
        formatter_class=RawDescriptionHelpFormatter,
        description=dedent('''
            PULL : fcp [-p PORT] [USER@]HOST:SRC DST
            PUSH : fcp [-p PORT] SRC [USER@]HOST:DST
        ''')
    )
    parser.add_argument('-p', dest='port', type=int, default=7325,
                        help='server port (default: 7325)')

    parser.add_argument('-n', dest='num', type=int, default=16,
                        help='maximum number of connections (default: 16)')

    parser.add_argument(dest='src', help='source path')
    parser.add_argument(dest='dst', help='destination path')
    args = parser.parse_args()
    cli = Client(args.src, args.dst, args.port, args.num)
    cli.launch()

#!/usr/bin/env python

import sys
import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter, BooleanOptionalAction
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

    def handshake(self, flag: Flag, remote_path: str):
        '''握手'''
        self.send_msg(flag, remote_path)
        packet = self.recv_msg()
        self.sid, = packet.unpack_body()

    def parse_remote(self, remote):
        netloc, path = remote.split(':')
        user, host = netloc.split('@') if '@' in netloc else ('', netloc)
        return user, host, path

    def init_conn(self):
        '''初始化连接'''
        if ':' in self.src:
            # 解析远程主机地址
            user, self.host, self.src = self.parse_remote(self.src)
            logging.info(f'PULL: {self.host}:{self.port}:{self.src} -> {self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PULL, self.src)
            self.transfer = Receiver(self.sid, self.dst, self.n_conn)

        elif ':' in self.dst:
            # 解析远程主机地址
            user, self.host, self.dst = self.parse_remote(self.dst)
            logging.info(f'PUSH: {self.src} -> {self.host}:{self.port}:{self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PUSH, self.dst)
            self.transfer = Sender(self.sid, self.src, self.n_conn)

        else:
            parser.print_help()
            sys.exit(1)

        self.transfer.conn_pool.add(self.sock)

    def create_parallel_connections(self):
        '''创建并行连接'''
        attach_pkt = Packet.load(Flag.ATTACH, self.sid)
        datagram = attach_pkt.pack()
        for _ in range(self.n_conn - 1):
            sock = create_connection((self.host, self.port))
            sock.send(datagram)
            self.transfer.conn_pool.add(sock)

    def launch(self):
        self.init_conn()
        self.create_parallel_connections()
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
    parser.add_argument('-v', dest='verbose', type=bool, action=BooleanOptionalAction,
                        help='Verbose mode')
    parser.add_argument(dest='src', help='source path')
    parser.add_argument(dest='dst', help='destination path')

    args = parser.parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, datefmt='%Y-%m-%d %H:%M:%S',
                        format='%(asctime)s %(levelname)4.4s %(module)s.%(lineno)s: %(message)s')

    cli = Client(args.src, args.dst, args.port, args.num)
    cli.launch()

#!/usr/bin/env python

import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from textwrap import dedent

from const import Flag
from network import NetworkMixin
from transfer import Sender, Receiver


class Client(NetworkMixin):
    def __init__(self, src: str, dst: str, port: int, n_conn: int) -> None:
        self.src = src
        self.dst = dst
        self.port = port
        self.n_conn = n_conn

        self.host = ''
        self.sid = 0

    def handshake(self, flag: Flag, remote_dir: str):
        '''握手'''
        self.connect((self.host, self.port))
        self.send_msg(flag, remote_dir.encode('utf8'))
        msg = self.recv_msg()

    def parse_args(self):
        '''解析参数'''
        if ':' in self.src:
            flag = Flag.PULL
            netloc, self.src = self.src.split(':')
            user, self.host = netloc.split('@')
            print(f'PULL: {user}@{self.host}:{self.port}:{self.src} -> {self.dst}')

        elif ':' in self.dst:
            flag = Flag.PUSH
            netloc, dst = self.dst.split(':')
            user, self.host = netloc.split('@')
            print(f'PUSH: {self.src} -> {user}@{self.host}:{self.port}:{self.dst}')

        else:
            parser.print_help()
            sys.exit(1)

    def run(self):
        fst_sock = self.connect()
        fst_sock.send()


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
    cli.run()

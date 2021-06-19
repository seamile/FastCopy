#!/usr/bin/env python

import sys
import logging
from os.path import abspath
from argparse import ArgumentParser, RawDescriptionHelpFormatter, BooleanOptionalAction
from socket import socket, create_connection
from textwrap import dedent
from typing import Optional, Tuple, Union

from const import Flag
from network import NetworkMixin, Packet
from transport import Sender, Receiver, Transporter


class Client(NetworkMixin):
    def __init__(self, srcs: str, dst: str, port: int, n_conn: int) -> None:
        self.srcs = srcs
        self.dst = dst
        self.host = ''
        self.port = port
        self.user = ''
        self.sid = 0
        self.n_conn = n_conn

        # create by self.connect()
        self.sock: Optional[socket] = None  # type: ignore
        self.transporter: Optional[Transporter] = None

    def handshake(self, flag: Flag, remote_path: Union[str, list]):
        '''握手'''
        if isinstance(remote_path, list):
            remote_path = ','.join(remote_path)
        self.send_msg(flag, remote_path)
        packet = self.recv_msg()
        self.sid, = packet.unpack_body()

    def parse_remote(self, remote):
        '''解析远程主机登录信息'''
        # src format: user@host:/path/foo/bar
        netloc, path = remote.split(':')
        user, host = netloc.split('@') if '@' in netloc else ('', netloc)
        return user, host, path

    def parse_sources(self, sources) -> Tuple[str, str, list]:
        users, hosts, srcs = set(), set(), set()
        for src in sources:
            user, host, path = self.parse_remote(src)
            users.add(user)
            hosts.add(host)
            srcs.add(path)
        if len(users) == 1 and len(hosts) == 1:
            return users.pop(), hosts.pop(), sorted(srcs)
        else:
            raise ValueError('All source args must come from the same machine with same user.')

    def init_conn(self):
        '''初始化连接'''
        if ':' in self.srcs[0]:
            # 解析远程主机地址
            user, self.host, self.srcs = self.parse_sources(self.srcs)
            logging.info(f'PULL: {self.host}:{self.port}:{self.srcs} -> {self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PULL, self.srcs)
            self.dst = abspath(self.dst)
            self.transporter = Receiver(self.sid, self.dst, self.n_conn)

        elif ':' in self.dst:
            # 解析远程主机地址
            user, self.host, self.dst = self.parse_remote(self.dst)
            logging.info(f'PUSH: {self.srcs} -> {self.host}:{self.port}:{self.dst}')
            # 建立连接, 并握手
            self.connect((self.host, self.port))
            self.handshake(Flag.PUSH, self.dst)
            self.srcs = [abspath(path) for path in self.srcs]
            self.transporter = Sender(self.sid, self.srcs, self.n_conn)

        else:
            parser.print_help()
            sys.exit(1)

        self.transporter.conn_pool.add(self.sock)

    def create_parallel_connections(self):
        '''创建并行连接'''
        attach_pkt = Packet.load(Flag.ATTACH, self.sid)
        datagram = attach_pkt.pack()
        for _ in range(self.n_conn - 1):
            sock = create_connection((self.host, self.port))
            sock.send(datagram)
            self.transporter.conn_pool.add(sock)


def main(args):
    client = Client(args.src, args.dst, args.port, args.num)

    try:
        logging.info('[Client] Connecting to server')
        client.init_conn()
        client.create_parallel_connections()
        client.transporter.start()
        client.transporter.join()
    except Exception as e:
        logging.error(f'[Client] {e}, exit.')
        sys.exit(1)


if __name__ == '__main__':
    parser = ArgumentParser(
        prog='fcp',
        formatter_class=RawDescriptionHelpFormatter,
        description=dedent('''
            PULL : fcp [-p PORT] [USER@]HOST:SRC... DST
            PUSH : fcp [-p PORT] SRC... [USER@]HOST:DST
        ''')
    )
    parser.add_argument('-p', dest='port', type=int, default=7325,
                        help='server port (default: 7325)')
    parser.add_argument('-n', dest='num', type=int, default=16,
                        help='maximum number of connections (default: 16)')
    parser.add_argument('-v', dest='verbose', type=bool, action=BooleanOptionalAction,
                        help='Verbose mode')
    parser.add_argument(dest='src', nargs='+', help='source path')
    parser.add_argument(dest='dst', help='destination path')

    args = parser.parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(message)s')

    main(args)

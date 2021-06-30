#!/usr/bin/env python

import sys
import logging
from os.path import abspath
from argparse import ArgumentParser, RawDescriptionHelpFormatter, BooleanOptionalAction
from socket import socket, create_connection
from textwrap import dedent
from typing import Optional, Tuple, Union

from sshtunnel import open_tunnel

from const import Flag, SERVER_ADDR
from network import NetworkMixin, Packet
from transport import Sender, Receiver, Transporter


class Client(NetworkMixin):
    def __init__(self, action: Flag, srcs: str, dst: str, addr: Tuple[str, int], n_conn: int):
        self.action = action
        self.srcs = srcs
        self.dst = dst
        self.addr = addr
        self.user = ''
        self.sid = 0
        self.n_conn = n_conn

        # create by self.connect()
        self.sock: Optional[socket] = None  # type: ignore
        self.transporter: Optional[Transporter] = None

    def handshake(self, remote_path: Union[str, list]):
        '''握手'''
        print('connect to %s:%s' % self.addr)
        self.sock = create_connection(self.addr, timeout=30)

        self.send_msg(self.action, remote_path)
        packet = self.recv_msg()
        self.sid, = packet.unpack_body()

    def init_conn(self):
        '''初始化连接'''
        if self.action == Flag.PULL:
            self.handshake(self.srcs)
            self.transporter = Receiver(self.sid, abspath(self.dst), self.n_conn)

        elif self.action == Flag.PUSH:
            self.handshake(self.dst)
            srcs = [abspath(path) for path in self.srcs]
            self.transporter = Sender(self.sid, srcs, self.n_conn)

        else:
            parser.print_help()
            sys.exit(1)

        self.transporter.conn_pool.add(self.sock)

    def create_parallel_connections(self):
        '''创建并行连接'''
        attach_pkt = Packet.load(Flag.ATTACH, self.sid)
        datagram = attach_pkt.pack()
        for _ in range(self.n_conn - 1):
            sock = create_connection(self.addr)
            sock.send(datagram)
            self.transporter.conn_pool.add(sock)


class ArgsError(Exception):
    pass


def parse_remote_addr(remote):
    '''解析远程主机登录信息'''
    netloc, path = remote.split(':')
    user, host = netloc.split('@') if '@' in netloc else ('', netloc)
    return user, host, path


def parse_remote_sources(sources):
    users, hosts, srcs = set(), set(), set()
    for src in sources:
        user, host, path = parse_remote_addr(src)
        users.add(user)
        hosts.add(host)
        srcs.add(path)
    if len(users) == 1 and len(hosts) == 1:
        return users.pop(), hosts.pop(), ','.join(sorted(srcs))
    else:
        raise ValueError('All source args must come from the same machine with same user.')


def parse_cli_args(args):
    '''解析命令行参数'''
    # 解析主机地址等参数
    if ':' in args.srcs[0]:
        user, host, srcs = parse_remote_sources(args.srcs)
        return Flag.PULL, srcs, args.dst, user, host
    elif ':' in args.dst:
        user, host, dst = parse_remote_addr(args.dst)
        return Flag.PUSH, args.srcs, dst, user, host
    else:
        raise ArgsError


def main(parser: ArgumentParser):
    '''主函数'''
    args = parser.parse_args()

    # 处理日志
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(message)s')

    # 解析源路径、目的路径、远程主机、用户等
    try:
        action, srcs, dst, user, host = parse_cli_args(args)
    except ArgsError:
        parser.print_help()
        sys.exit(1)

    tunnel = open_tunnel(host,
                         ssh_username=user,
                         ssh_port=args.ssh_port,
                         ssh_config_file='~/.ssh/config',
                         ssh_host_key=None,
                         ssh_password=args.password,
                         ssh_pkey=None,
                         ssh_private_key_password=None,
                         remote_bind_address=SERVER_ADDR,
                         compression=True)
    with tunnel:
        client = Client(action, srcs, dst, tunnel.local_bind_address, args.num)

        try:
            logging.info('[Client] Connecting to server')
            client.init_conn()
            client.create_parallel_connections()
            client.transporter.start()  # type:ignore
            client.transporter.join()  # type:ignore
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

    parser.add_argument('-p', dest='ssh_port', type=int, default=22,
                        help='SSH server port (default: 22)')

    parser.add_argument('-P', dest='password', type=str, default=None,
                        help='Password for SSH')

    parser.add_argument('-n', dest='num', type=int, default=16,
                        help='Maximum number of connections (default: 16)')

    parser.add_argument('-v', dest='verbose', type=bool, action=BooleanOptionalAction,
                        help='Verbose mode')

    parser.add_argument(dest='srcs', nargs='+', help='source path')
    parser.add_argument(dest='dst', help='destination path')

    main(parser)

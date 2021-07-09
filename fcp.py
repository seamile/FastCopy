#!/usr/bin/env python

import os
import sys
import logging
import paramiko
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from getpass import getpass, getuser
from os.path import abspath
from socket import socket, create_connection
from textwrap import dedent
from typing import List, Optional, Union
from paramiko import pkey

import sshtunnel

from const import Flag, SERVER_ADDR
from network import Packet, send_msg, recv_msg
from transport import Sender, Receiver, Transporter


def _add_handler(logger, handler, loglevel=None):
    """
    Add a handler to an existing logging.Logger object
    """
    handler.setLevel(loglevel or logging.ERROR)
    handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(handler)


sshtunnel._add_handler = _add_handler


class ArgsError(Exception):
    pass


class Client:
    ssh_default_port = 22
    ssh_default_dir = os.path.expanduser('~/.ssh')
    ssh_config_file = os.path.join(ssh_default_dir, 'config')

    def __init__(self, args_parser: ArgumentParser):
        self.args_parser = args_parser
        args = parser.parse_args()

        (
            self.action,
            self.srcs,
            self.dst,
            self.user,
            self.host
        ) = self.parse_cli_args(args)
        self.port = args.port
        self.pkey = args.private_key
        self.config = self.load_ssh_config(self.host, args.ssh_config)
        self.max_channel = args.num
        self.set_log(args.verbose)

        self.sid = 0

        # create by self.connect()
        self.transporter: Optional[Transporter] = None
        self.tunnels: List = []

    def parse_remote_addr(self, remote):
        '''解析远程主机登录信息'''
        netloc, path = remote.split(':')
        user, host = netloc.split('@') if '@' in netloc else ('', netloc)
        return user, host, path

    def parse_remote_sources(self, sources):
        users, hosts, srcs = set(), set(), set()
        for src in sources:
            user, host, path = self.parse_remote_addr(src)
            users.add(user)
            hosts.add(host)
            srcs.add(path)
        if len(users) == 1 and len(hosts) == 1:
            return users.pop(), hosts.pop(), ','.join(sorted(srcs))
        else:
            raise ValueError('All source args must come from the same machine with same user.')

    def parse_cli_args(self, args):
        '''解析命令行参数'''
        if ':' in args.srcs[0]:
            user, host, srcs = self.parse_remote_sources(args.srcs)
            return Flag.PULL, srcs, args.dst, user, host
        elif ':' in args.dst:
            user, host, dst = self.parse_remote_addr(args.dst)
            return Flag.PUSH, args.srcs, dst, user, host
        else:
            self.args_parser.print_help()
            sys.exit(1)

    def set_log(self, verbose_mode):
        '''处理日志'''
        log_level = logging.DEBUG if verbose_mode else logging.INFO
        logging.basicConfig(level=log_level, format='%(message)s')

    @classmethod
    def load_ssh_config(cls, hostname: str, user_config_file=None) -> dict:
        '''加载默认配置'''
        _path = user_config_file or cls.ssh_config_file
        cfg = paramiko.SSHConfig.from_path(_path)
        return cfg.lookup(hostname)

    @staticmethod
    def load_key(key_path):
        '''加载 Key'''
        _path = os.path.abspath(os.path.expanduser(key_path))
        if not os.path.isfile(_path):
            return

        # guess key type
        filename = os.path.basename(_path)
        key_type = filename.split('_')[1] if filename.startswith('id_') else ''
        key_types = ['rsa', 'ed25519', 'dsa', 'ecdsa']
        key_classes = {'rsa': paramiko.RSAKey, 'ed25519': paramiko.Ed25519Key,
                       'dsa': paramiko.DSSKey, 'ecdsa': paramiko.ECDSAKey}

        types_to_try = [key_type] if key_type in key_types else key_types
        for i in range(3):
            password = None
            for _type in types_to_try:
                key_cls = key_classes[_type]
                try:
                    return key_cls.from_private_key_file(key_path, password)
                except paramiko.PasswordRequiredException:
                    password = getpass(f"Enter password for key '{key_path}': ")
                except paramiko.SSHException:
                    continue

    def create_transport(self, sock, user, pkey, password):
        '''创建新的 ssh transport'''
        try:
            tp = paramiko.Transport(sock)
            tp.connect(username=user, pkey=pkey, password=password)
            return tp
        except paramiko.SSHException:
            tp.stop_thread()

    def init_transport(self, host, port=None, username=None, pkey_path=None):
        '''创建 ssh_transport'''
        # 获取 SSH 服务器的连接参数
        host = self.config.get('hostname', host)
        port = port or self.config.get('port') or self.ssh_default_port
        username = username or self.config.get('user') or getuser()

        # search private keys
        pkey_paths = [pkey_path] if pkey_path else self.config.get('identityfile', [])
        if not pkey_paths:
            for filename in os.listdir(self.ssh_default_dir):
                if filename.startswith('id_') and not filename.endswith('.pub'):
                    path = os.path.join(self.ssh_default_dir, filename)
                    pkey_paths.append(path)

        # connect to ssh server (just connect, not auth)
        addr = (host, port)
        sock = socket.create_connection(addr)

        # try the pkeys one by one
        for _path in pkey_paths:
            key = self.load_key(_path)
            if tp := self.create_transport(sock, username, key, None):
                return tp

        # try to auth with password
        for _ in range(3):
            password = getpass(f'password for {username}@{host}: ')
            if tp := self.create_transport(sock, username, None, password):
                return tp

    def handshake(self, channel, remote_path: Union[str, list]):
        '''握手'''
        packet = Packet.load(self.action, remote_path)
        send_msg(channel, packet)
        packet = recv_msg(channel)
        self.sid, = packet.unpack_body()

    def init_conn(self):
        '''初始化连接'''
        transport = self.init_transport(self.host, self.port, self.user)
        if self.action == Flag.PULL:
            self.handshake(self.srcs)
            self.transporter = Receiver(self.sid, abspath(self.dst), self.max_channel)

        elif self.action == Flag.PUSH:
            self.handshake(self.dst)
            srcs = [abspath(path) for path in self.srcs]
            self.transporter = Sender(self.sid, srcs, self.max_channel)

        else:
            parser.print_help()
            sys.exit(1)

        self.transporter.conn_pool.add(self.sock)

    def create_parallel_connections(self):
        '''创建并行连接'''
        attach_pkt = Packet.load(Flag.ATTACH, self.sid)
        datagram = attach_pkt.pack()
        for _ in range(self.max_channel - 1):
            sock = create_connection(self.addr)
            sock.send(datagram)
            self.transporter.conn_pool.add(sock)

    def run(self, parser: ArgumentParser):
        '''主函数'''
        try:
            logging.info('[Client] Connecting to server')
            self.init_conn()
            self.create_parallel_connections()
            self.transporter.start()  # type:ignore
            self.transporter.join()  # type:ignore
        except Exception as e:
            logging.error(f'[Client] {e}, exit.')
            sys.exit(1)


if __name__ == '__main__':
    parser = ArgumentParser(
        prog='fcp',
        formatter_class=RawDescriptionHelpFormatter,
        description=dedent('''
            PULL : fcp [OPTIONS...] [USER@]HOST:SRC... DST
            PUSH : fcp [OPTIONS...] SRC... [USER@]HOST:DST
        ''')
    )

    parser.add_argument('-p', dest='port', type=int, default=None,
                        help='The port of SSH server (default: 22)')

    parser.add_argument('-i', dest='private_key', type=str, default=None,
                        help='The private key file for SSH')

    parser.add_argument('-F', dest='ssh_config', type=str, default=None,
                        help='The config file for SSH (default: ~/.ssh/config)')

    parser.add_argument('-n', dest='num', type=int, default=16,
                        help='Max number of connections (default: 16)')

    parser.add_argument('-v', dest='verbose', action='count', default=0,
                        help='Verbose mode (default: disable)')

    parser.add_argument(dest='srcs', nargs='+', help='source path')
    parser.add_argument(dest='dst', help='destination path')

    args = parser.parse_args()
    print(args.password)
    # cli = Client.parse_args(parser)
    # cli.run()

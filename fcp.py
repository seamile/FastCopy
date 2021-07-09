#!/usr/bin/env python

import os
import sys
import logging
import paramiko
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from getpass import getpass, getuser
from os.path import abspath
from socket import create_connection
from textwrap import dedent
from typing import List

from const import Flag, SERVER_ADDR
from network import Packet, send_msg, recv_msg
from transport import Sender, Receiver


class ArgsError(Exception):
    pass


class Client:
    ssh_default_port = 22
    ssh_default_dir = os.path.expanduser('~/.ssh')
    ssh_config_file = os.path.join(ssh_default_dir, 'config')

    def __init__(self, cli_parser: ArgumentParser):
        args = cli_parser.parse_args()
        self.set_log(args.verbose)

        try:
            # init instance attributes from CLI args:
            #   - self.action:   Flag.PUSH | Flag.PULL
            #   - self.host:     ssh server's ip or domain
            #   - self.username: username used to login to the ssh server
            #   - self.srcs:     source dirs or files
            #   - self.dst:      dest dir or file
            self.parse_cli_args(args)
        except Exception as e:
            logging.error(e)
            cli_parser.print_help()
            sys.exit(1)

        self.config = self.load_ssh_config(self.host, args.ssh_config)
        self.max_channel = args.num
        self.port = args.port
        self.pkey_path = args.private_key

        # the ssh tunnels
        # inside: [(paramiko.Transport, paramiko.Channel), (...), ...]
        self.tunnels: List = []

    @staticmethod
    def parse_remote_addr(remote):
        '''解析远程主机登录信息'''
        netloc, path = remote.split(':')
        user, host = netloc.split('@') if '@' in netloc else ('', netloc)
        return user, host, path

    @classmethod
    def parse_remote_sources(cls, sources):
        users, hosts, srcs = set(), set(), set()
        for src in sources:
            user, host, path = cls.parse_remote_addr(src)
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
            self.username, self.host, self.srcs = self.parse_remote_sources(args.srcs)
            self.action = Flag.PULL
            self.dst = args.dst
        elif ':' in args.dst:
            self.username, self.host, self.dst = self.parse_remote_addr(args.dst)
            self.action = Flag.PUSH
            self.srcs = args.srcs
        else:
            raise ValueError('Server address not specified.')

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

    def new_channel(self, sock, user, pkey, password):
        '''create a new Channel'''
        try:
            tp = paramiko.Transport(sock)
            tp.use_compression(True)
            tp.set_keepalive(60)
            tp.connect(username=user, pkey=pkey, password=password)
            channel = tp.open_channel('direct-tcpip', SERVER_ADDR, ('localhost', 0))
            self.tunnels.append((tp, channel))
            return True
        except paramiko.SSHException:
            tp.stop_thread()
            return False

    def connect(self):
        '''连接服务器'''
        # 获取 SSH 服务器的连接参数
        self.host = self.config.get('hostname', self.host)
        self.port = self.port or self.config.get('port') or self.ssh_default_port
        self.username = self.username or self.config.get('user') or getuser()

        # search private keys
        pkey_paths = [self.pkey_path] if self.pkey_path else self.config.get('identityfile', [])
        if not pkey_paths:
            for filename in os.listdir(self.ssh_default_dir):
                if filename.startswith('id_') and not filename.endswith('.pub'):
                    path = os.path.join(self.ssh_default_dir, filename)
                    pkey_paths.append(path)

        # connect to ssh server (just connect, not auth)
        addr = (self.host, self.port)
        sock = create_connection(addr)

        # try the pkeys one by one
        for _path in pkey_paths:
            key = self.load_key(_path)
            if self.new_channel(sock, self.username, key, None):
                for _ in range(self.max_channel - 1):
                    self.new_channel(sock, self.username, key, None)
                return

        # try to auth with password
        for _ in range(3):
            password = getpass(f'password for {self.username}@{self.host}: ')
            if self.new_channel(sock, self.username, None, password):
                for _ in range(self.max_channel - 1):
                    self.new_channel(sock, self.username, None, password)
                return

        logging.error('Failed to create SSH tunnel')
        sys.exit(1)

    def handshake(self, remote_path: str):
        '''握手'''
        channel = self.tunnels[0][1]
        conn_pkt = Packet.load(self.action, remote_path)
        send_msg(channel, conn_pkt)
        session_pkt = recv_msg(channel)
        session_id, = session_pkt.unpack_body()

        attach_pkt = Packet.load(Flag.ATTACH, session_id)
        for _, channel in self.tunnels:
            send_msg(channel, attach_pkt)

        return session_id

    def start(self):
        '''主函数'''
        try:
            logging.info('[Client] Connecting to server')
            self.connect()

            if self.action == Flag.PULL:
                session_id = self.handshake(self.srcs)
                transporter = Receiver(session_id, abspath(self.dst), self.max_channel)
            else:
                session_id = self.handshake(self.dst)
                srcs = [abspath(path) for path in self.srcs]
                transporter = Sender(session_id, srcs, self.max_channel)

            for _, channel in self.tunnels:
                transporter.conn_pool.add(channel)

            transporter.start()
            transporter.join()
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

    cli = Client(parser)
    cli.start()

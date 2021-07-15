#!/usr/bin/env python

import os
import sys
import logging
import paramiko
import signal
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from getpass import getpass, getuser
from json import dumps
from os.path import abspath
from socket import create_connection
from textwrap import dedent
from threading import Thread
from time import sleep
from typing import List
from functools import partial

from utils import Flag, SERVER_ADDR, TIMEOUT
from utils import Packet, send_msg, recv_msg
from utils import Sender, Receiver, progress


class Client:
    default_port = 22
    default_dir = os.path.expanduser('~/.ssh')
    default_config = os.path.join(default_dir, 'config')

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
        self.n_channel = args.num
        self.port = args.port
        self.pkey_path = args.private_key
        self.include = args.include
        self.exclude = [p for p in args.exclude.split(',') if p]

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
            return users.pop(), hosts.pop(), sorted(srcs)
        else:
            raise ValueError('All source args must come from '
                             'the same machine with same user.')

    def parse_cli_args(self, args):
        '''解析命令行参数'''
        if ':' in args.srcs[0]:
            self.username, self.host, self.srcs = self.parse_remote_sources(args.srcs)
            self.action = Flag.PULL
            self.dst = abspath(args.dst)
        elif ':' in args.dst:
            self.username, self.host, self.dst = self.parse_remote_addr(args.dst)
            self.action = Flag.PUSH
            self.srcs = [abspath(path) for path in args.srcs]
        else:
            raise ValueError('Server address not specified.')

    def set_log(self, verbose_mode):
        '''处理日志'''
        global print
        print = partial(progress.print, style='blue')

        log_level = {
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
            3: logging.DEBUG
        }.get(verbose_mode, logging.ERROR)

        if log_level <= logging.ERROR:
            logging.error = partial(progress.print, style='red')
        if log_level <= logging.WARNING:
            logging.warning = partial(progress.print, style='yellow')
        if log_level <= logging.INFO:
            print = partial(progress.print, style='blue')
        if log_level <= logging.DEBUG:
            logging.debug = partial(progress.print, style='white')

        paramiko_logger = logging.getLogger("paramiko")
        paramiko_logger.setLevel(logging.ERROR)

    @classmethod
    def load_ssh_config(cls, hostname: str, user_config_file=None) -> dict:
        '''加载默认配置'''
        _path = user_config_file or cls.default_config
        cfg = paramiko.SSHConfig.from_path(_path)
        return cfg.lookup(hostname)

    @staticmethod
    def load_pkey(key_path):
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

    def search_pkeys(self):
        '''查找可用的私钥'''
        if self.pkey_path:
            pkey_paths = [self.pkey_path]
        else:
            pkey_paths = self.config.get('identityfile', [])

        if not pkey_paths:
            for keyname in os.listdir(self.default_dir):
                if keyname.startswith('id_') and not keyname.endswith('.pub'):
                    path = os.path.join(self.default_dir, keyname)
                    pkey_paths.append(path)

        logging.debug(f'found pkeys: {pkey_paths}')

        return pkey_paths

    def new_channel_name(self):
        '''产生一个新的 Channel 名'''
        if not hasattr(self, '_chanid'):
            self._chanid = 0
        self._chanid += 1
        return f'{self._chanid:03d}'

    def new_channel(self, sock, user, pkey, password, num=1):
        '''create a new Channel'''
        try:
            tp = paramiko.Transport(sock)
            tp.use_compression(True)
            tp.set_keepalive(60)
            tp.connect(username=user, pkey=pkey, password=password)
        except paramiko.SSHException:
            tp.stop_thread()
            return

        try:
            conns = [tp]
            for _ in range(num):
                channel = tp.open_channel('direct-tcpip', SERVER_ADDR, ('localhost', 0))
                channel.settimeout(TIMEOUT)
                channel.set_name(self.new_channel_name())
                conns.append(channel)
            self.tunnels.append(conns)
            return conns[1:]
        except paramiko.ChannelException:
            sys.exit(1)

    def first_connect(self):
        '''连接服务器'''
        # 获取 SSH 服务器的连接参数
        self.host = self.config.get('hostname', self.host)
        self.port = self.port or self.config.get('port') or self.default_port
        self.username = self.username or self.config.get('user') or getuser()
        logging.debug(f'login info: {self.username}@{self.host}:{self.port}')

        # search private keys
        pkey_paths = self.search_pkeys()

        # connect to ssh server (just connect, not auth)
        addr = (self.host, self.port)
        sock = create_connection(addr)

        # try the pkeys one by one
        for _path in pkey_paths:
            logging.debug(f'test pkey: {_path}')
            pkey = self.load_pkey(_path)
            channels = self.new_channel(sock, self.username, pkey, None)
            if channels:
                return channels[0], pkey, None

        # try to auth with password
        for _ in range(3):
            password = getpass(f'password for {self.username}@{self.host}: ')
            channels = self.new_channel(sock, self.username, None, password)
            if channels:
                return channels[0], None, password

        logging.error('Failed to create SSH tunnel')
        sys.exit(1)

    def handshake(self, remote_path: str):
        '''握手'''
        channel = self.tunnels[0][1]
        conn_pkt = Packet.load(self.action, remote_path)
        send_msg(channel, conn_pkt)
        session_pkt = recv_msg(channel)
        session_id, = session_pkt.unpack_body()
        logging.debug(f'[cyan]fcp[/cyan]: Channel {channel.get_name()} connected')

        return session_id

    def attched_connect(self, porter, session_id, pkey, password):
        '''后续连接'''
        addr = (self.host, self.port)
        attach_pkt = Packet.load(Flag.ATTACH, session_id)

        def _connect(wait):
            sleep(wait)
            sock = create_connection(addr)
            channels = self.new_channel(sock, self.username, pkey, password, 3)
            for channel in channels:
                send_msg(channel, attach_pkt)
                porter.conn_pool.add(channel)
                logging.debug(f'[cyan]fcp[/cyan]: Channel {channel.get_name()} connected')

        for i in range(self.n_channel - 1):
            Thread(target=_connect, args=(0.5 * i,), daemon=True).start()

    def start(self):
        '''主函数'''
        try:
            progress.start()
            print('[cyan]fcp[/cyan]: connecting to server ...')
            channel, pkey, password = self.first_connect()

            if self.action == Flag.PULL:
                remote_path = dumps({
                    'srcs': self.srcs,
                    'include': self.include,
                    'exclude': self.exclude
                }, ensure_ascii=False, separators=(',', ':'))
                session_id = self.handshake(remote_path)
                porter = Receiver(session_id, self.dst, self.n_channel)
                print('[cyan]fcp[/cyan]: receiving files ...')
            else:
                session_id = self.handshake(self.dst)
                porter = Sender(session_id, self.srcs, self.n_channel,
                                self.include, self.exclude)
                print('[cyan]fcp[/cyan]: sending files ...')

            porter.start()
            porter.conn_pool.add(channel)
            self.attched_connect(porter, session_id, pkey, password)
            porter.join()
            print('[cyan]fcp[/cyan]: finished.')
        except Exception as e:
            from traceback import print_exc
            logging.error(f'[cyan]fcp[/cyan]: {e}, exit.')
            print_exc()
            sys.exit(1)
        finally:
            progress.stop()


def handle_sigint(signum, frame):
    '''键盘中断事件的处理'''
    logging.error('[cyan]fcp[/cyan]: user canceled.')
    progress.stop()
    sys.exit(1)


signal.signal(signal.SIGINT, handle_sigint)


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

    parser.add_argument('-n', dest='num', type=int, default=4,
                        help='Max number of connections (default: %(default)s)')

    parser.add_argument('-v', dest='verbose', action='count', default=0,
                        help='Verbose mode (default: disable)')

    parser.add_argument('--include', type=str, metavar='PATTERN', default='*',
                        help='include files matching PATTERN')

    parser.add_argument('--exclude', type=str, metavar='PATTERN', default='',
                        help='exclude files matching PATTERN, split by `,`')

    parser.add_argument(dest='srcs', nargs='+', help='source path')
    parser.add_argument(dest='dst', help='destination path')

    cli = Client(parser)
    cli.start()

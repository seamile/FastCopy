#!/usr/bin/env python

import os
import sys
import logging
import signal
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from functools import partial, wraps
from getpass import getpass, getuser
from json import dumps
from os.path import abspath
from pwd import getpwuid
from socket import create_connection
from textwrap import dedent
from threading import Thread
from time import sleep
from typing import Any, Dict, List, Tuple

from paramiko import Channel, Transport, SSHConfig
from paramiko import RSAKey, DSSKey, ECDSAKey, Ed25519Key
from paramiko import SSHException, ChannelException, PasswordRequiredException
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import SERVER_ADDR, SSH_MUX, TIMEOUT
from .network import Flag, Packet, send_pkt, recv_pkt
from .transfer import Sender, Receiver, trans_progress


conn_progress = Progress(
    TextColumn("[bold blue]Connecting "),
    TextColumn("[progress.percentage]{task.completed}/{task.total} "),
    SpinnerColumn(finished_text='✓')
)


def retry(num, *, wait, exceptions=(Exception,)):
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for i in range(num):
                try:
                    return func(*args, **kwargs)
                except exceptions as err:
                    if i + 1 == num:
                        raise RuntimeError from err
                    sleep(wait)
                    continue
        return wrapper
    return deco


class Client:
    default_port = 22
    default_dir = os.path.expanduser('~/.ssh')
    default_config = os.path.join(default_dir, 'config')

    def __init__(self, cli_parser: ArgumentParser):
        args = cli_parser.parse_args()

        # init logger
        self.log_level = {
            0: logging.ERROR,
            1: logging.WARNING,
            2: logging.INFO,
            3: logging.DEBUG
        }.get(args.verbose, logging.ERROR)
        self.set_log()

        try:
            # init instance attributes from CLI args:
            #   - self.action:   Flag.PUSH | Flag.PULL
            #   - self.host:     ssh server's ip or domain
            #   - self.username: username used to login to the ssh server
            #   - self.srcs:     source dirs or files
            #   - self.dst:      dest dir or file
            self.parse_cli_args(args)
        except Exception as e:
            msg = f'[b]fcp[/b]: {e}'
            logging.fatal(msg)
            print('-' * (len(msg) - 7))
            cli_parser.print_help()
            sys.exit(1)

        self.config = self.load_ssh_config(self.host, args.ssh_config)
        self.port = args.port
        self.pkey_path = args.private_key
        self.include = args.include
        self.exclude = [p for p in args.exclude.split(',') if p]
        self.n_tunnel = args.num
        self.n_channel = self.n_tunnel * SSH_MUX
        self.conn_tid = conn_progress.add_task('Connecting',
                                               total=self.n_channel)

        # the ssh tunnels
        self.tunnels: Dict[Transport, List[Channel]] = {}

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
            raise ValueError('The server address is not specified.')

    def set_log(self):
        '''处理日志'''
        global print
        print = partial(conn_progress.print, style='cyan')

        logging.root.setLevel(self.log_level)
        if self.log_level <= logging.ERROR:
            logging.fatal = partial(conn_progress.print, style='bold red')
            logging.error = partial(conn_progress.print, style='red')
        if self.log_level <= logging.WARNING:
            logging.warning = partial(conn_progress.print, style='yellow')
        if self.log_level <= logging.INFO:
            logging.info = partial(conn_progress.print, style='blue')
        if self.log_level <= logging.DEBUG:
            logging.debug = partial(conn_progress.print, style='white')

        logging.getLogger("paramiko").setLevel(logging.FATAL)

    @classmethod
    def load_ssh_config(cls, hostname: str, user_config_file=None) -> dict:
        '''加载默认配置'''
        _path = user_config_file or cls.default_config
        if os.path.isfile(_path):
            cfg = SSHConfig.from_path(_path)
            return cfg.lookup(hostname)
        else:
            return {}

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
        key_classes = {
            'rsa': RSAKey,
            'ed25519': Ed25519Key,
            'dsa': DSSKey,
            'ecdsa': ECDSAKey
        }

        types_to_try = [key_type] if key_type in key_types else key_types
        for _ in range(3):
            password = None
            for _type in types_to_try:
                key_cls = key_classes[_type]
                try:
                    return key_cls.from_private_key_file(key_path, password)
                except PasswordRequiredException:
                    password = getpass(f"Enter password for key '{key_path}': ")
                except SSHException:
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

    def create_transport(self, sock, user, pkey, password):
        if isinstance(sock, tuple):
            sock = create_connection(sock)
        tp = Transport(sock)
        tp.use_compression(True)
        tp.set_keepalive(60)
        try:
            tp.connect(username=user, pkey=pkey, password=password)
            if tp.is_authenticated():
                self.tunnels[tp] = []
                return tp
        except SSHException as e:
            tp.stop_thread()
            if 'Connection reset by peer' in str(e):
                raise ConnectionResetError from e
            else:
                logging.warning(f'[b]fcp[/b]: create transport failed due to {e}')

    def create_channel(self, transport: Transport) -> Channel:  # type: ignore
        '''create a new channel by transport'''
        try:
            # create channel
            channel = transport.open_channel(kind='direct-tcpip',
                                             dest_addr=SERVER_ADDR,
                                             src_addr=('localhost', 0))
            channel.settimeout(TIMEOUT)

            # add to self.tunnels
            channels = self.tunnels.setdefault(transport, [])
            channels.append(channel)

            conn_progress.update(self.conn_tid, advance=1)
            return channel
        except (SSHException, ChannelException) as e:
            logging.error(f'[b]fcp[/b]: create channel failed due to {e}')
            sys.exit(1)

    def ssh_connect(self) -> Tuple[Transport, Any, Any]:  # type: ignore
        '''连接 SSH 服务器'''
        # 获取 SSH 服务器的连接参数
        self.host = self.config.get('hostname', self.host)
        self.port = self.port or self.config.get('port') or self.default_port
        self.port = int(self.port)
        self.username = self.username or self.config.get('user') or getuser()
        logging.debug(f'login info: {self.username}@{self.host}:{self.port}')

        # search private keys
        pkey_paths = self.search_pkeys()

        # connect to ssh server (just connect, not auth)
        addr = (self.host, self.port)

        # try the pkeys one by one
        for _path in pkey_paths:
            logging.info(f'[b]test pkey[/b]: {_path}')
            pkey = self.load_pkey(_path)
            tp = self.create_transport(addr, self.username, pkey, None)
            if tp:
                self.tunnels[tp] = []
                return tp, pkey, None

        # try to auth with password
        for _ in range(3):
            password = conn_progress.console.input(
                f'password for {self.username}@{self.host}:\n',
                password=True
            )
            logging.debug('[b]test password[/b]: %s' % password)
            tp = self.create_transport(addr, self.username, None, password)
            if tp:
                self.tunnels[tp] = []
                return tp, None, password
            else:
                print('[b]fcp[/b]: wrong password!', style='red')  # type:ignore

        logging.error('[b]fcp[/b]: failed to create SSH tunnel')
        sys.exit(1)

    def handshake(self, channel, conn_info: str):
        '''握手'''
        conn_pkt = Packet.load(self.action, conn_info)
        send_pkt(channel, conn_pkt)
        session_pkt = recv_pkt(channel)
        session_id, = session_pkt.unpack_body()
        logging.info(f'[b]fcp[/b]: Channel-{id(channel):x} connected')

        return session_id

    def create_attached_channels(self, tp, conn_pool, session_id):
        channels = self.tunnels[tp]
        attach_pkt = Packet.load(Flag.ATTACH, session_id)

        def _attache_channel():
            channel = self.create_channel(tp)
            send_pkt(channel, attach_pkt)
            conn_pool.add(channel)
            logging.info(f'[b]fcp[/b]: Channel-{id(channel):x} connected')

        for _ in range(SSH_MUX - len(channels)):
            thr = Thread(target=_attache_channel, daemon=True)
            thr.start()

    def attached_connect(self, conn_pool, session_id, pkey, password):
        '''后续连接'''
        addr = (self.host, self.port)

        @retry(3, wait=0.3, exceptions=ConnectionResetError)
        def _attache():
            tp = self.create_transport(addr, self.username, pkey, password)
            self.create_attached_channels(tp, conn_pool, session_id)

        # create channels from exists transports
        for tp in self.tunnels:
            self.create_attached_channels(tp, conn_pool, session_id)

        # create new transports
        for _ in range(self.n_tunnel - len(self.tunnels)):
            thr = Thread(target=_attache, daemon=True)
            thr.start()
            sleep(0.3)

    def start(self):
        progress_table = Table.grid()
        progress_table.add_row(conn_progress)
        progress_table.add_row(trans_progress)

        with Live(progress_table, refresh_per_second=10):
            try:
                tp, pkey, password = self.ssh_connect()
                first_channel = self.create_channel(tp)
                local_user = getpwuid(os.getuid()).pw_name

                if self.action == Flag.PULL:
                    conn_info = dumps({
                        'user': self.username,
                        'srcs': self.srcs,
                        'include': self.include,
                        'exclude': self.exclude
                    }, ensure_ascii=False, separators=(',', ':'))
                    session_id = self.handshake(first_channel, conn_info)
                    porter = Receiver(session_id, local_user, self.dst,
                                      self.n_channel)
                else:
                    conn_info = dumps({
                        'user': self.username,
                        'dst': self.dst
                    })
                    session_id = self.handshake(first_channel, conn_info)
                    porter = Sender(session_id, local_user, self.srcs,
                                    self.n_channel, self.include, self.exclude)

                porter.conn_pool.add(first_channel)
                porter.start()

                # create attached connections
                t = Thread(target=self.attached_connect,
                           args=(porter.conn_pool, session_id, pkey, password))
                t.start()

                porter.join()
            except Exception as e:
                logging.fatal(f'[b]fcp[/b]: {e}')
                if self.log_level == logging.DEBUG:
                    conn_progress.console.print_exception()
                sys.exit(1)


def handle_sigint(signum, frame):
    '''键盘中断事件的处理'''
    logging.error('[b]fcp[/b]: user canceled.')
    conn_progress.stop()
    trans_progress.stop()
    sys.exit(1)


signal.signal(signal.SIGINT, handle_sigint)


def main():
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

    parser.add_argument('-n', dest='num', type=int, default=8,
                        help='Max number of SSH tunnels (default: %(default)s)')

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


if __name__ == '__main__':
    main()

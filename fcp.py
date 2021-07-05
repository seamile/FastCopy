#!/usr/bin/env python
import os
import sys
import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from binascii import hexlify
from getpass import getpass
from os.path import abspath
from socket import socket, create_connection, gaierror, error as SocketError
from textwrap import dedent
from typing import List, Optional, Union

import paramiko
import sshtunnel

from const import Flag, SERVER_ADDR
from network import NetworkMixin, Packet
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


class SSHTunnelForwarder(sshtunnel.SSHTunnelForwarder):
    '''rewrite `SSHTunnelForwarder`'''

    def _raise(self, exception=sshtunnel.BaseSSHTunnelForwarderError, reason=None):
        self.logger.error(exception(reason))
        sys.exit(1)

    def _consolidate_auth(self,
                          ssh_password=None,
                          ssh_pkey=None,
                          ssh_pkey_password=None,
                          allow_agent=True,
                          host_pkey_directories=None,
                          logger=logging.root):
        """
        Get sure authentication information is in place.
        ``ssh_pkey`` may be of classes:
            - ``str`` - in this case it represents a private key file; public
            key will be obtained from it
            - ``paramiko.Pkey`` - it will be transparently added to loaded keys
        """
        ssh_loaded_pkeys = []
        if isinstance(ssh_pkey, str):
            ssh_pkey_expanded = os.path.expanduser(ssh_pkey)
            if os.path.isfile(ssh_pkey_expanded):
                ssh_pkey = self.read_private_key_file(
                    pkey_file=ssh_pkey_expanded,
                    pkey_password=ssh_pkey_password or ssh_password,
                    logger=logger
                )
                ssh_loaded_pkeys.append(ssh_pkey)
            else:
                logger.warning('Private key file not found: {0}'.format(ssh_pkey))

        if not ssh_loaded_pkeys:
            ssh_loaded_pkeys = self.get_keys(
                logger=logger,
                host_pkey_directories=host_pkey_directories,
                allow_agent=allow_agent
            )

        if not ssh_password and not ssh_loaded_pkeys:
            prompt = f"{self.ssh_username}@{self.ssh_host}'s Password: "
            ssh_password = getpass(prompt)

        return (ssh_password, ssh_loaded_pkeys)

    def _connect_to_gateway(self):
        """
        Open connection to SSH gateway
         - First try with all keys loaded from an SSH agent (if allowed)
         - Then with those passed directly or read from ~/.ssh/config
         - As last resort, try with a provided password
        """
        for key in self.ssh_pkeys:
            self.logger.debug('Trying to log in with key: {0}'
                              .format(hexlify(key.get_fingerprint())))
            try:
                self._transport = self._get_transport()
                self._transport.connect(hostkey=self.ssh_host_key,
                                        username=self.ssh_username,
                                        pkey=key)
                if self._transport.is_alive:
                    return
            except paramiko.AuthenticationException:
                self.logger.debug('Authentication error')
                self._stop_transport()

        prompt = f"{self.ssh_username}@{self.ssh_host}'s Password: "
        password = self.ssh_password or getpass(prompt)

        for _ in range(2):
            try:
                self._transport = self._get_transport()
                self._transport.connect(hostkey=self.ssh_host_key,
                                        username=self.ssh_username,
                                        password=password)
                if self._transport.is_alive:
                    return
            except paramiko.AuthenticationException:
                self.logger.error('Permission denied, please try again.')
                password = getpass(prompt)
                self._stop_transport()
        self.logger.error('Permission denied (publickey,password).')
        sys.exit(1)

    def _create_tunnels(self):
        """
        Create SSH tunnels on top of a transport to the remote gateway
        """
        if not self.is_active:
            try:
                self._connect_to_gateway()
            except gaierror:  # raised by paramiko.Transport
                msg = 'Could not resolve IP address for {0}, aborting!' \
                    .format(self.ssh_host)
                self.logger.error(msg)
                sys.exit(1)
            except (paramiko.SSHException, SocketError) as e:
                template = 'Could not connect to gateway {0}:{1} : {2}'
                msg = template.format(self.ssh_host, self.ssh_port, e.args[0])
                self.logger.error(msg)
                sys.exit(1)
        for (rem, loc) in zip(self._remote_binds, self._local_binds):
            try:
                self._make_ssh_forward_server(rem, loc)
            except sshtunnel.BaseSSHTunnelForwarderError as e:
                msg = 'Problem setting SSH Forwarder up: {0}'.format(e.value)
                self.logger.error(msg)

    @classmethod
    def get_keys(cls, logger=None, host_pkey_directories=None, allow_agent=False):
        """
        Load public keys from any available SSH agent or local
        .ssh directory.

        Arguments:
            logger (Optional[logging.Logger])

            host_pkey_directories (Optional[list[str]]):
                List of local directories where host SSH pkeys in the format
                "id_*" are searched. For example, ['~/.ssh']

                .. versionadded:: 0.1.0

            allow_agent (Optional[boolean]):
                Whether or not load keys from agent

                Default: False

        Return:
            list
        """
        keys = cls.get_agent_keys(logger=logger) if allow_agent else []

        if host_pkey_directories is None:
            host_pkey_directories = [sshtunnel.DEFAULT_SSH_DIRECTORY]

        paramiko_key_types = {'rsa': paramiko.RSAKey,
                              'dsa': paramiko.DSSKey,
                              'ecdsa': paramiko.ECDSAKey}
        if hasattr(paramiko, 'Ed25519Key'):
            paramiko_key_types['ed25519'] = paramiko.Ed25519Key
        for directory in host_pkey_directories:
            for keytype in paramiko_key_types.keys():
                ssh_pkey_expanded = os.path.expanduser(
                    os.path.join(directory, 'id_{}'.format(keytype))
                )
                try:
                    if os.path.isfile(ssh_pkey_expanded):
                        ssh_pkey = cls.read_private_key_file(
                            pkey_file=ssh_pkey_expanded,
                            logger=logger,
                            key_type=paramiko_key_types[keytype]
                        )
                        if ssh_pkey:
                            keys.append(ssh_pkey)
                except OSError as exc:
                    if logger:
                        logger.warning('Private key file {0} check error: {1}'
                                       .format(ssh_pkey_expanded, exc))
        if logger:
            logger.info('{0} key(s) loaded'.format(len(keys)))
        return keys

    @classmethod
    def read_private_key_file(cls,
                              pkey_file,
                              pkey_password=None,
                              key_type=None,
                              logger=None):
        """
        Get SSH Public key from a private key file, given an optional password

        Arguments:
            pkey_file (str):
                File containing a private key (RSA, DSS or ECDSA)
        Keyword Arguments:
            pkey_password (Optional[str]):
                Password to decrypt the private key
            logger (Optional[logging.Logger])
        Return:
            paramiko.Pkey
        """
        ssh_pkey = None
        key_types = (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey)
        if hasattr(paramiko, 'Ed25519Key'):
            key_types += (paramiko.Ed25519Key, )
        for pkey_class in (key_type,) if key_type else key_types:
            try:
                ssh_pkey = pkey_class.from_private_key_file(
                    pkey_file,
                    password=pkey_password
                )
                break
            except paramiko.PasswordRequiredException:
                prompt = f"Enter passphrase for key '{pkey_file}': "
                pkey_password = getpass(prompt)
                return cls.read_private_key_file(pkey_file, pkey_password,
                                                 key_type, logger)
            except paramiko.SSHException:
                if logger:
                    logger.debug('Private key file ({0}) could not be loaded '
                                 'as type {1} or bad password'
                                 .format(pkey_file, pkey_class))
        return ssh_pkey


class Client(NetworkMixin):
    def __init__(self, action: Flag, srcs: str, dst: str, n_conn: int):
        self.action = action
        self.srcs = srcs
        self.dst = dst

        self.user = ''
        self.sid = 0
        self.n_conn = n_conn

        # create by self.connect()
        self.sock: Optional[socket] = None  # type: ignore
        self.transporter: Optional[Transporter] = None
        self.tunnels: List = []

    def connect(self, host, port=None, user=None, pkey=None, pkey_password=None,
                config_file=None):
        '''创建连接'''
        tunnel = SSHTunnelForwarder(host,
                                    ssh_port=port,
                                    ssh_username=user,
                                    ssh_pkey=pkey,
                                    ssh_private_key_password=pkey_password,
                                    ssh_config_file=config_file,
                                    remote_bind_address=SERVER_ADDR)
        tunnel.start()
        sock = create_connection(tunnel.local_bind_address)
        return sock

    def handshake(self, tunnel: SSHTunnelForwarder, remote_path: Union[str, list]):
        '''握手'''
        tunnel.start()
        print('connect to %s:%s' % tunnel.local_bind_address)
        self.sock = create_connection(tunnel.local_bind_address, timeout=30)

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
        # 解析主机地址等参数
        if ':' in args.srcs[0]:
            user, host, srcs = self.parse_remote_sources(args.srcs)
            return Flag.PULL, srcs, args.dst, user, host
        elif ':' in args.dst:
            user, host, dst = self.parse_remote_addr(args.dst)
            return Flag.PUSH, args.srcs, dst, user, host
        else:
            raise ArgsError

    def set_log(self, verbose_mode):
        '''处理日志'''
        log_level = logging.DEBUG if verbose_mode else logging.INFO
        logging.basicConfig(level=log_level, format='%(message)s')

    def run(self, parser: ArgumentParser):
        '''主函数'''
        args = parser.parse_args()

        self.set_log(args.verbose)

        # 解析源路径、目的路径、远程主机、用户等
        try:
            action, srcs, dst, user, host = self.parse_cli_args(args)
        except ArgsError:
            parser.print_help()
            sys.exit(1)

        tunnel = SSHTunnelForwarder(host,
                                    ssh_username=user,
                                    ssh_port=args.port,
                                    ssh_config_file=args.ssh_config,
                                    ssh_password=args.password,
                                    ssh_pkey=args.private_key,
                                    ssh_private_key_password=None,
                                    remote_bind_address=SERVER_ADDR,
                                    compression=True)

        with tunnel:
            client = Client(action, srcs, dst, args.num)

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
            PULL : fcp [OPTIONS...] [USER@]HOST:SRC... DST
            PUSH : fcp [OPTIONS...] SRC... [USER@]HOST:DST
        ''')
    )

    parser.add_argument('-p', dest='port', type=int, default=22,
                        help='The port of SSH server (default: 22)')

    # parser.add_argument('-P', dest='password', action='store_true',
    #                     help='The password for SSH')

    parser.add_argument('-i', dest='private_key', type=str, default=None,
                        help='The private key file for SSH')

    parser.add_argument('-F', dest='ssh_config', type=str, default='~/.ssh/config',
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

#!/usr/bin/env python

import _socket
import logging
from argparse import ArgumentParser
from json import loads
from socket import socket
from socket import error as SocketError, timeout as TimeoutError
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT
from threading import Lock, Thread
from typing import Dict
from uuid import uuid4

import daemon

from .utils import Flag, SERVER_ADDR
from .utils import Packet, send_pkt, recv_pkt
from .utils import Sender, Receiver, Porter


class WatchDog(Thread):
    def __init__(self, server: 'Server', sock: socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            logging.debug('[WatchDog] waiting for handshake from %s:%d'
                          % self.sock.getpeername())
            self.sock.settimeout(60)
            packet = recv_pkt(self.sock)
            self.sock.settimeout(None)
        except ConnectionResetError:
            logging.error('[WatchDog] connection reset by peer.')
            return
        except TimeoutError:
            # 超时退出
            logging.error('[WatchDog] handshake timeout.')
            self.sock.close()
            return

        if packet.flag == Flag.PULL or packet.flag == Flag.PUSH:
            # 创建 Porter
            path, = packet.unpack_body()
            porter = self.server.create_porter(packet.flag, path)
            porter.conn_pool.add(self.sock)
            porter.start()

            # 将 SID 发送给客户端
            packet = Packet.load(Flag.SID, porter.sid)
            send_pkt(self.sock, packet)

        elif packet.flag == Flag.ATTACH:
            sid, = packet.unpack_body()
            if not self.server.porters[sid].conn_pool.add(self.sock):
                self.sock.close()

        else:
            # 对于错误的类型，直接关闭连接
            logging.debug('close conn')
            self.sock.close()


class Server(Thread):
    max_tasks = 256  # 同时运行的最大任务数量

    def __init__(self, max_conn) -> None:
        super().__init__(daemon=True)
        self.addr = SERVER_ADDR
        self.max_conn = max_conn  # 一个 Porter 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.porters: Dict[bytes, Porter] = {}

    def create_porter(self, cli_flag: Flag, path: str) -> Porter:
        '''创建新 Porter'''
        sid = uuid4().bytes
        if cli_flag == Flag.PULL:
            _path = loads(path)
            srcs = _path['srcs']
            include = _path['include']
            exclude = _path['exclude']
            logging.debug(f'[Server] New task-{sid.hex()} for send {path}')
            self.porters[sid] = Sender(sid, srcs, self.max_conn,
                                       include, exclude)
        else:
            logging.debug(f'[Server] New task-{sid.hex()} for recv {path}')
            self.porters[sid] = Receiver(sid, path, self.max_conn)
        return self.porters[sid]

    def close_all_porters(self):
        '''关闭所有 Porter'''
        logging.debug('[Server] Closing all porters.')
        for porter in self.porters.values():
            porter.close()

    @staticmethod
    def create_socket_server(address, *, family=AF_INET, backlog=None,
                             reuse_port=False):
        """copyed from socket.py"""
        if reuse_port and not hasattr(_socket, "SO_REUSEPORT"):
            raise ValueError("SO_REUSEPORT not supported on this platform")

        sock = socket(family, SOCK_STREAM)
        try:
            if hasattr(_socket, 'SO_REUSEADDR'):
                try:
                    sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                except SocketError:
                    # Fail later on bind(), for platforms which may not
                    # support this option.
                    pass
            if reuse_port:
                sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
            try:
                sock.bind(address)
            except SocketError as err:
                msg = '%s (while attempting to bind on address %r)' % \
                    (err.strerror, address)
                raise SocketError(err.errno, msg) from None
            if backlog is None:
                sock.listen()
            else:
                sock.listen(backlog)
            return sock
        except SocketError:
            sock.close()
            raise

    def run(self):
        self.srv_sock = self.create_socket_server(self.addr,
                                                  backlog=2048,
                                                  reuse_port=True)
        logging.info('[Server] Listening to %s:%d' % self.addr)
        while self.is_running:
            # wait for new connection
            cli_sock, cli_addr = self.srv_sock.accept()
            logging.info('[Server] Accept new connection: %s:%s' % cli_addr)

            # create a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


def main():
    parser = ArgumentParser()
    parser.add_argument('-d',
                        dest='daemon',
                        action='store_true',
                        help='daemonize the fcp process.')

    parser.add_argument('-c',
                        dest='concurrency',
                        metavar='NUM',
                        type=int,
                        default=128,
                        help='max concurrent connections of one task.')

    parser.add_argument('--loglevel',
                        metavar='LEVEL',
                        default='error',
                        choices=['debug', 'info', 'warning', 'error'],
                        help=('specify the server verbosity level. '
                              'Choices: debug | info | warning | error'))

    args = parser.parse_args()

    loglevel = getattr(logging, args.loglevel.upper())
    logformat = '%(asctime)s %(levelname)7s %(module)s.%(lineno)s: %(message)s'

    if args.daemon:
        with daemon.DaemonContext():
            logging.basicConfig(filename='/tmp/fcpd.log',
                                level=loglevel,
                                datefmt='%Y-%m-%d %H:%M:%S',
                                format=logformat)
            server = Server(args.concurrency)
            server.start()
            server.join()
    else:
        logging.basicConfig(level=loglevel,
                            datefmt='%Y-%m-%d %H:%M:%S',
                            format=logformat)
        server = Server(args.concurrency)
        server.start()
        server.join()


if __name__ == '__main__':
    main()

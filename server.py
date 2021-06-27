#!/usr/bin/env python

import socket
import logging
from argparse import ArgumentParser, BooleanOptionalAction
from functools import wraps
from threading import Lock, Thread
from typing import Dict

import daemon

from const import Flag, SERVER_ADDR
from network import NetworkMixin
from transport import Sender, Receiver, Transporter


def singleton(cls):
    '''Singleton Pattern Decorator'''
    obj = None

    @wraps(cls)
    def wrapper(*args, **kwargs):
        nonlocal obj
        if isinstance(obj, cls):
            return obj
        else:
            obj = cls(*args, **kwargs)
            return obj
    return wrapper


class WatchDog(Thread, NetworkMixin):
    def __init__(self, server: 'Server', sock: socket.socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            logging.debug('waiting for the first packet from %s:%d' % self.sock.getpeername())
            self.sock.settimeout(10)
            packet = self.recv_msg()
            self.sock.settimeout(None)
        except socket.timeout:
            # 超时退出
            logging.debug('[WatchDog] handshake timeout, exit.')
            self.sock.close()
            return

        if packet.flag == Flag.PULL or packet.flag == Flag.PUSH:
            # 创建 Transporter
            path, = packet.unpack_body()
            transporter = self.server.create_transporter(packet.flag, path)
            transporter.conn_pool.add(self.sock)
            transporter.start()

            # 将 SID 发送给客户端
            self.send_msg(Flag.SID, transporter.sid)

        elif packet.flag == Flag.ATTACH:
            sid, = packet.unpack_body()
            if not self.server.transporters[sid].conn_pool.add(self.sock):
                self.sock.close()

        else:
            # 对于错误的类型，直接关闭连接
            logging.debug('close conn')
            self.sock.close()


@singleton
class Server(Thread):
    def __init__(self, max_conn=256) -> None:
        super().__init__(daemon=True)
        self.addr = SERVER_ADDR
        self.max_transporters = 65535  # 最大 Transporter 数量，与 Session ID 相关
        self.max_conn = max_conn  # 一个 Transporter 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.next_id = 1
        self.transporters: Dict[int, Transporter] = {}

    def geneate_sid(self) -> int:
        with self.mutex:
            if len(self.transporters) >= self.max_transporters:
                raise ValueError('已达到最大 Transporter 数量，无法创建')

            while self.next_id in self.transporters:
                if self.next_id < self.max_transporters:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def create_transporter(self, cli_flag: Flag, path: str) -> Transporter:
        '''创建新 Transporter'''
        sid = self.geneate_sid()
        if cli_flag == Flag.PULL:
            logging.info(f'[Server] New task-{sid} for send {path}')
            self.transporters[sid] = Sender(sid, path.split(','), self.max_conn)
        else:
            logging.info(f'[Server] New task-{sid} for recv {path}')
            self.transporters[sid] = Receiver(sid, path, self.max_conn)
        return self.transporters[sid]

    def close_all_transporters(self):
        '''关闭所有 Transporter'''
        logging.info('[Server] Closing all transporters.')
        for transporter in self.transporters.values():
            transporter.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        logging.info('[Server] Listening to %s:%d' % self.addr)
        while self.is_running:
            # wait for new connection
            logging.debug('[Server] Waitting for new connections')
            cli_sock, cli_addr = self.srv_sock.accept()
            logging.debug('[Server] Accept new connection: %s:%s' % cli_addr)

            # launch a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', dest='concurrency', metavar='NUM', type=int, default=128,
                        help='maximum concurrent connections')
    parser.add_argument('-d', dest='daemon', type=bool, action=BooleanOptionalAction,
                        help='daemon mode')
    parser.add_argument('-v', dest='verbose', type=bool, action=BooleanOptionalAction,
                        help='verbose mode')

    args = parser.parse_args()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    if args.daemon:
        with daemon.DaemonContext():
            logging.basicConfig(filename='/tmp/fcpd.log', level=log_level, datefmt='%Y-%m-%d %H:%M:%S',
                                format='%(asctime)s %(levelname)7s %(module)s.%(lineno)s: %(message)s')
            server = Server(args.concurrency)
            server.start()
            server.join()
    else:
        logging.basicConfig(level=log_level, datefmt='%Y-%m-%d %H:%M:%S',
                            format='%(asctime)s %(levelname)7s %(module)s.%(lineno)s: %(message)s')
        server = Server(args.concurrency)
        server.start()
        server.join()

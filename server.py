#!/usr/bin/env python

import socket
import logging
from argparse import ArgumentParser, BooleanOptionalAction
from threading import Lock, Thread
from typing import Dict
from uuid import uuid4

import daemon

from const import Flag, SERVER_ADDR
from network import Packet, send_msg, recv_msg
from transport import Sender, Receiver, Transporter


class WatchDog(Thread):
    def __init__(self, server: 'Server', sock: socket.socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            logging.debug('[WatchDog] waiting for the first packet from %s:%d' % self.sock.getpeername())
            self.sock.settimeout(60)
            packet = recv_msg(self.sock)
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
            packet = Packet.load(Flag.SID, transporter.sid)
            send_msg(self.sock, packet)

        elif packet.flag == Flag.ATTACH:
            sid, = packet.unpack_body()
            if not self.server.transporters[sid].conn_pool.add(self.sock):
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
        self.max_conn = max_conn  # 一个 Transporter 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.transporters: Dict[bytes, Transporter] = {}

    def create_transporter(self, cli_flag: Flag, path: str) -> Transporter:
        '''创建新 Transporter'''
        sid = uuid4().bytes
        if cli_flag == Flag.PULL:
            logging.debug(f'[Server] New task-{sid.hex()} for send {path}')
            self.transporters[sid] = Sender(sid, path.split(','), self.max_conn)
        else:
            logging.debug(f'[Server] New task-{sid.hex()} for recv {path}')
            self.transporters[sid] = Receiver(sid, path, self.max_conn)
        return self.transporters[sid]

    def close_all_transporters(self):
        '''关闭所有 Transporter'''
        logging.debug('[Server] Closing all transporters.')
        for transporter in self.transporters.values():
            transporter.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        logging.info('[Server] Listening to %s:%d' % self.addr)
        while self.is_running:
            # wait for new connection
            cli_sock, cli_addr = self.srv_sock.accept()
            logging.info('[Server] Accept new connection: %s:%s' % cli_addr)

            # create a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-c', dest='concurrency', metavar='NUM', type=int, default=128,
                        help='Max concurrent connections of one task')
    parser.add_argument('-d', dest='daemon', type=bool, action=BooleanOptionalAction,
                        help='Daemon mode')
    parser.add_argument('-v', dest='verbose', type=bool, action=BooleanOptionalAction,
                        help='Verbose mode')

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

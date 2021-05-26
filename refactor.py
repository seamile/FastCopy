#!/usr/bin/env python

import socket
from functools import wraps
from struct import unpack
from threading import Lock, Thread
from typing import Dict

from const import Flag
from network import NetworkMixin
from transfer import Sender, Receiver, Transfer


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
            self.sock.settimeout(10)
            cli_flag, *_, payload = self.recv_msg()
            self.sock.settimeout(None)
        except socket.timeout:
            # 超时退出
            self.sock.close()
            return

        if cli_flag == Flag.PULL or cli_flag == Flag.PUSH:
            dst_path = payload.decode('utf8')
            worker = self.server.create_worker(cli_flag, dst_path)
            worker.conn_pool.add(self.sock)
            worker.start()

        elif cli_flag == Flag.ATTACH:
            print('run as a follower')
            sid = unpack('>H', payload)[0]
            worker = self.server.workers[sid]
            worker.conn_pool.add(self.sock)

        else:
            # 对于错误的类型，直接关闭连接
            print('close conn')
            self.sock.close()


@singleton
class Server(Thread):

    def __init__(self, host: str, port: int, max_conn=256) -> None:
        super().__init__(daemon=True)
        self.addr = (host, port)
        self.max_workers = 65535  # 最大 Transfer 数量，与 Session ID 相关
        self.max_conn = max_conn  # 一个 Transfer 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.next_id = 1
        self.workers: Dict[int, Transfer] = {}

    def geneate_sid(self) -> int:
        with self.mutex:
            if len(self.workers) >= self.max_workers:
                raise ValueError('已达到最大 Transfer 数量，无法创建')

            while self.next_id in self.workers:
                if self.next_id < self.max_workers:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def create_worker(self, cli_flag: Flag, dst_path: str) -> Transfer:
        '''创建新 Transfer'''
        sid = self.geneate_sid()
        if cli_flag == Flag.PULL:
            self.workers[sid] = Sender(sid, dst_path)
        else:
            self.workers[sid] = Receiver(sid, dst_path)
        return self.workers[sid]

    def close_all_workers(self):
        '''关闭所有 Transfer'''
        for worker in self.workers.values():
            worker.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        while self.is_running:
            # wait for new connection
            cli_sock, cli_addr = self.srv_sock.accept()
            print('new connection: %s:%s' % cli_addr)

            # launch a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


if __name__ == '__main__':
    # Server 启动方式: fcpd -h host -p port -w 256 -c 128
    # Client 启动方式: fcp -c 100 host:/foo/bar ./loc/
    pass

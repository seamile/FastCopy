#!/usr/bin/env python

import os
import socket
from zlib import crc32
from queue import Queue, Empty
from threading import Thread, Event

from packages import PKG_OK, PKG_END, CHUNK_SIZE


class Reader(Thread):
    def __init__(self, file_path: str, qsize: int):
        super().__init__()
        self.daemon = True
        self.file_path = file_path
        self.file_q = Queue(qsize)
        self.done = Event()

    def run(self):
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f'File `{self.file_path}` not found')
        else:
            num = 0
            with open(self.file_path, 'rb') as fp:
                while chunk := fp.read(CHUNK_SIZE):           # 读取单位长度的数据，如果为空则跳出循环
                    seq = num.to_bytes(4, 'big')              # 序号 4 字节
                    chksum = crc32(chunk).to_bytes(4, 'big')  # 校验和 4 字节
                    length = len(chunk).to_bytes(2, 'big')    # 长度占 2 字节
                    pkg = seq + chksum + length + chunk       # 组装完整数据包
                    self.file_q.put(pkg)                      # 写入队列
                    num += 1
                else:
                    self.file_q.put(PKG_END)  # 文件读完，Head 全部写 1
            self.file_q.join()
            self.done.set()


class Worker(Thread):
    def __init__(self, cli_sock: socket.socket, cli_addr: tuple,
                 data_q: Queue, done: Event):
        super().__init__()
        self.daemon = True
        self.cli_sock = cli_sock
        self.cli_addr = cli_addr
        self.data_q = data_q
        self.done = done

    def run(self):
        print('Worker 启动')
        while not self.done.is_set():
            try:
                package = self.data_q.get(timeout=1)
            except Empty:
                print('empty')
                pass
            else:
                self.cli_sock.send(package)
                result = self.cli_sock.recv(1)
                if result != PKG_OK:
                    print('re-send')
                    continue
                else:
                    print(b'send: %s' % package[:4])
                self.data_q.task_done()


class Server(Thread):
    def __init__(self, host: str, port: int, reader: Reader):
        super().__init__()
        self.name = 'TCPServerThread'
        self.daemon = True
        self.host = host
        self.port = port
        self.reader = reader
        self.clients = {}
        self.workers = []

        # init socket
        self.addr = (self.host, self.port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self) -> None:
        self.sock.bind(self.addr)
        self.sock.listen(2048)
        self.reader.start()

        while not self.reader.done.is_set():
            cli_sock, cli_addr = self.sock.accept()
            self.clients[cli_addr] = cli_sock
            worker = Worker(cli_sock, cli_addr, self.reader.file_q, self.reader.done)
            worker.start()

        for worker in self.workers:
            worker.join()

        self.sock.close()


if __name__ == '__main__':
    reader = Reader('./images.zip', qsize=32)
    srv = Server('0.0.0.0', 7758, reader)
    srv.run()

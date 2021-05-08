#!/usr/bin/env python

import socket
from queue import Queue, Empty
from threading import Thread, Event

from const import PKG_OK


class Worker(Thread):
    def __init__(self, father: 'Server', cli_sock: socket.socket, cli_addr: tuple,
                 data_q: Queue, done: Event):
        super().__init__(daemon=True)
        self.father = father
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
    def __init__(self, host: str, port: int):
        super().__init__(name='TCPServerThread', daemon=True)
        self.addr = (host, port)
        self.sock = None
        self.clients = {}
        self.workers = []

    def run(self) -> None:
        # init socket
        self.sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)

        while True:
            cli_sock, cli_addr = self.sock.accept()
            worker = Worker(self, cli_sock, cli_addr)
            worker.start()


def main():
    pass


if __name__ == '__main__':
    main()

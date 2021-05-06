#!/usr/bin/env python

import socket
from queue import Queue, Empty
from threading import Thread, Event

from packages import PKG_OK
from sender import Reader


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

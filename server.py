#!/usr/bin/env python

import socket
# from queue import Queue, Empty
from threading import Thread

import const
from const import Ptype
from network import NetworkMixin


class Worker(Thread, NetworkMixin):
    def __init__(self, sock, addr):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr

    def gen_session_id(self) -> int:
        pass

    def create_session(self):
        session_id = self.gen_session_id()
        print(session_id)

    def run(self) -> None:
        ptype = self.recv_all(const.LEN_TYPE)
        if ptype == Ptype.PULL:
            pass
        elif ptype == Ptype.PUSH:
            pass
        elif ptype == Ptype.FOLLOWER:
            pass
        else:
            pass


def main(host: str = '0.0.0.0', port: int = 7323, backlog: int = 2048):
    addr = (host, port)
    sock = socket.create_server(addr, backlog=backlog, reuse_port=True)
    sock.settimeout(const.TIMEOUT)

    while True:
        cli_sock, cli_addr = sock.accept()
        worker = Worker(cli_sock, cli_addr)
        worker.start()


if __name__ == '__main__':
    main()

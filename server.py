#!/usr/bin/env python

import socket
from queue import Queue
from struct import unpack
from threading import Thread, Lock
from typing import Dict, List, Tuple

import const
from const import Ptype, Role
from network import NetworkMixin


class Session:
    def __init__(self, session_id: int, role: Role, dest_path: str) -> None:
        self.id = session_id
        self.role = role
        self.dest_path = dest_path
        self.send_q: Queue[bytes] = Queue()
        self.recv_q: Queue[bytes] = Queue()
        self.clients: List[socket.socket] = []

    def attach(self, sock: socket.socket):
        self.clients.append(sock)

    def launch_reader(self):
        pass

    def launch_sender(self):
        pass

    def run_as_sender(self):
        pass

    def run_as_receiver(self):
        pass


class SessionManager:
    '''会话管理器 (单例)'''
    manager = None

    def __new__(cls) -> 'SessionManager':
        if cls.manager is None:
            cls.manager = object.__new__(cls)
        return cls.manager

    def __init__(self, max_session: int = 1024) -> None:
        self.max_session = max_session
        self.sessions: Dict[int, Session] = {}
        self.mutex = Lock()
        self.next_id = 1

    def new_id(self) -> int:
        with self.mutex:
            if len(self.sessions) >= 1024:
                raise ValueError('已达到最大 Session 数量，无法创建')

            while self.next_id in self.sessions:
                if self.next_id < self.max_session:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def new_session(self, role: Role, dest_path: str) -> Session:
        session_id = self.new_id()
        session = Session(session_id, role, dest_path)
        return session

    def get_session(self, session_id: int):
        return self.sessions[session_id]

    def del_session(self, session_id: int):
        return self.sessions.pop(session_id)


class Worker(Thread, NetworkMixin):
    def __init__(self, sock: socket.socket, addr: Tuple[str, int]):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr

    def run(self) -> None:
        s_manager = SessionManager()
        ptype, *_, datagram = self.recv_msg()

        if ptype == Ptype.PULL:
            dest_path = datagram.decode('utf8')
            session = s_manager.new_session(Role.Receiver, dest_path)
            session.attach(self.sock)

        elif ptype == Ptype.PUSH:
            dest_path = datagram.decode('utf8')
            session = s_manager.new_session(Role.Sender, dest_path)
            session.attach(self.sock)

        elif ptype == Ptype.FOLLOWER:
            session_id = unpack('>H', datagram)[0]
            session = s_manager.get_session(session_id)
            session.attach(self.sock)

        else:
            raise TypeError('连接报文类型错误')


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

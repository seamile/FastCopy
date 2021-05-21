#!/usr/bin/env python

import socket
from struct import unpack
from threading import Thread, Lock
from typing import AnyStr, Dict, List, Optional, Tuple, Union

from const import PacketType, Role
from filemanage import Reader, Writer
from network import NetworkMixin


class Session:
    def __init__(self, session_id: int, role: Role, dest_path: AnyStr) -> None:
        self.id = session_id
        self.role = role
        self.dest_path = dest_path  # type: Union[str, bytes]

        self.file_man: Union[Reader, Writer, None] = None
        self.workers: List['Worker'] = []

    def launch_reader(self):
        '''启动 Reader'''
        self.file_man = Reader(self.dest_path)
        self.file_man.start()

    def launch_writer(self):
        '''启动 Writer'''
        self.file_man = Writer()
        self.file_man.start()


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

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close_all_sessions()

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

    def new_session(self, role: Role, dest_path: AnyStr) -> Session:
        session_id = self.new_id()
        session = Session(session_id, role, dest_path)
        return session

    def get_session(self, session_id: int) -> Session:
        return self.sessions[session_id]

    def del_session(self, session_id: int):
        return self.sessions.pop(session_id)

    def close_all_sessions(self):
        pass


class Worker(Thread, NetworkMixin):
    def __init__(self, sock: socket.socket, addr: Tuple[str, int]):
        super().__init__(daemon=True)
        self.name = 'Worker-%s:%s' % addr
        self.sock = sock
        self.addr = addr
        self.sub_thread: Optional[Thread] = None
        self.session: Optional[Session] = None

    def bind_session(self, session: Session):
        self.session = session
        session.workers.append(self)

    def listen_for_sender(self):
        while True:
            ptype, *_, pkg = self.recv_msg()
            self.session.file_man.input_q.put((ptype, pkg))

    def run_as_sender(self):
        '''作为文件发送端运行'''
        # 启动监听子线程
        self.sub_thread = Thread(target=self.listen_for_sender)
        self.sub_thread.start()

        # 从文件读取队列获取数据，并发送到接收端
        while True:
            ptype, payload = self.session.file_man.output_q.get()
            self.send_msg(ptype, payload)

    def run_as_receiver(self):
        '''作为文件接收端运行'''
        while True:
            ptype, *_, payload = self.recv_msg()
            self.session.file_man.input_q.put(ptype, payload)

    def run(self) -> None:
        print(f'{self.name} is running')
        s_manager = SessionManager()
        ptype, *_, datagram = self.recv_msg()
        print(f'Received {ptype.name} msg')

        if ptype == PacketType.SEND:
            # 服务端作为发送端运行
            print(f'{self.name} run as a sender')
            session = s_manager.new_session(Role.Sender, datagram)
            self.bind_session(session)
            self.run_as_sender()

        elif ptype == PacketType.RECV:
            # 服务端作为接收端运行
            print(f'{self.name} run as a receiver')
            session = s_manager.new_session(Role.Receiver, datagram)
            self.bind_session(session)
            self.run_as_receiver()

        elif ptype == PacketType.ATTACH:
            # 将后续连接加入对应会话
            print(f'{self.name} run as a follower')
            session_id = unpack('>H', datagram)[0]
            session = s_manager.get_session(session_id)
            self.bind_session(session)

            if session.role is Role.Sender:
                self.run_as_sender()
            else:
                self.run_as_receiver()

        else:
            raise TypeError('连接报文类型错误')


def main(host: str = '0.0.0.0', port: int = 7323, backlog: int = 2048):
    addr = (host, port)
    sock = socket.create_server(addr, backlog=backlog, reuse_port=True)
    print(f'Listen to {host}:{port}')

    with SessionManager():
        while True:
            cli_sock, cli_addr = sock.accept()
            print('Accept client %s:%d' % cli_addr)
            worker = Worker(cli_sock, cli_addr)
            worker.start()


if __name__ == '__main__':
    main()

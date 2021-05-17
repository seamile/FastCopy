import socket
from functools import wraps
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from struct import unpack
from threading import Lock, Thread
from typing import Dict, List, Union

from const import Ptype, Role
from filemanage import Reader, Writer
from network import NetworkMixin


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


class Session:

    def start(self):
        raise NotImplementedError

    def close(self):
        '''关闭所以连接'''
        for sock in self.conn_pool:
            sock.close()


class Sender(Thread):
    '''读取文件数据，并发送到对端'''

    def __init__(self, sid: int, role: Role, dest_path: str) -> None:
        super().__init__(daemon=True)

        self.id = sid
        self.role = role
        self.dest_path = dest_path

        self.listener = DefaultSelector()
        self.file_man: Union[Reader, Writer, None] = None
        self.conn_pool: List[socket.socket] = []

    def run(self):
        pass


class Receiver(Session):
    '''从对端接收数据，并保存到本地文件'''


class WatchDog(Thread, NetworkMixin):
    def __init__(self, server: 'Server', sock: socket.socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            self.sock.settimeout(10)
            ptype, *_, packet = self.recv_msg()
            self.sock.settimeout(None)
        except socket.timeout:
            self.sock.close()
            return

        if ptype == Ptype.SEND:
            # 作为发送端运行
            print('run as a sender')
            dst_path = packet.decode('utf8')
            session = self.server.create_session(Role.Sender, dst_path)
            session.conn_pool.append(self.sock)
            session.start()

        elif ptype == Ptype.RECV:
            # 作为接收端运行
            print('run as a receiver')
            dst_path = packet.decode('utf8')
            session = self.server.create_session(Role.Receiver, dst_path)
            session.conn_pool.append(self.sock)
            session.start()

        elif ptype == Ptype.FOLLOW:
            print('run as a follower')
            sid = unpack('>H', packet)[0]
            session = self.server.sessions[sid]
            session.conn_pool.append(self.sock)

        else:
            # 对于错误的类型，直接关闭连接
            print('close conn')
            self.sock.close()


@singleton
class Server(Thread):

    def __init__(self, host, port, max_sessions=256) -> None:
        super().__init__(daemon=True)
        self.addr = (host, port)
        self.max_sessions = max_sessions
        self.running = True
        self.mutex = Lock()
        self.next_id = 1
        self.sessions: Dict[int, 'Session'] = {}

    def geneate_sid(self) -> int:
        with self.mutex:
            if len(self.sessions) >= self.max_sessions:
                raise ValueError('已达到最大 Session 数量，无法创建')

            while self.next_id in self.sessions:
                if self.next_id < self.max_sessions:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def create_session(self, role: 'Role', dest_path: str) -> Session:
        '''创建新 Session'''
        sid = self.geneate_sid()
        self.sessions[sid] = Session(sid, role, dest_path)
        return self.sessions[sid]

    def close_all_sessions(self):
        '''关闭所有 Session'''
        for session in self.sessions.values():
            session.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        while self.running:
            # wait for new connection
            cli_sock, cli_addr = self.srv_sock.accept()
            print('new connection: %s:%s' % cli_addr)

            # launch a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


####################################################################################################
#                                              Client                                              #
####################################################################################################


class Client:
    def __init__(self) -> None:
        pass

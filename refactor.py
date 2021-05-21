import socket
from binascii import crc32
from functools import wraps
from queue import Empty, Queue
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from struct import pack, unpack
from threading import Lock, Thread
from typing import Any, Dict, List, NamedTuple, Tuple, Union

from const import PacketType, QUEUE_SIZE, Role, PacketSnippet, LEN_HEAD
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


class Packet(NamedTuple):
    ptype: PacketType
    length: int
    body: bytes

    @staticmethod
    def load(ptype: Union[PacketType, int], body: bytes) -> 'Packet':
        return Packet(PacketType(ptype), len(body), body)

    @property
    def chksum(self) -> int:
        return crc32(self.body)

    def pack(self) -> bytes:
        '''封包'''
        fmt = f'>BIH{self.length}s'
        return pack(fmt, self.ptype, self.chksum, self.length, self.body)

    @staticmethod
    def parse_head(head: bytes) -> Tuple[PacketType, int, int]:
        '''解析 Head'''
        ptype, chksum, length = unpack('>BIH', head)
        return PacketType(ptype), chksum, length

    def parse_body(self) -> Tuple[Any, ...]:
        if self.ptype == PacketType.SEND or self.ptype == PacketType.RECV:
            return unpack(f'>{self.length}s', self.body)  # dest path

        elif self.ptype == PacketType.SESSION or self.ptype == PacketType.FOLLOW:
            return unpack('>H', self.body)  # Session ID

        elif self.ptype == PacketType.FILE_COUNT:
            return unpack('>H', self.body)  # file count

        elif self.ptype == PacketType.FILE_INFO:
            # file_id | perm | size | ctime | mtime | atime | chksum | path
            #   2B    |  2B  |  8B  |  8B   |  8B   |  8B   |  16B   |  ...
            fmt = f'>2HQ3d16s{self.length - 52}s'
            return unpack(fmt, self.body)

        elif self.ptype == PacketType.FILE_READY:
            return unpack('>H', self.body)  # file id

        elif self.ptype == PacketType.FILE_CHUNK:
            # file_id |  seq  | chunk
            #    2B   |  4B   |  ...
            fmt = f'>HI{self.length - 10}'
            return unpack(fmt, self.body)

        else:
            raise TypeError

    def is_valid(self, chksum: int):
        '''是否是有效的包体'''
        return len(self.body) == self.length and self.chksum == chksum


class Buffer:
    __slots__ = ('waiting', 'remain', 'ptype', 'chksum', 'data')

    def __init__(self,
                 waiting: PacketSnippet = PacketSnippet.HEAD,
                 remain: int = LEN_HEAD) -> None:
        self.waiting = waiting
        self.remain = remain
        self.ptype: Any = None
        self.chksum: int = 0
        self.data: bytearray = bytearray()

    def reset(self):
        self.waiting = PacketSnippet.HEAD
        self.remain = LEN_HEAD
        self.ptype = None
        self.chksum = 0
        self.data.clear()


class ConnectionPool:
    def __init__(self) -> None:
        self.input_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.output_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.sender = DefaultSelector()
        self.receiver = DefaultSelector()
        self.is_working = True
        self.threads: List[Thread] = []

    def add_conn(self, sock: socket.socket):
        self.sender.register(sock, EVENT_WRITE)
        self.receiver.register(sock, EVENT_READ, Buffer())

    def rem_conn(self, sock: socket.socket):
        self.sender.unregister(sock)
        self.receiver.unregister(sock)
        sock.close()

    def parse_head(self, buf: Buffer):
        '''解析 head'''
        # 解包
        buf.ptype, buf.chksum, buf.remain = Packet.parse_head(buf.data)

        # 切换 Buffer 为等待接收 body 状态
        buf.waiting = PacketSnippet.BODY
        buf.data.clear()

    def parse_body(self, buf: Buffer):
        '''解析 body'''
        # 检查校验码
        if crc32(buf.data) == buf.chksum:
            # 正确的数据包放入队列
            pkt = Packet.load(buf.ptype, buf.data)
            self.output_q.put(pkt)
        else:
            print('错误的包，丢弃')

        # 一个数据包解析完成后，重置 buf
        buf.reset()

    def send(self):
        '''从 input_q 获取数据，并封包发送到对端'''
        while self.is_working:
            try:
                packet = self.input_q.get(timeout=3)
            except Empty:
                continue  # 队列为空，直接进入下轮循环
            else:
                for key, _ in self.sender.select(timeout=3):
                    msg = packet.pack()
                    key.fileobj.send(msg)
                    break
                else:
                    # 若超时未取到就绪的 sock，则将 packet 放回队列首位，重入循环
                    self.input_q.queue.insert(0, packet)

    def recv(self):
        '''接收并解析数据包, 解析结果存入 output_q 队列'''
        while self.is_working:
            for key, _ in self.receiver.select(timeout=3):
                sock, buf = key.fileobj, key.data
                data = sock.recv(buf.remain)

                if data:
                    buf.remain -= len(data)  # 更新剩余长度
                    buf.data.extend(data)  # 合并数据

                    if buf.remain == 0:
                        if buf.waiting == PacketSnippet.HEAD:
                            self.parse_head(buf)  # 解析 head 部分
                        else:
                            self.parse_body(buf)  # 解析 Body 部分
                else:
                    self.rem_conn(sock)  # 关闭连接

    def launch(self):
        s_thread = Thread(target=self.send, daemon=True)
        s_thread.start()
        self.threads.append(s_thread)

        r_thread = Thread(target=self.recv, daemon=True)
        r_thread.start()
        self.threads.append(r_thread)

    def close_all(self):
        '''关闭所有连接'''
        with self.input_q.mutex:
            self.is_working = False
            for key in list(self.sender.get_map().values()):
                sock = key.fileobj
                sock.close()

        self.sender.close()
        self.receiver.close()


class Session(Thread):
    def __init__(self, sid: int, role: Role, dest_path: str) -> None:
        super().__init__(daemon=True)

        self.id = sid
        self.role = role
        self.dest_path = dest_path

        self.file_man: Union[Reader, Writer, None] = None
        self.conn_pool = ConnectionPool()

    def run_as_sender(self):
        self.file_man = Reader(self.dest_path)
        self.file_man.start()
        while True:
            self.file_man.output_q.get()

    def run_as_receiver(self):
        pass

    def run(self):
        self.conn_pool.launch()
        if self.role == Role.Sender:
            self.run_as_sender()
        else:
            self.run_as_receiver()

    def close(self):
        '''关闭所以连接'''
        self.conn_pool.close_all()


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

        if ptype == PacketType.SEND:
            # 作为发送端运行
            print('run as a sender')
            dst_path = packet.decode('utf8')
            session = self.server.create_session(Role.Sender, dst_path)
            session.conn_pool.add_conn(self.sock)
            session.start()

        elif ptype == PacketType.RECV:
            # 作为接收端运行
            print('run as a receiver')
            dst_path = packet.decode('utf8')
            session = self.server.create_session(Role.Receiver, dst_path)
            session.conn_pool.add_conn(self.sock)
            session.start()

        elif ptype == PacketType.FOLLOW:
            print('run as a follower')
            sid = unpack('>H', packet)[0]
            session = self.server.sessions[sid]
            session.conn_pool.add_conn(self.sock)

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

import socket
from binascii import crc32
from functools import wraps
from queue import Empty, Queue
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from struct import pack, unpack
from threading import Lock, Thread
from typing import Dict, List, Optional, Union

from const import Packet, Ptype, QUEUE_SIZE, Role, BufType, LEN_HEAD
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
    def __init__(self, sid: int, role: Role, dest_path: str) -> None:
        self.id = sid
        self.role = role
        self.dest_path = dest_path

        self.listener = DefaultSelector()
        self.file_man: Union[Reader, Writer, None] = None
        self.conn_pool: List[socket.socket] = []

    def start(self):
        raise NotImplementedError

    def close(self):
        '''关闭所以连接'''
        for sock in self.conn_pool:
            sock.close()


class Buffer:
    __slots__ = ('type', 'remain', 'ptype', 'chksum', 'data')

    def __init__(self, btype: BufType = BufType.HEAD, remain: int = LEN_HEAD) -> None:
        self.btype = btype
        self.remain = remain
        self.ptype: Optional[Ptype] = None
        self.chksum: int = 0
        self.data: bytearray = bytearray()

    def reset(self):
        self.btype = BufType.HEAD
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

    def pack_msg(self, packet: Packet):
        '''打包 packet'''
        chksum = crc32(packet.body)
        length = len(packet.body)
        fmt = f'>BIH{length}s'
        return pack(fmt, packet.ptype, chksum, length, packet.body)

    def check_body(self, chksum: int, body: bytes):
        return crc32(body) == chksum

    def add_conn(self, sock: socket.socket):
        self.sender.register(sock, EVENT_WRITE)
        self.receiver.register(sock, EVENT_READ, Buffer())

    def parse_head(self, buf: Buffer):
        '''解析 head'''
        # 解包
        buf.ptype, buf.chksum, buf.remain = unpack('>BIH', buf.data)
        buf.btype = BufType.BODY
        buf.data.clear()

    def parse_body(self, buf: Buffer):
        '''解析 body'''
        # 检查校验码
        if crc32(buf.data) == buf.chksum:
            # 正确的数据包放入队列
            pkt = Packet(buf.ptype, buf.data)
            self.output_q.put(pkt)
        else:
            print('错误的包，丢弃')

        # 一个数据包解析完成后，重置 buf
        buf.reset()

    def send(self):
        '''从 input_q 获取数据，并封包发送到对端'''
        while True:
            try:
                packet = self.input_q.get(timeout=3)
            except Empty:
                # 队列为空，则直接进入下轮循环
                continue
            else:
                for key, _ in self.sender.select(timeout=3):
                    sock = key.fileobj
                    msg = self.pack_msg(packet)
                    sock.send(msg)
                    break
                else:
                    # 若超时未取到就绪的 sock，则将 packet 放回队列首位，重入循环
                    self.input_q.queue.insert(0, packet)

    def recv(self):
        '''接收并解析数据包, 解析结果存入 output_q 队列'''
        while True:
            for key, _ in self.receiver.select(timeout=3):
                sock, buf = key.fileobj, key.data
                data = sock.recv(buf.remain)

                if data:
                    buf.remain -= len(data)  # 更新剩余长度
                    buf.data.extend(data)  # 合并数据

                    if buf.remain == 0:
                        if buf.btype == BufType.HEAD:
                            self.parse_head(buf)  # 解析 head 部分
                        else:
                            self.parse_body(buf)  # 解析 Body 部分
                else:
                    print('关闭连接')
                    self.receiver.unregister(sock)
                    sock.close()


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

import socket
from binascii import crc32
from queue import Queue, Empty
from selectors import DefaultSelector, EVENT_READ, EVENT_WRITE
from struct import pack, unpack
from threading import Thread
from typing import Any, List, NamedTuple, Tuple

from const import PacketSnippet, Flag, LEN_HEAD


class Packet(NamedTuple):
    flag: Flag
    body: bytes

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def chksum(self) -> int:
        return crc32(self.body)

    @staticmethod
    def load(flag: Flag, *args) -> 'Packet':
        '''将包体封包'''
        if flag == Flag.PULL or flag == Flag.PUSH:
            body = str(args[0]).encode('utf8')
        elif flag == Flag.SID or flag == Flag.ATTACH:
            body = pack('>H', *args)
        elif flag == Flag.FILE_COUNT:
            body = pack('>H', *args)
        elif flag == Flag.FILE_INFO:
            length = len(args[-1])
            body = pack(f'>2HQ3d16s{length}s', *args)
        elif flag == Flag.FILE_READY:
            body = pack('>H', *args)
        elif flag == Flag.FILE_CHUNK:
            length = len(args[-1])
            body = pack(f'>HI{length}s', *args)
        else:
            raise ValueError('Invalid flag')
        return Packet(flag, body)

    def pack(self) -> bytes:
        '''封包'''
        fmt = f'>BIH{self.length}s'
        return pack(fmt, self.flag, self.chksum, self.length, self.body)

    @staticmethod
    def unpack_head(head: bytes) -> Tuple[Flag, int, int]:
        '''解析 head'''
        flag, chksum, length = unpack('>BIH', head)
        return Flag(flag), chksum, length

    def unpack_body(self) -> Tuple[Any, ...]:
        '''将 body 解包'''
        if self.flag == Flag.PULL or self.flag == Flag.PUSH:
            return (self.body.decode('utf8'),)  # dest path

        elif self.flag == Flag.SID or self.flag == Flag.ATTACH:
            return unpack('>H', self.body)  # Worker ID

        elif self.flag == Flag.FILE_COUNT:
            return unpack('>H', self.body)  # file count

        elif self.flag == Flag.FILE_INFO:
            # file_id | perm | size | ctime | mtime | atime | chksum | path
            #   2B    |  2B  |  8B  |  8B   |  8B   |  8B   |  16B   |  ...
            fmt = f'>2HQ3d16s{self.length - 52}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.FILE_READY:
            return unpack('>H', self.body)  # file id

        elif self.flag == Flag.FILE_CHUNK:
            # file_id |  seq  | chunk
            #    2B   |  4B   |  ...
            fmt = f'>HI{self.length - 6}s'
            return unpack(fmt, self.body)

        else:
            raise TypeError

    def is_valid(self, chksum: int):
        '''是否是有效的包体'''
        return self.chksum == chksum


class Buffer:
    __slots__ = ('waiting', 'remain', 'flag', 'chksum', 'data')

    def __init__(self,
                 waiting: PacketSnippet = PacketSnippet.HEAD,
                 remain: int = LEN_HEAD) -> None:
        self.waiting = waiting
        self.remain = remain
        self.flag: Any = None
        self.chksum: int = 0
        self.data: bytearray = bytearray()

    def reset(self):
        self.waiting = PacketSnippet.HEAD
        self.remain = LEN_HEAD
        self.flag = None
        self.chksum = 0
        self.data.clear()


class ConnectionPool:
    def __init__(self, send_q: Queue[Packet], recv_q: Queue[Packet]) -> None:
        self.send_q = send_q
        self.recv_q = recv_q
        self.sender = DefaultSelector()
        self.receiver = DefaultSelector()
        self.is_working = True
        self.threads: List[Thread] = []

    def add(self, sock: socket.socket):
        self.sender.register(sock, EVENT_WRITE)
        self.receiver.register(sock, EVENT_READ, Buffer())

    def remove(self, sock: socket.socket):
        self.sender.unregister(sock)
        self.receiver.unregister(sock)
        sock.close()

    def parse_head(self, buf: Buffer):
        '''解析 head'''
        # 解包
        buf.flag, buf.chksum, buf.remain = Packet.unpack_head(buf.data)

        # 切换 Buffer 为等待接收 body 状态
        buf.waiting = PacketSnippet.BODY
        buf.data.clear()

    def parse_body(self, buf: Buffer):
        '''解析 body'''
        pkt = Packet(buf.flag, buf.data)
        # 检查校验码
        if pkt.is_valid(buf.chksum):
            self.recv_q.put(pkt)  # 正确的数据包放入队列
        else:
            print('错误的包，丢弃')

        # 一个数据包解析完成后，重置 buf
        buf.reset()

    def send(self):
        '''从 send_q 获取数据，并封包发送到对端'''
        while self.is_working:
            try:
                packet = self.send_q.get(timeout=3)
            except Empty:
                continue  # 队列为空，直接进入下轮循环
            else:
                for key, _ in self.sender.select(timeout=3):
                    msg = packet.pack()
                    key.fileobj.send(msg)
                    break
                else:
                    # 若超时未取到就绪的 sock，则将 packet 放回队列首位，重入循环
                    self.send_q.queue.insert(0, packet)

    def recv(self):
        '''接收并解析数据包, 解析结果存入 recv_q 队列'''
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
                    self.remove(sock)  # 关闭连接

    def launch(self):
        s_thread = Thread(target=self.send, daemon=True)
        s_thread.start()
        self.threads.append(s_thread)

        r_thread = Thread(target=self.recv, daemon=True)
        r_thread.start()
        self.threads.append(r_thread)

    def close_all(self):
        '''关闭所有连接'''
        with self.send_q.mutex:
            self.is_working = False
            for key in list(self.sender.get_map().values()):
                sock = key.fileobj
                sock.close()

        self.sender.close()
        self.receiver.close()


class NetworkMixin:
    def connect(self, server_addr: Tuple[str, int]):
        '''建立连接'''
        self.sock = socket.create_connection(server_addr, timeout=30)

    def recv_all(self, length: int) -> bytearray:
        '''接收指定长度的完整数据'''
        buffer = bytearray(length)
        self.sock.recv_into(buffer, length, socket.MSG_WAITALL)
        return buffer

    def send_msg(self, flag: Flag, *args):
        '''发送数据报文'''
        packet = Packet.load(flag, *args)
        datagram = packet.pack()
        self.sock.send(datagram)

    def recv_msg(self):
        '''接收数据报文'''
        head = self.recv_all(7)
        flag, chksum, length = unpack('>BIH', head)
        try:
            flag = Flag(flag)
        except (ValueError, TypeError):
            # TODO: 更好的错误处理
            print('flag error')
            return Flag.ERROR, 0, 0, b''

        payload = self.recv_all(length)

        # 错误重传
        # TODO: 不完善
        if crc32(payload) != chksum:
            self.send_msg(Flag.ERROR, head)

        return Flag(flag), chksum, length, payload

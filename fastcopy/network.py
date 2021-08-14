import logging
from binascii import crc32
from enum import IntEnum
from paramiko import Channel
from queue import Queue
from selectors import SelectSelector, EVENT_WRITE
from socket import socket, error as SocketError
from struct import pack, unpack
from threading import Event, Thread
from typing import Any, NamedTuple, Set, Tuple, Union

from .config import TIMEOUT, LEN_HEAD

Connection = Union[socket, Channel]


class Flag(IntEnum):
    PUSH = 1         # 推送申请
    PULL = 2         # 拉取申请
    SID = 3          # 建立会话
    ATTACH = 4       # 后续连接
    MONOFILE = 5     # 传输模式
    DIR_INFO = 6     # 目录信息
    FILE_INFO = 7    # 文件信息
    FILE_COUNT = 8   # 文件数量
    FILE_READY = 9   # 文件就绪
    FILE_CHUNK = 10  # 数据传输
    DONE = 11        # 完成
    EXCEPTION = 12   # 异常退出

    @classmethod
    def contains(cls, member: object) -> bool:
        return member in cls.__members__.values()


class Packet(NamedTuple):
    flag: Flag
    body: bytes

    def __str__(self) -> str:
        return (f'Packet: {self.flag.name} '
                f'len={self.length} '
                f'chk={self.chksum:08x}')

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
            if isinstance(args[0], bytes):
                body = args[0]
            else:
                body = str(args[0]).encode('utf8')
        elif flag == Flag.SID or flag == Flag.ATTACH:
            body = pack('>16s', *args)
        elif flag == Flag.MONOFILE:
            body = pack('>?', *args)
        elif flag == Flag.DIR_INFO:
            length = len(args[-1])
            body = pack(f'>IH{length}s', *args)
        elif flag == Flag.FILE_INFO:
            chksum, path = args[-2:]
            len_chk = len(chksum)
            n_chksum = len_chk // 16 - 1
            len_path = len(path)
            body = pack(f'>IHQdB{len_chk}s{len_path}s',
                        *args[:-2], n_chksum, chksum, path)
        elif flag == Flag.FILE_COUNT:
            body = pack('>I', *args)
        elif flag == Flag.FILE_READY:
            body = pack('>IQ', *args)
        elif flag == Flag.FILE_CHUNK:
            length = len(args[-1])
            body = pack(f'>2I{length}s', *args)
        elif flag == Flag.DONE:
            body = pack('>?', True)
        elif flag == Flag.EXCEPTION:
            body = str(args[0]).encode('utf8')
        else:
            raise ValueError(f'{flag} is not a valid Flag')
        return Packet(flag, body)

    def pack(self) -> bytes:
        '''封包'''
        fmt = f'>BIH{self.length}s'
        return pack(fmt, self.flag, self.chksum, self.length, self.body)

    @staticmethod
    def unpack_head(head: bytes) -> Tuple[Flag, int, int]:
        '''解析 head'''
        flag, chksum, length = unpack('>BIH', head)
        if not Flag.contains(flag):
            raise PacketError
        else:
            return Flag(flag), chksum, length

    def unpack_body(self) -> Tuple[Any, ...]:
        '''将 body 解包'''
        if self.flag == Flag.PULL or self.flag == Flag.PUSH:
            return (self.body.decode('utf-8'),)  # dest path

        elif self.flag == Flag.SID or self.flag == Flag.ATTACH:
            return unpack('>16s', self.body)  # Worker ID

        elif self.flag == Flag.MONOFILE:
            return unpack('>?', self.body)  # is monofile

        elif self.flag == Flag.DIR_INFO:
            # file_id | perm | path
            #   4B    |  2B  |  ...
            fmt = f'>IH{self.length - 6}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.FILE_INFO:
            # file_id | perm | size | mtime | n_chksum | chksum  | path
            #   4B    |  2B  |  8B  |  8B   |    1B    | n * 16B |  ...
            part1 = unpack('>IHQdB', self.body[:23])
            len_chk = (part1[-1] + 1) * 16
            len_path = self.length - 23 - len_chk
            part2 = unpack(f'>{len_chk}s{len_path}s', self.body[23:])
            return part1[:-1] + part2

        elif self.flag == Flag.FILE_COUNT:
            return unpack('>I', self.body)  # file count

        elif self.flag == Flag.FILE_READY:
            return unpack('>IQ', self.body)  # file id

        elif self.flag == Flag.FILE_CHUNK:
            # file_id |  seq  | chunk
            #    4B   |  4B   |  ...
            fmt = f'>2I{self.length - 8}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.DONE:
            return unpack('>?', self.body)

        elif self.flag == Flag.EXCEPTION:
            return (self.body.decode('utf-8'),)

        else:
            raise ValueError(f'{self.flag} is not a valid Flag')

    def is_valid(self, chksum: int):
        '''是否是有效的包体'''
        return self.chksum == chksum


class PacketError(Exception):
    pass


def send_pkt(conn: Connection, packet: Packet):
    '''发送数据报文'''
    datagram = packet.pack()
    conn.sendall(datagram)


def recv_all(conn: Connection, length: int) -> bytes:
    '''接受完整数据'''
    datagram = bytearray()
    while length > 0:
        _data = conn.recv(length)
        n_recv = len(_data)
        if n_recv > 0:
            length -= n_recv
            datagram += _data
        else:
            raise ConnectionResetError

    return bytes(datagram)


def recv_pkt(conn: Connection) -> Packet:
    '''接收数据报文'''
    # 接收并解析 head 部分
    head = recv_all(conn, LEN_HEAD)
    flag, chksum, len_body = Packet.unpack_head(head)

    # 接收 body 部分
    body = recv_all(conn, len_body)
    if crc32(body) == chksum:
        return Packet(flag, body)
    else:
        raise PacketError


class Counter:
    def __init__(self):
        self.n_sent = 0

    def acc(self, length):
        self.n_sent += length


class ConnectionPool(Thread):
    _max_size = 128

    def __init__(self, size=16):
        super().__init__(daemon=True)
        self.size = min(size, self._max_size)
        self.send_q = Queue(self.size)
        self.recv_q = Queue()
        self.done = Event()
        self.sender = SelectSelector()
        self.connections: Set[Connection] = set()

    def send(self, packet: Packet):
        self.send_q.put(packet)

    def recv(self, timeout=TIMEOUT) -> Packet:
        return self.recv_q.get(timeout)

    def add(self, conn: Connection):
        '''添加一个连接'''
        # 检查数量是否达到上限
        if len(self.connections) >= self._max_size:
            return False
        # 检查是否已添加过
        if conn in self.connections:
            return True

        self.connections.add(conn)
        self.sender.register(conn, EVENT_WRITE, data=Counter())

        t_recv = Thread(target=self.listen_to_recv, args=(conn,), daemon=True)
        t_recv.start()
        return True

    def pop(self, conn: Connection):
        try:
            self.sender.unregister(conn)
        except (KeyError, ValueError):
            pass

        try:
            self.connections.remove(conn)
        except KeyError:
            pass
        finally:
            conn.close()

    def listen_to_send(self):
        while not self.done.is_set():
            # find the conn that sent the least data
            keys = [key for key, _ in self.sender.select(timeout=1)]
            if not keys:
                continue
            else:
                key = min(keys, key=lambda k: k.data.n_sent)

            # get data
            packet: Packet = self.send_q.get()
            conn: Connection = key.fileobj

            # send
            try:
                send_pkt(conn, packet)
                key.data.acc(packet.length)
            except SocketError as e:
                self.pop(conn)
                logging.warning(f'[Send] Conn-{id(conn):x}: {e}.')

    def listen_to_recv(self, conn: Connection):
        conn_name = f'{id(conn):x}'
        while not self.done.is_set():
            try:
                packet = recv_pkt(conn)
                self.recv_q.put(packet)
                logging.debug(f'[Recv] conn-{conn_name}: {packet}')
            except ConnectionResetError:
                self.pop(conn)
                return
            except SocketError as e:
                self.pop(conn)
                logging.warning(f'[Recv] Conn-{conn_name}: {e}.')
            except PacketError:
                self.pop(conn)
                logging.error(f'conn-{conn_name} received an error packet.')
                return

    def stop(self):
        self.done.set()
        self.sender.close()
        for conn in self.connections.copy():
            conn.close()

    def run(self):
        if not self.connections:
            raise ValueError('No connection')

        self.done.clear()
        self.listen_to_send()
        self.stop()

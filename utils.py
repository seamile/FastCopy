import os
import re
import time
import logging

from binascii import crc32
from collections import deque
from enum import IntEnum
from glob import has_magic, iglob
from hashlib import md5
from math import ceil
from paramiko import Channel
from pathlib import Path
from queue import Queue, Empty
from selectors import SelectSelector, EVENT_READ, EVENT_WRITE
from socket import socket, MSG_WAITALL
from socket import timeout as TimeoutError, error as SocketError
from struct import pack, unpack
from threading import Semaphore, Thread
from typing import (Any, Deque, Dict, Generator, Iterable,
                    List, NamedTuple, Set, Tuple, Union)


SERVER_ADDR = ('127.0.0.1', 7523)

CHUNK_SIZE = 1400  # 默认数据块大小 (单位: 字节)
TIMEOUT = 60 * 5  # 全局超时时间
LEN_HEAD = 7

EOF = 0xffffffff


class Flag(IntEnum):
    PUSH = 1        # 推送申请
    PULL = 2        # 拉取申请
    SID = 3         # 建立会话
    ATTACH = 4      # 后续连接
    FILE_COUNT = 5  # 文件总量
    DIR_INFO = 6    # 文件信息
    FILE_INFO = 7   # 文件信息
    FILE_READY = 8  # 文件就绪
    FILE_CHUNK = 9  # 数据传输
    DONE = 10       # 完成
    RESEND = 11     # 错误回传

    @classmethod
    def contains(cls, member: object) -> bool:
        return member in cls.__members__.values()


class Packet(NamedTuple):
    flag: Flag
    body: bytes

    def __str__(self) -> str:
        return f'Flag: {self.flag} Len={self.length}'

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
        elif flag == Flag.FILE_COUNT:
            body = pack('>I', *args)
        elif flag == Flag.DIR_INFO:
            length = len(args[-1])
            body = pack(f'>IH{length}s', *args)
        elif flag == Flag.FILE_INFO:
            length = len(args[-1])
            body = pack(f'>IHQd16s{length}s', *args)
        elif flag == Flag.FILE_READY:
            body = pack('>I', *args)
        elif flag == Flag.FILE_CHUNK:
            length = len(args[-1])
            body = pack(f'>2I{length}s', *args)
        elif flag == Flag.DONE:
            body = pack('>I', EOF)
        elif flag == Flag.RESEND:
            body = pack('>BIH', *args)
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
            return (self.body.decode('utf-8'),)  # dest path

        elif self.flag == Flag.SID or self.flag == Flag.ATTACH:
            return unpack('>16s', self.body)  # Worker ID

        elif self.flag == Flag.FILE_COUNT:
            return unpack('>I', self.body)  # file count

        elif self.flag == Flag.DIR_INFO:
            # file_id | perm | path
            #   4B    |  2B  |  ...
            fmt = f'>IH{self.length - 6}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.FILE_INFO:
            # file_id | perm | size | mtime | chksum | path
            #   4B    |  2B  |  8B  |  8B   |  16B   |  ...
            fmt = f'>IHQd16s{self.length - 38}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.FILE_READY:
            return unpack('>I', self.body)  # file id

        elif self.flag == Flag.FILE_CHUNK:
            # file_id |  seq  | chunk
            #    4B   |  4B   |  ...
            fmt = f'>2I{self.length - 8}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.DONE:
            return unpack('>I', self.body)

        elif self.flag == Flag.RESEND:
            return unpack('>BIH', self.body)

        else:
            raise TypeError

    def is_valid(self, chksum: int):
        '''是否是有效的包体'''
        return self.chksum == chksum


class DirInfo:
    '''文件夹信息'''
    __slots__ = ('id', 'perm', 'relpath', 'abspath', '_values')

    def __init__(self, id: int, perm: int, relpath: bytes) -> None:
        self.id = id
        self.perm = perm
        self.relpath = relpath
        self.abspath = Path()

    def __getitem__(self, index):
        if not hasattr(self, '_values'):
            self._values = [self.id, self.perm, self.relpath]
        return self._values[index]

    def __str__(self) -> str:
        return (f'DirInfo(id={self.id}, perm={self.perm}, '
                f'path={self.s_relpath})')

    @classmethod
    def load(cls, dir_id: int, fullpath: Path, relpath: Path):
        d_info = cls(dir_id, fullpath.stat().st_mode, bytes(relpath))
        d_info.abspath = fullpath
        return d_info

    @property
    def s_relpath(self):
        return self.relpath.decode('utf8')

    def set_parent(self, parent: Path):
        '''通过上级目录设置绝对路径'''
        self.abspath = parent.joinpath(self.relpath.decode('utf8'))
        return self.abspath

    def set_stat(self):
        '''设置目录属性'''
        self.abspath.chmod(self.perm)

    def make(self):
        logging.debug(f'[DirInfo] Make dir: {self.s_relpath}')
        self.abspath.mkdir(parents=True, exist_ok=True)
        self.abspath.chmod(self.perm)


class FileInfo:
    '''文件基础信息'''
    __slots__ = ('id', 'perm', 'size', 'mtime', 'chksum', 'relpath', 'abspath',
                 '_values')

    def __init__(self, id: int, perm: int, size: int,
                 mtime: float, chksum: bytes, relpath: bytes):
        self.id = id
        self.perm = perm
        self.size = size
        self.mtime = mtime
        self.chksum = chksum
        self.relpath = relpath
        self.abspath = Path()

    def __getitem__(self, index):
        if not hasattr(self, '_values'):
            self._values = [self.id,
                            self.perm,
                            self.size,
                            self.mtime,
                            self.chksum,
                            self.relpath]
        return self._values[index]

    def __str__(self) -> str:
        return (f'FileInfo(id={self.id}, perm={self.perm:o}, '
                f'sz={self.size}, path={self.s_relpath})')

    @property
    def n_chunks(self):
        return ceil(self.size / CHUNK_SIZE)

    @classmethod
    def load(cls, file_id: int, fullpath: Path, relpath: Path):
        # 读取文件状态信息
        stat = fullpath.stat()
        f_info = cls(file_id,
                     stat.st_mode,   # 权限, 2 Bytes
                     stat.st_size,   # 大小, 8 Bytes
                     stat.st_mtime,  # 修改时间, 8 Bytes
                     cls.hash(fullpath),  # 文件 MD5 校验码
                     bytes(relpath))
        f_info.abspath = fullpath
        return f_info

    @property
    def s_relpath(self):
        return self.relpath.decode('utf8')

    def set_parent(self, parent: Path):
        '''通过上级目录设置绝对路径'''
        self.abspath = parent.joinpath(self.s_relpath)
        return self.abspath

    def set_stat(self):
        '''设置文件属性'''
        # 设置权限
        self.abspath.chmod(self.perm)
        # 设置时间
        os.utime(self.abspath, (self.mtime, self.mtime))

    def touch(self):
        '''创建空文件'''
        # 确保文件的上级目录存在
        self.abspath.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

        if not self.abspath.exists():
            open(self.abspath, 'w').close()
            self.set_stat()

    def iread(self) -> Generator[Packet, None, None]:
        '''封装文件数据块报文'''
        with open(self.abspath, 'rb') as fp:
            seq = 0
            # 读取单位长度的数据，如果为空则跳出循环
            while chunk := fp.read(CHUNK_SIZE):
                yield Packet.load(Flag.FILE_CHUNK, self.id, seq, chunk)
                seq += 1

    def iwrite(self) -> Generator[None, Tuple[int, bytes], None]:
        '''按数据块迭代写入'''
        # 确保文件的上级目录存在
        self.abspath.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

        # 定义文件所有数据块编号集
        seqs = {i for i in range(self.n_chunks)}

        # 开始迭代写入
        mode = 'rb+' if self.abspath.is_file() else 'wb'
        with open(self.abspath, mode) as fp:
            while seqs:
                seq, chunk = yield
                if seq in seqs:
                    fp.seek(seq * CHUNK_SIZE)
                    fp.write(chunk)
                    seqs.remove(seq)

    @staticmethod
    def hash(filepath: Path) -> bytes:
        hasher = md5()
        with open(filepath, 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.digest()

    def is_vaild(self):
        '''检查文件校验和'''
        return (self.abspath.is_file()
                and self.hash(self.abspath) == self.chksum)


class Reader(Thread):
    '''文件读取器'''

    def __init__(self,
                 src_paths: List[str],
                 input_q: Queue[Packet],
                 output_q: Queue[Packet]):
        '''
        @src_path: 要读取的目标路径
        @input_q: 输入队列
        @output_q: 输出队列
        '''
        super().__init__(daemon=True)

        self.src_paths = src_paths
        self.input_q = input_q
        self.output_q = output_q

        self.tree: Dict[int, Union[DirInfo, FileInfo]] = {}

    @staticmethod
    def abspath(path: str):
        if path.startswith('/'):
            return Path(path)
        elif path.startswith('~'):
            return Path(os.path.expanduser(path))
        elif path.startswith('$'):
            return Path(os.path.expandvars(path))
        else:
            return Path.home().joinpath(path)

    @staticmethod
    def traverse_directory(dir_path: Union[str, Path], include):
        '''遍历文件夹'''
        if isinstance(dir_path, str):
            dir_path = Path(dir_path)

        for item in dir_path.rglob(include):
            if item.is_file() or item.is_dir():
                yield item
            else:
                logging.debug(f'[Reader] The `{item}` is not a regular file or dir.')

    @staticmethod
    def need_exclude(path: Path, patterns: Iterable[str]) -> bool:
        if patterns:
            for pattern in patterns:
                try:
                    if path.match(pattern) or bool(re.search(pattern, path.as_posix())):
                        return True
                except re.error:
                    continue
        return False

    @classmethod
    def checkout_paths(cls, fullpath: Path, include: str, excludes: Iterable[str]) \
            -> Generator[Tuple[Path, Path], None, None]:
        '''检出路径'''
        if fullpath.exists():
            if fullpath.is_file():
                relpath = fullpath.relative_to(fullpath.parent)
                if not cls.need_exclude(relpath, excludes):
                    yield fullpath, relpath
            elif fullpath.is_dir():
                for sub_path in cls.traverse_directory(fullpath, include):
                    relpath = sub_path.relative_to(fullpath)
                    if not cls.need_exclude(relpath, excludes):
                        yield sub_path, relpath
            else:
                logging.error(f'[Reader] The {fullpath} is not a regular file or dir.')
        else:
            logging.error(f'[Reader] No such file or directory: {fullpath}.')

    @classmethod
    def search_files_and_dirs(cls, path: str, include='*', excludes=None) \
            -> Generator[Tuple[Path, Path], None, None]:
        '''查找文件与文件夹'''
        _path = cls.abspath(path)
        if has_magic(path):
            for matched_path in iglob(str(_path)):
                for paths in cls.checkout_paths(Path(matched_path), include, excludes):
                    yield paths
        else:
            for paths in cls.checkout_paths(_path, include, excludes):
                yield paths

    def prepare_all_files(self):
        '''整理要传输的文件列表'''
        _id = 0
        relpaths = set()
        for src_path in self.src_paths:
            items = self.search_files_and_dirs(src_path)
            for fullpath, relpath in items:
                if relpath not in relpaths:
                    relpaths.add(relpath)
                    inf_cls = FileInfo if fullpath.is_file() else DirInfo
                    self.tree[_id] = inf_cls.load(_id, fullpath, relpath)
                    logging.debug(f'[Reader] Found {inf_cls.__name__}: id={_id} path={relpath.as_posix()}')
                    _id += 1
                else:
                    logging.debug(f'[Reader] Name conflict: {relpath.as_posix()}, ignore.')

        return _id  # _id == n_files + n_dirs

    def run(self):
        # 整理所有文件
        total = self.prepare_all_files()
        logging.info(f'[Reader] Num of files and dirs: {total}')

        # 将文件数量写入队列
        packet = Packet.load(Flag.FILE_COUNT, total)
        self.output_q.put(packet)

        # 将目录树信息写入队列
        for _id in range(total):
            _info = self.tree[_id]
            flag = Flag.DIR_INFO if _info.abspath.is_dir() else Flag.FILE_INFO
            packet = Packet.load(flag, *_info)
            self.output_q.put(packet)

        # 将对端准备就绪的文件读入 output_q
        while True:
            try:
                packet = self.input_q.get(timeout=TIMEOUT)
            except Empty:
                logging.error('[Reader] get input queue timeout, reader exit.')
                break
            else:
                if packet.flag == Flag.FILE_READY:
                    f_id, = packet.unpack_body()
                    for chunk_packet in self.tree[f_id].iread():
                        self.output_q.put(chunk_packet)
                elif packet.flag == Flag.DONE:
                    logging.info('[Reader] All files are processed, reader exit.')
                    break
                else:
                    logging.error(f'[Reader] Unknow packet: {packet}')


class Writer(Thread):
    '''文件写入线程'''

    def __init__(self,
                 dst_path: str,
                 input_q: Queue[Packet],
                 output_q: Queue[Packet]):
        '''
        @dst_path: 要读取的目标路径
        @input_q: 输入队列
        @output_q: 输出队列
        '''
        super().__init__(daemon=True)

        self.dst_path = Reader.abspath(dst_path)
        self.input_q = input_q
        self.output_q = output_q

        self.base_dir = Path.home()
        self.size = 0
        self.total = 0
        self.n_recv = 0
        self.use_custom_name = False
        self.concurrency = Semaphore(32)  # 允许同时写入的文件数
        self.files: Dict[int, FileInfo] = {}
        self.iwriters: Dict[int, Generator] = {}
        self.ready_files: Deque[int] = deque()

    def check_dst_path(self):
        '''检查目标路径'''
        if self.total > 1:
            # 多文件传输
            self.base_dir = self.dst_path
            # 确保保存目录存在
            self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        elif self.total == 1:
            # 单文件传输
            if self.dst_path.is_dir():
                self.base_dir = self.dst_path
            else:
                self.base_dir = self.dst_path.parent
                # 确保保存目录存在
                self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                self.use_custom_name = True

    def process_dir_info(self, packet: Packet):
        '''处理目录信息报文'''
        # 创建目录
        d_info = DirInfo(*packet.unpack_body())
        d_info.set_parent(self.base_dir)
        d_info.make()
        logging.info(f'[Writer] Dir ready: {d_info}')
        # 接收数量 +1
        self.n_recv += 1

    def ready_notice(self):
        '''通知对端文件准备就绪'''
        while self.ready_files:
            if self.concurrency.acquire(False):
                f_id = self.ready_files[0]
                # 创建写入迭代器
                self.iwriters[f_id] = self.files[f_id].iwrite()
                self.iwriters[f_id].send(None)

                # 通知对端：文件准备就绪
                logging.info(f'[Writer] File({f_id}) ready')
                ready_pkt = Packet.load(Flag.FILE_READY, f_id)
                self.output_q.put(ready_pkt)
                self.ready_files.popleft()
            else:
                break

    def process_file_info(self, packet: Packet):
        '''处理文件信息报文'''
        # 解包，并创建 FileInfo 对象
        f_info = FileInfo(*packet.unpack_body())
        if self.use_custom_name:
            f_info.abspath = self.dst_path
        else:
            f_info.set_parent(self.base_dir)

        # 检查文件是否需要传输
        if f_info.is_vaild():
            f_info.set_stat()
            self.n_recv += 1
            logging.info(f'[Writer] File skiped: {f_info.s_relpath}.')
        else:
            if f_info.size > 0:
                self.files[f_info.id] = f_info
                self.size += f_info.size
                self.ready_files.append(f_info.id)  # 将 f_id 加入待通知队列
                self.ready_notice()
            else:
                # 传输的是空文件，直接标记为完成
                f_info.touch()
                self.n_recv += 1
                logging.info(f'[Writer] File finished: {f_info.s_relpath}')

    def get_iwriter(self, f_id):
        '''获取写入迭代器'''
        if f_id not in self.iwriters:
            f_info = self.files[f_id]
            # 创建并启动写入迭代器
            self.iwriters[f_id] = f_info.iwrite()
            self.iwriters[f_id].send(None)
        return self.iwriters[f_id]

    def process_file_chunk(self, packet: Packet):
        '''处理文件数据块'''
        f_id, seq, chunk = packet.unpack_body()
        try:
            logging.debug(f'[Writer] Write chunk({seq}) into {self.files[f_id].s_relpath}')
            iwriter = self.get_iwriter(f_id)
            iwriter.send((seq, chunk))
        except StopIteration:
            # 释放并发计数器
            self.concurrency.release()
            # 检查文件 Hash
            if self.files[f_id].is_vaild():
                self.files[f_id].set_stat()  # 修改文件状态
                self.n_recv += 1
                self.iwriters.pop(f_id)
                self.ready_notice()
                logging.info(f'[Writer] File finished: {self.files[f_id].s_relpath}')
            else:
                # TODO: 错误重传机制
                logging.error(f'[Writer] Bad file hash: {self.files[f_id].s_relpath}')

        return len(chunk)

    def print_progess(self, current_size):
        now = time.time()
        interval = 3

        if not hasattr(self, '_last_time'):
            self._last_time = now
            self._last_size = 0

        if now - self._last_time >= interval:
            delta_size = (current_size - self._last_size) / interval
            if delta_size < 1024:
                speed = f'{delta_size:6.1f} B/s'
            elif delta_size < 1048576:
                speed = f'{delta_size // 1024:6.1f} KB/s'
            else:
                speed = f'{delta_size // 1048576:6.1f} MB/s'
            logging.info(f'Progress: {current_size / self.size: 7.2%} {speed}')
            self._last_time = now
            self._last_size = current_size

    def run(self):
        # 等待接收文件总数数据包
        logging.info('[Writer] Waitting for the total number of files')
        packet = self.input_q.get()
        if packet.flag == Flag.FILE_COUNT:
            # 取出文件总数，并确认目标路径
            self.total, = packet.unpack_body()
            logging.info(f'[Writer] Total num of files and dirs: {self.total}')
            self.check_dst_path()
        else:
            logging.error(f'[Writer] The first packet must be `FILE_COUNT` '
                          f'but receive `{packet.flag.name}`')
            return

        # 等待接收文件信息和数据
        recv_size = 0
        while self.n_recv < self.total:
            packet = self.input_q.get()
            if packet.flag == Flag.DIR_INFO:
                self.process_dir_info(packet)

            elif packet.flag == Flag.FILE_INFO:
                self.process_file_info(packet)

            elif packet.flag == Flag.FILE_CHUNK:
                recv_size += self.process_file_chunk(packet)
                self.print_progess(recv_size)

            else:
                logging.error(f'[Writer] Unknow packet flag: {packet.flag}')
        else:
            self.output_q.put(Packet.load(Flag.DONE, EOF))
            logging.info('[Writer] All files finished')


def send_msg(sock: socket, packet: Packet):
    '''发送数据报文'''
    datagram = packet.pack()
    sock.send(datagram)


def recv_all(sock: Union[socket, Channel], length):
    if isinstance(sock, socket):
        return sock.recv(length, MSG_WAITALL)
    else:
        datagram = bytearray()
        while length > 0:
            _data = sock.recv(length)
            length -= len(_data)
            datagram.extend(_data)
        return bytes(datagram)


def recv_msg(sock: socket) -> Packet:
    '''接收数据报文'''
    # 接收并解析 head 部分
    head = recv_all(sock, LEN_HEAD)
    flag, chksum, len_body = Packet.unpack_head(head)

    if not Flag.contains(flag):
        raise ValueError('unknow flag: %d' % flag)

    # 接收 body 部分
    body = recv_all(sock, len_body)

    # 错误重传
    if crc32(body) != chksum:
        pkt = Packet.load(Flag.RESEND, head)
        send_msg(sock, pkt)
        return recv_msg(sock)

    return Packet(flag, body)


class ConnectionPool:
    _max_size = 128
    _timeout = 0.001  # 1ms

    def __init__(self, size: int) -> None:
        self.size = min(size, self._max_size)
        # 发送、接收队列
        self.send_q: Queue[Packet] = Queue(self.size * 5)
        self.recv_q: Queue[Packet] = Queue(self.size * 5)

        # 所有 Socket
        self.socks: Set[socket] = set()

        # 发送、接收多路复用
        self.sender = SelectSelector()
        self.receiver = SelectSelector()

        self.is_working = True
        self.threads: List[Thread] = []

    def send(self, packet: Packet):
        '''发送'''
        self.send_q.put(packet)

    def recv(self, block=True, timeout=None) -> Packet:
        '''接收'''
        return self.recv_q.get(block, timeout)

    def add(self, sock: socket):
        '''添加 sock'''
        if len(self.socks) < self.size:
            self.socks.add(sock)
            self.sender.register(sock, EVENT_WRITE)
            self.receiver.register(sock, EVENT_READ, bytearray())
            return True
        else:
            return False

    def remove(self, sock: socket):
        '''删除 sock'''
        self.sender.unregister(sock)
        self.receiver.unregister(sock)
        self.socks.remove(sock)
        sock.close()

    def handle_sock_err(self, error: SocketError, sock: socket):
        '''处理 socket 错误'''
        # 对端已断开，则从本端删除此连接
        self.remove(sock)
        logging.error(error)

    def _send(self):
        '''从 send_q 获取数据，并封包发送到对端'''
        while self.is_working:
            for key, _ in self.sender.select(1):
                try:
                    packet = self.send_q.get(timeout=1)
                except Empty:
                    break

                try:
                    # 发送数据
                    send_msg(key.fileobj, packet)
                    logging.debug(f'[Send-{key.fd}] {packet.flag.name}: '
                                  f'length={packet.length} '
                                  f'chksum={packet.chksum}')
                except SocketError as e:
                    self.handle_sock_err(e, key.fileobj)
                except Exception as e:
                    logging.error(f'SendErr: {e} | {packet.flag.name}: '
                                  f'length={packet.length} '
                                  f'chksum={packet.chksum}')
                    # 若发送失败，则将 packet 放回队列首位
                    self.send_q.queue.appendleft(packet)

    def _recv(self):
        '''接收并解析数据包, 解析结果存入 recv_q 队列'''
        while self.is_working:
            for key, _ in self.receiver.select(timeout=0.2):
                try:
                    # 从缓存或 sock 取出包头
                    head = key.data or recv_all(key.fileobj, LEN_HEAD)
                except TimeoutError:
                    continue

                # 若数据为空，关闭连接
                if not head:
                    self.remove(key.fileobj)
                    continue

                try:
                    # 解析包头，并接收包体
                    flag, chksum, length = Packet.unpack_head(head)
                    body = recv_all(key.fileobj, length)
                    key.data.clear()
                except TimeoutError:
                    key.data.extend(head)
                    continue

                # 检查报文有效性
                packet = Packet(flag, body)
                if packet.is_valid(chksum):
                    logging.debug(f'[Recv-{key.fd}] {packet.flag.name}: '
                                  f'length={packet.length} '
                                  f'chksum={packet.chksum}')
                    self.recv_q.put(packet)  # 正确的数据包放入队列
                else:
                    logging.error('丢弃错误包，请求重传')
                    r_packet = Packet.load(Flag.RESEND, flag, chksum, length)
                    self.send_q.put(r_packet)

    def start(self):
        '''启动连接池的发送和接收线程'''
        s_thread = Thread(target=self._send, daemon=True)
        s_thread.start()
        self.threads.append(s_thread)

        r_thread = Thread(target=self._recv, daemon=True)
        r_thread.start()
        self.threads.append(r_thread)

    def stop(self):
        '''关闭所有连接'''
        self.is_working = False
        for t in self.threads:
            t.join()

        self.sender.close()
        self.receiver.close()

        for sock in self.socks:
            sock.close()

        logging.info('[ConnPool] closed all connections.')


class Sender(Thread):
    def __init__(self, sid: bytes, src_paths: List[str], pool_size: int):
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.reader = Reader(src_paths,
                             self.conn_pool.recv_q,
                             self.conn_pool.send_q)

    def run(self):
        logging.debug(f'Sender-{self.sid.hex()} is running')
        self.conn_pool.start()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        self.conn_pool.stop()
        logging.debug(f'Sender-{self.sid.hex()} exit')


class Receiver(Thread):
    def __init__(self, sid: bytes, dst_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.writer = Writer(dst_path,
                             self.conn_pool.recv_q,
                             self.conn_pool.send_q)

    def run(self):
        logging.debug(f'Receiver-{self.sid.hex()} is running')
        self.conn_pool.start()  # 启动连接池
        self.writer.start()  # 启动写入线程

        self.writer.join()
        self.conn_pool.stop()
        logging.debug(f'Receiver-{self.sid.hex()} exit')


Transporter = Union[Sender, Receiver]

import os
import re
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
from selectors import SelectSelector, EVENT_WRITE
from socket import socket, error as SocketError
from struct import pack, unpack
from threading import Event, Semaphore, Thread
from typing import (Any, Deque, Dict, Generator, Iterable, List, NamedTuple,
                    Set, Tuple, Union)

from rich.progress import (BarColumn, Progress, TaskID, TextColumn,
                           TransferSpeedColumn)


SERVER_ADDR = ('127.0.0.1', 7523)
CHUNK_SIZE = 1024 * 16  # 默认数据块大小 (单位: 字节)
SSH_MUX = 3
TIMEOUT = 60 * 5  # 全局超时时间
LEN_HEAD = 7

Connection = Union[socket, Channel]

progress = Progress(
    TextColumn("[bold blue]{task.fields[filename]}"),
    BarColumn(bar_width=60),
    TransferSpeedColumn(),
    "•",
    "[progress.percentage]{task.percentage:>3.1f}%"
)


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
            length = len(args[-1])
            body = pack(f'>IHQd16s{length}s', *args)
        elif flag == Flag.FILE_COUNT:
            body = pack('>I', *args)
        elif flag == Flag.FILE_READY:
            body = pack('>I', *args)
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
            # file_id | perm | size | mtime | chksum | path
            #   4B    |  2B  |  8B  |  8B   |  16B   |  ...
            fmt = f'>IHQd16s{self.length - 38}s'
            return unpack(fmt, self.body)

        elif self.flag == Flag.FILE_COUNT:
            return unpack('>I', self.body)  # file count

        elif self.flag == Flag.FILE_READY:
            return unpack('>I', self.body)  # file id

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
                logging.error(f'[Send] conn-{id(conn):x}: {e}, conn exit.')

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
                logging.error(f'[Recv] conn-{conn_name}: {e}, conn exit.')
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
    def name(self) -> str:
        return self.abspath.name

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
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if chunk:
                    yield Packet.load(Flag.FILE_CHUNK, self.id, seq, chunk)
                    seq += 1
                else:
                    break

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
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if chunk:
                    hasher.update(chunk)
                else:
                    break
        return hasher.digest()

    def is_vaild(self):
        '''检查文件校验和'''
        return (self.abspath.is_file()
                and self.hash(self.abspath) == self.chksum)


class Sender(Thread):
    def __init__(self, sid: bytes, src_paths: List[str], pool_size: int,
                 include=None, exclude=None):
        super().__init__(daemon=True)

        self.sid = sid
        self.srcs = src_paths
        self.conn_pool = ConnectionPool(pool_size)
        self.include = include or '*'
        self.exclude = exclude or []
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
                logging.debug(f'[Sender] The `{item}` is not '
                              f'a regular file or dir.')

    @staticmethod
    def need_exclude(path: Path, patterns: Iterable[str]) -> bool:
        for pattern in patterns:
            try:
                if path.match(pattern) or re.search(pattern, path.as_posix()):
                    return True
            except re.error:
                continue
        return False

    @classmethod
    def checkout_paths(cls, fullpath: Path, include: str, exclude: Iterable[str]) \
            -> Generator[Tuple[Path, Path], None, None]:
        '''检出路径'''
        if fullpath.exists():
            if fullpath.is_file():
                relpath = fullpath.relative_to(fullpath.parent)
                if not cls.need_exclude(relpath, exclude):
                    yield fullpath, relpath
            elif fullpath.is_dir():
                for sub_path in cls.traverse_directory(fullpath, include):
                    relpath = sub_path.relative_to(fullpath)
                    if not cls.need_exclude(relpath, exclude):
                        yield sub_path, relpath
            else:
                logging.warning(f'[Sender] The {fullpath} is not '
                                f'a regular file or dir.')
        else:
            logging.warning(f'[Sender] No such file or directory: {fullpath}.')

    @classmethod
    def search_files_and_dirs(cls, path: str, include: str, exclude: list) \
            -> Generator[Tuple[Path, Path], None, None]:
        '''查找文件与文件夹'''
        _path = cls.abspath(path)
        if has_magic(path):
            for matched_path in iglob(str(_path)):
                matched = Path(matched_path)
                for paths in cls.checkout_paths(matched, include, exclude):
                    yield paths
        else:
            for paths in cls.checkout_paths(_path, include, exclude):
                yield paths

    def prepare_all_files(self):
        '''整理要传输的文件列表'''
        _id = 0
        relpaths = set()
        for src_path in self.srcs:
            items = self.search_files_and_dirs(src_path, self.include, self.exclude)
            for fullpath, relpath in items:
                if relpath not in relpaths:
                    # 整理目录树
                    relpaths.add(relpath)
                    if fullpath.is_file():
                        inf_cls, flag = FileInfo, Flag.FILE_INFO
                    else:
                        inf_cls, flag = DirInfo, Flag.DIR_INFO
                    self.tree[_id] = inf_cls.load(_id, fullpath, relpath)

                    # 将 文件/目录 信息发送给接收端
                    info_pkt = Packet.load(flag, *self.tree[_id])
                    self.conn_pool.send(info_pkt)
                    logging.debug(f'[Sender] Found {inf_cls.__name__}: '
                                  f'id={_id} path={relpath.as_posix()}')

                    _id += 1
                else:
                    logging.debug(f'[Sender] Name conflict: '
                                  f'{relpath.as_posix()}, ignore.')

        if _id == 0:
            packet = Packet.load(Flag.EXCEPTION, 'No such file or directory')
        else:
            packet = Packet.load(Flag.FILE_COUNT, _id)
        self.conn_pool.send(packet)
        logging.info(f'[Sender] Num of files and dirs: {_id}')

    def run(self):
        logging.debug(f'[Sender] Sender-{self.sid.hex()[:8]} is running')
        self.conn_pool.start()  # 启动网络连接池

        # 通知对端是否是单文件
        is_monofile = (len(self.srcs) == 1
                       and not has_magic(self.srcs[0])
                       and self.abspath(self.srcs[0]).is_file())
        mono_pkt = Packet.load(Flag.MONOFILE, is_monofile)
        self.conn_pool.send(mono_pkt)

        # 整理所有文件
        Thread(target=self.prepare_all_files, daemon=True).start()

        # 将对端准备就绪的文件读入 output_q
        while True:
            try:
                packet = self.conn_pool.recv()
            except Empty:
                logging.error('[Sender] get input queue timeout, exit.')
                exit_pkt = Packet.load(Flag.EXCEPTION, 'waitting timeout.')
                self.conn_pool.send(exit_pkt)
                break

            if packet.flag == Flag.FILE_READY:
                f_id, = packet.unpack_body()
                f_info = self.tree[f_id]

                # 添加进度条任务
                task_id = progress.add_task(
                    f'upload-{f_info.name}',
                    filename=f_info.name,
                    total=f_info.size,
                    start=True
                )

                # 发送文件数据块
                for chunk_packet in f_info.iread():
                    self.conn_pool.send(chunk_packet)
                    progress.update(task_id, advance=chunk_packet.length)

            elif packet.flag == Flag.DONE:
                logging.info('[Sender] All files are processed, exit.')
                break

            else:
                logging.error(f'[Sender] Unknow packet: {packet}')

        self.conn_pool.stop()
        logging.debug(f'Sender-{self.sid.hex()[:8]} exit')


class Receiver(Thread):
    def __init__(self, sid: bytes, dst_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.dst_path = Sender.abspath(dst_path)
        self.conn_pool = ConnectionPool(pool_size)

        self.base_dir = Path.home()
        self.size = 0
        self.is_monofile = True
        self.n_recv = 0
        self.total = 0xffffffff
        self.use_custom_name = False
        self.concurrency = Semaphore(8)  # 允许同时写入的文件数
        self.files: Dict[int, FileInfo] = {}
        self.iwriters: Dict[int, Generator] = {}
        self.ready_files: Deque[int] = deque()
        self.progress_tasks: Dict[int, TaskID] = {}

    def check_dst_path(self):
        '''检查目标路径'''
        if self.is_monofile:
            # 单文件传输
            if self.dst_path.is_dir():
                self.base_dir = self.dst_path
            else:
                self.base_dir = self.dst_path.parent
                # 确保保存目录存在
                self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                self.use_custom_name = True
        else:
            # 多文件传输
            self.base_dir = self.dst_path
            # 确保保存目录存在
            self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

    def process_dir_info(self, packet: Packet):
        '''处理目录信息报文'''
        # 创建目录
        d_info = DirInfo(*packet.unpack_body())
        d_info.set_parent(self.base_dir)
        d_info.make()
        logging.info(f'[Receiver] Dir ready: {d_info}')
        # 接收数量 +1
        self.n_recv += 1

    def ready_notice(self):
        '''通知对端文件准备就绪'''
        while self.ready_files:
            if self.concurrency.acquire(False):
                f_id = self.ready_files[0]
                f_info = self.files[f_id]
                # 创建写入迭代器
                self.iwriters[f_id] = f_info.iwrite()
                self.iwriters[f_id].send(None)

                # 通知对端：文件准备就绪
                logging.debug(f'[Receiver] File({f_id}) ready')
                ready_pkt = Packet.load(Flag.FILE_READY, f_id)
                self.conn_pool.send(ready_pkt)
                self.ready_files.popleft()

                # 添加进度条任务
                task_id = progress.add_task(
                    f'download-{f_info.name}',
                    filename=f_info.name,
                    total=f_info.size,
                    start=True
                )
                self.progress_tasks[f_id] = task_id
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
            logging.info(f'[Receiver] File finished: {f_info.s_relpath}.')
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
                logging.info(f'[Receiver] File finished: {f_info.s_relpath}')

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
            logging.debug(f'[Receiver] Write chunk({seq}) '
                          f'into {self.files[f_id].s_relpath}')
            iwriter = self.get_iwriter(f_id)
            progress.update(self.progress_tasks[f_id], advance=len(chunk))
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
                logging.info(f'[Receiver] File finished: '
                             f'{self.files[f_id].s_relpath}')
            else:
                # TODO: 错误重传
                logging.error(f'[Receiver] Bad file hash: '
                              f'{self.files[f_id].s_relpath}')

        return len(chunk)

    def run(self):
        logging.debug(f'Receiver-{self.sid.hex()[:8]} is running')
        self.conn_pool.start()  # 启动连接池

        # 等待接收文件总数数据包
        logging.debug('[Receiver] Waitting for translation mode')
        packet = self.conn_pool.recv()
        if packet.flag == Flag.MONOFILE:
            # 取出文件总数，并确认目标路径
            self.is_monofile, = packet.unpack_body()
            logging.debug(f'[Receiver] Is monofile: {self.is_monofile}.')
            self.check_dst_path()
        else:
            logging.error(f'[Receiver] The first packet must be `MONOFILE` '
                          f'but receive `{packet.flag.name}`')
            exit_pkt = Packet.load(Flag.EXCEPTION, 'packet type error.')
            self.conn_pool.send(exit_pkt)
            return

        # 等待接收文件信息和数据
        while self.n_recv < self.total:
            packet = self.conn_pool.recv()
            if packet.flag == Flag.DIR_INFO:
                self.process_dir_info(packet)

            elif packet.flag == Flag.FILE_INFO:
                self.process_file_info(packet)

            elif packet.flag == Flag.FILE_CHUNK:
                self.process_file_chunk(packet)

            elif packet.flag == Flag.FILE_COUNT:
                self.total, = packet.unpack_body()

            elif packet.flag == Flag.EXCEPTION:
                msg, = packet.unpack_body()
                logging.error(f'fcp: the sender exit due to `{msg}`')
                break

            else:
                logging.error(f'[Receiver] Unknow packet flag: {packet.flag}')

        self.conn_pool.send(Packet.load(Flag.DONE))
        logging.info('[Receiver] All files finished.')

        self.conn_pool.stop()
        logging.debug(f'Receiver-{self.sid.hex()[:8]} exit')


Porter = Union[Sender, Receiver]

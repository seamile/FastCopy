import os
import re
import time
import logging
from glob import has_magic, iglob

from hashlib import md5
from math import ceil
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from typing import Dict, Generator, Iterable, List, Tuple, Union

from const import CHUNK_SIZE, EOF, Flag, TIMEOUT
from network import Packet


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
        return f'FileInfo(id={self.id}, perm={self.perm})'

    @classmethod
    def load(cls, dir_id: int, fullpath: Path, relpath: Path):
        d_info = cls(dir_id, fullpath.stat().st_mode, bytes(relpath))
        d_info.abspath = fullpath
        return d_info

    @property
    def s_relpath(self):
        return self.relpath.decode('utf8')

    def set_abspath(self, parent: Path):
        '''设置绝对路径'''
        self.abspath = parent.joinpath(self.relpath.decode('utf8'))
        return self.abspath

    def set_stat(self):
        '''设置目录属性'''
        self.abspath.chmod(self.perm)

    def make(self):
        self.abspath.mkdir(parents=True, exist_ok=True)
        self.abspath.chmod(self.perm)


class FileInfo:
    '''文件基础信息'''
    __slots__ = ('id', 'perm', 'size', 'mtime', 'chksum', 'relpath', 'abspath', '_values')

    def __init__(self, id: int, perm: int, size: int, mtime: float, chksum: bytes, relpath: bytes):
        self.id = id
        self.perm = perm
        self.size = size
        self.mtime = mtime
        self.chksum = chksum
        self.relpath = relpath
        self.abspath = Path()

    def __getitem__(self, index):
        if not hasattr(self, '_values'):
            self._values = [self.id, self.perm, self.size, self.mtime, self.chksum, self.relpath]
        return self._values[index]

    def __str__(self) -> str:
        return f'FileInfo(id={self.id}, perm={self.perm:o}, sz={self.size}, chk={self.chksum.hex()})'

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

    def set_abspath(self, parent: Path):
        '''设置绝对路径'''
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
        if self.abspath.is_file():
            st = self.abspath.stat()
            if st.st_size > self.size:
                logging.debug(f'[FileInfo] truncate file {self.s_relpath}')
                with open(self.abspath, 'rb+') as fp:
                    fp.truncate(self.size)
            else:
                logging.debug(f'[FileInfo] file {self.abspath} exists')
        else:
            # 文件不存在时，创建空文件
            logging.debug(f'[FileInfo] make file {self.s_relpath}')
            open(self.abspath, 'w').close()

    def iread(self) -> Generator[Packet, None, None]:
        '''封装文件数据块报文'''
        with open(self.abspath, 'rb') as fp:
            seq = 0
            while chunk := fp.read(CHUNK_SIZE):  # 读取单位长度的数据，如果为空则跳出循环
                yield Packet.load(Flag.FILE_CHUNK, self.id, seq, chunk)
                seq += 1

    def iwrite(self) -> Generator[None, Tuple[int, bytes], None]:
        '''按数据块迭代写入'''
        seqs = {i for i in range(self.n_chunks)}
        with open(self.abspath, 'rb+') as fp:
            while seqs:
                seq, chunk = yield
                if seq in seqs:
                    fp.seek(seq * CHUNK_SIZE)
                    fp.write(chunk)
                    seqs.remove(seq)
                else:
                    raise ValueError

    @staticmethod
    def hash(filepath: Path) -> bytes:
        hasher = md5()
        with open(filepath, 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.digest()

    def is_vaild(self):
        '''检查文件校验和'''
        return self.hash(self.abspath) == self.chksum


class Reader(Thread):
    '''文件读取器'''

    def __init__(self, src_paths: List[str], input_q: Queue[Packet], output_q: Queue[Packet]):
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
                logging.error(f'[Reader] The `{fullpath}` is not a regular file or dir.')
        else:
            logging.error(f'[Reader] No such file or directory: `{fullpath}`.')

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
                    logging.debug(f'[Reader] Found {inf_cls.__name__}: id={_id} path={fullpath.as_posix()}')
                    _id += 1
                else:
                    logging.debug(f'[Reader] Name conflict: `{relpath.as_posix()}`, ignore `{fullpath.as_posix()}`')

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

    def __init__(self, dst_path: str, input_q: Queue[Packet], output_q: Queue[Packet]) -> None:
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
        self.files: Dict[int, FileInfo] = {}
        self.iwriters: Dict[int, Generator] = {}
        self.use_custom_name = False

    def check_dst_path(self):
        '''检查目标路径'''
        if self.total > 1:
            # 多文件传输
            self.base_dir = self.dst_path
            self.base_dir.mkdir(parents=True, exist_ok=True)  # 确保保存目录存在
        elif self.total == 1:
            # 单文件传输
            if self.dst_path.is_dir():
                self.base_dir = self.dst_path
            else:
                self.base_dir = self.dst_path.parent
                self.base_dir.mkdir(parents=True, exist_ok=True)  # 确保保存目录存在
                self.use_custom_name = True
        else:
            return

    def process_dir_info(self, packet: Packet):
        '''处理目录信息报文'''
        # 创建目录
        d_info = DirInfo(*packet.unpack_body())
        d_info.set_abspath(self.base_dir)
        d_info.make()
        # 接收数量 +1
        self.n_recv += 1

    def process_file_info(self, packet: Packet):
        '''处理文件信息报文'''
        # 解包，并创建 FileInfo 对象
        f_info = FileInfo(*packet.unpack_body())
        if self.use_custom_name:
            f_info.abspath = self.dst_path
        else:
            f_info.set_abspath(self.base_dir)

        # 检查文件是否需要传输
        if f_info.abspath.is_file() and f_info.is_vaild():
            f_info.set_stat()
            self.n_recv += 1
            logging.info(f'[Writer] File finished: {f_info.s_relpath}')
        else:
            # 创建空文件
            f_info.touch()
            if f_info.size > 0:
                self.files[f_info.id] = f_info
                self.size += f_info.size

                # 创建并启动写入迭代器
                self.iwriters[f_info.id] = f_info.iwrite()
                self.iwriters[f_info.id].send(None)

                # 通知对端：文件准备就绪
                logging.info(f'[Writer] File ready: {f_info}')
                ready_pkt = Packet.load(Flag.FILE_READY, f_info.id)
                self.output_q.put(ready_pkt)
            else:
                f_info.set_stat()
                self.n_recv += 1
                logging.info(f'[Writer] File finished: {f_info.s_relpath}')

    def process_file_chunk(self, packet: Packet):
        '''处理文件数据块'''
        f_id, seq, chunk = packet.unpack_body()
        try:
            logging.debug(f'[Writer] Write file: {f_id=} {seq=}')
            self.iwriters[f_id].send((seq, chunk))
        except StopIteration:
            # 检查文件 Hash
            if not self.files[f_id].is_vaild():
                # TODO: 错误重传机制
                logging.error(f'[Writer] File hash error: {self.files[f_id].s_relpath}')
            else:
                # 修改文件属性
                self.files[f_id].set_stat()
                self.n_recv += 1
                logging.info(f'[Writer] File finished: {self.files[f_id].s_relpath}')
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
            logging.info(f'Progress: {current_size / self.size: 7.2%}  {speed}')
            self._last_time = now
            self._last_size = current_size

    def run(self):
        # 等待接收文件总数数据包
        packet = self.input_q.get()
        if packet.flag == Flag.FILE_COUNT:
            # 取出文件总数，并确认目标路径
            self.total, = packet.unpack_body()
            logging.info(f'[Writer] Num of files and dirs: {self.total}')
            self.check_dst_path()
        else:
            logging.error('[Writer] The first packet must be `FILE_COUNT`')
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

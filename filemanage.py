import os
import logging
from glob import has_magic, iglob

from hashlib import md5
from math import ceil
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Dict, Generator, NamedTuple, Set, Tuple, Union

from const import CHUNK_SIZE, EOF, Flag
from network import Packet


class DirInfo(NamedTuple):
    '''文件夹信息'''
    id: int
    perm: int
    relpath: bytes  # 文件的相对路径

    @classmethod
    def load(cls, dir_id: int, abspath: Path, relpath: Path):
        return cls(dir_id, abspath.stat().st_mode, bytes(relpath))

    def make(self, parent: Path):
        _rel = self.relpath.decode('utf8')
        abspath = parent.joinpath(_rel)
        abspath.mkdir(parents=True, exist_ok=True)
        abspath.chmod(self.perm)


class FileInfo(NamedTuple):
    '''文件基础信息'''
    fid: int
    perm: int
    size: int
    mtime: float
    chksum: bytes
    relpath: bytes  # 文件的相对路径

    @property
    def n_chunks(self):
        return ceil(self.size / CHUNK_SIZE)

    @classmethod
    def load(cls, file_id: int, fullpath: Path, relpath: Path):
        # 读取文件状态信息
        stat = fullpath.stat()
        perm = stat.st_mode    # 权限, 2 Bytes
        size = stat.st_size    # 大小, 8 Bytes
        mtime = stat.st_mtime  # 修改时间, 8 Bytes
        chksum = cls.filehash(fullpath)  # 文件 MD5 校验码
        return cls(file_id, perm, size, mtime, chksum, bytes(relpath))

    def fullpath(self, parent: Path) -> Path:
        relpath = self.relpath.decode('utf-8')
        return parent.joinpath(relpath).absolute()

    def set_stat(self, parent: Path):
        '''设置文件属性'''
        abspath = self.fullpath(parent)
        # 设置权限
        abspath.chmod(self.perm)
        # 设置时间
        os.utime(abspath, (self.mtime, self.mtime))

    @staticmethod
    def filehash(filepath: Path) -> bytes:
        hasher = md5()
        with open(filepath, 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.digest()

    def is_vaild(self, parent: Path):
        '''检查文件校验和'''
        return self.filehash(self.fullpath(parent)) == self.chksum


class Reader(Thread):
    '''文件读取器'''

    def __init__(self, src_paths: Tuple[str], input_q: Queue[Packet], output_q: Queue[Packet]):
        '''
        @src_path: 要读取的目标路径
        @input_q: 输入队列
        @output_q: 输出队列
        '''
        super().__init__(daemon=True)

        self.src_paths = src_paths
        self.input_q = input_q
        self.output_q = output_q

        self.n_files = 0
        self.files: Dict[int, Path] = {}
        self.relpaths: Set[Path] = set()

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
    def traverse_directory(dir_path: Union[str, Path], include='*', exclude=None):
        '''遍历文件夹'''
        if isinstance(dir_path, str):
            dir_path = Path(dir_path)

        for item in dir_path.rglob(include):
            if item.is_file() or item.is_dir():
                if not exclude or not item.match(exclude):
                    yield item
            else:
                logging.debug(f'The `{item}` is not a regular file or dir.')

    @classmethod
    def search_files_and_dirs(cls, path: str, include='*') -> Generator[Tuple[Path, Path], None, None]:
        '''查找文件与文件夹'''
        _path = cls.abspath(path)
        if has_magic(path):
            for _item in iglob(str(_path)):
                item = Path(_item)
                if item.is_file():
                    yield item, item.relative_to(item.parent)
                elif item.is_dir():
                    for sub_item in cls.traverse_directory(item, include):
                        yield sub_item, sub_item.relative_to(item.parent)
                else:
                    logging.debug(f'The `{item}` is not a regular file or dir.')
        else:
            if _path.is_file():
                yield _path, _path.parent
            elif _path.is_dir():
                for item in cls.traverse_directory(_path, include):
                    yield item, item.relative_to(_path)
            else:
                logging.debug(f'The `{path}` is not a regular file or dir.')

    def prepare_all_files(self):
        '''整理要传输的文件列表'''
        items = self.search_files_and_dirs(self.src_path)
        for file_id, (abspath, relpath) in enumerate(items):
            if abspath.is_file():
                if relpath not in self.relpaths:
                    logging.debug(f'find file: {file_id=} file_path={abspath.as_posix()}')
                    self.relpaths.add(relpath)
                    self.files[file_id] = abspath
                else:
                    logging.debug(f'find file: {file_id=} file_path={abspath.as_posix()}')
            else:
                pass  # TODO

        self.n_files = file_id + 1  # TODO: 排除文件夹

    def iread(self, file_id: int) -> Generator[Packet, None, None]:
        '''封装文件数据块报文'''
        with open(self.files[file_id], 'rb') as fp:
            seq = 0
            while chunk := fp.read(CHUNK_SIZE):  # 读取单位长度的数据，如果为空则跳出循环
                logging.debug(f'got chunk {file_id=} {seq=}')
                yield Packet.load(Flag.FILE_CHUNK, file_id, seq, chunk)
                seq += 1

    def run(self):
        # 整理所有文件
        self.prepare_all_files()
        logging.debug(f'num of files: {self.n_files}')

        # 将文件数量写入队列
        packet = Packet.load(Flag.FILE_COUNT, self.n_files)
        self.output_q.put(packet)

        # 将文件信息写入队列
        for f_id in range(self.n_files):
            file_info = FileInfo.load(f_id, self.files[f_id], self.src_dir)
            packet = Packet.load(Flag.FILE_INFO, *file_info)
            self.output_q.put(packet)

        # 将对端准备就绪的文件读入 output_q
        finished = 0
        while True:
            packet = self.input_q.get()
            if packet.flag == Flag.FILE_READY:
                f_id, = packet.unpack_body()
                for chunk_packet in self.iread(f_id):
                    self.output_q.put(chunk_packet)
                finished += 1
            elif packet.flag == Flag.DONE:
                logging.info('client done')
                break
            else:
                logging.error(f'unknow packet: {packet}')

        logging.info('Reader: all files finished')


class Writer(Thread):
    '''文件写入线程'''

    def __init__(self, dst_path: str, input_q: Queue[Packet], output_q: Queue[Packet]) -> None:
        '''
        @dst_path: 要读取的目标路径
        @input_q: 输入队列
        @output_q: 输出队列
        '''
        super().__init__(daemon=True)

        self.dst_path = Path(dst_path).absolute()
        self.input_q = input_q
        self.output_q = output_q

        self.dst_dir = Path('')
        self.n_files = 0
        self.n_finished = 0
        self.files: Dict[int, FileInfo] = {}
        self.iwriters: Dict[int, Generator] = {}
        self.use_custom_dst_path = False

    @staticmethod
    def make_empty_file(file_path: Union[str, Path], file_size: int):
        logging.debug(f'make empty file: {file_path}')
        block_size = 1024 * 1024  # 一次写入的块大小，默认为 1Mb
        count, remain = divmod(file_size, block_size)
        chunk = b'\x00' * block_size
        ending = b'\x00' * remain

        # 创建文件所在目录
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        # 创建空文件
        with open(file_path, 'wb') as dst_fp:
            for _ in range(count):
                dst_fp.write(chunk)
            else:
                dst_fp.write(ending)

    @staticmethod
    def iwrite(file_path: Union[str, Path], n_chunks: int) -> Generator[None, Tuple[int, bytes], None]:
        seqs = {i for i in range(n_chunks)}
        with open(file_path, 'rb+') as fp:
            while seqs:
                seq, chunk = yield
                if seq in seqs:
                    fp.seek(seq * CHUNK_SIZE)
                    fp.write(chunk)
                    seqs.remove(seq)
                else:
                    raise ValueError

    def check_dst_path(self):
        '''检查目标路径'''
        if self.n_files <= 0:
            raise ValueError

        elif self.n_files == 1:
            # 单文件传输
            if self.dst_path.is_dir():
                self.dst_dir = self.dst_path
            else:
                self.dst_dir = self.dst_path.parent
                self.dst_dir.mkdir(parents=True, exist_ok=True)  # 确保保存目录存在
                self.use_custom_dst_path = True

        else:
            # 多文件传输
            self.dst_dir = self.dst_path
            self.dst_dir.mkdir(parents=True, exist_ok=True)  # 确保保存目录存在

    def handle_file_info(self, packet: Packet):
        '''处理文件信息报文'''
        # 解包，并创建 FileInfo 对象
        f_info = FileInfo(*packet.unpack_body())
        self.files[f_info.fid] = f_info

        # 创建空文件
        full_path = f_info.fullpath(self.dst_dir)
        self.make_empty_file(full_path, f_info.size)

        # 创建并启动写入迭代器
        self.iwriters[f_info.fid] = self.iwrite(full_path, f_info.n_chunks)
        self.iwriters[f_info.fid].send(None)

        # 创建文件准备就绪报文
        logging.debug(f'File ready: id={f_info.fid} path={f_info.relpath}')  # type: ignore
        ready_pkt = Packet.load(Flag.FILE_READY, f_info.fid)
        self.output_q.put(ready_pkt)

    def handle_file_chunk(self, packet: Packet):
        '''处理文件数据块'''
        file_id, seq, chunk = packet.unpack_body()
        try:
            logging.debug(f'write file: {file_id=} {seq=}')
            self.iwriters[file_id].send((seq, chunk))
        except StopIteration:
            # 检查文件 Hash
            if not self.files[file_id].is_vaild(self.dst_dir):
                raise ValueError('file hash error')
            else:
                # 修改文件属性
                self.files[file_id].set_stat(self.dst_dir)
                # 文件写入完成
                self.n_finished += 1

    def run(self):
        # 等待接收文件总数
        packet = self.input_q.get()
        if packet.flag != Flag.FILE_COUNT:
            raise ValueError

        # 取出文件总数，并确认目标路径
        # NOTE: unpack_body 的输出是元组，所以等号前须有逗号
        self.n_files, = packet.unpack_body()
        logging.info(f'number of files: {self.n_files}')
        self.check_dst_path()

        # 等待接收文件信息和数据
        while self.n_finished < self.n_files:
            packet = self.input_q.get()
            if packet.flag == Flag.FILE_INFO:
                self.handle_file_info(packet)

            elif packet.flag == Flag.FILE_CHUNK:
                self.handle_file_chunk(packet)

            else:
                raise ValueError(f'Unknow packet flag: {packet.flag}')
        else:
            self.output_q.put(Packet.load(Flag.DONE, EOF))
            logging.info('Writer: all file finished')

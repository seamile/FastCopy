import os
from hashlib import md5
from math import ceil
from pathlib import Path
from queue import Queue
from struct import pack
from threading import Thread
from typing import Dict, Generator, NamedTuple, Tuple

from const import CHUNK_SIZE, EOF, Flag
from network import Packet


class FileInfo(NamedTuple):
    '''文件基础信息'''
    fid: int
    perm: int
    size: int
    ctime: float
    mtime: float
    atime: float
    chksum: bytes
    path: Path

    @property
    def n_chunks(self):
        return ceil(self.size / CHUNK_SIZE)

    @classmethod
    def load(cls, file_id: int, file_path: Path, chksum: bytes = None):
        # 读取文件状态信息
        stat = os.stat(file_path)
        perm = stat.st_mode    # 权限, 2 Bytes
        size = stat.st_size    # 大小, 8 Bytes
        ctime = stat.st_ctime  # 创建时间, 8 Bytes
        mtime = stat.st_mtime  # 修改时间, 8 Bytes
        atime = stat.st_atime  # 访问时间, 8 Bytes
        chksum = chksum or cls.filehash(file_path)  # MD5 校验码
        return cls(file_id, perm, size, ctime, mtime, atime, chksum, file_path)

    @staticmethod
    def filehash(filepath: Path) -> bytes:
        hasher = md5()
        with open(filepath, 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.digest()

    @property
    def is_valid(self):
        return self.chksum == self.filehash(self.path)


class Reader(Thread):
    '''文件读取器'''

    def __init__(self, src_path: str, input_q: Queue[Packet], output_q: Queue[Packet]) -> None:
        '''
        @src_path: 要读取的目标路径
        @input_q: 输入队列
        @output_q: 输出队列
        '''
        super().__init__(daemon=True)

        self.src_path = Path(src_path).absolute()
        if not self.src_path.exists():
            raise FileNotFoundError(src_path)

        self.input_q = input_q
        self.output_q = output_q

        self.src_dir: Path = Path('')
        self.n_files = 0
        self.files: Dict[int, Path] = {}

    def prepare_all_files(self):
        '''整理要传输的文件列表'''
        file_id = 0  # 文件初始 ID 为 0

        if self.src_path.is_dir():
            # 目标路径是文件夹，遍历整个目录，将所有文件整理出来
            self.src_dir = self.src_path
            for dirname, _, filenames in os.walk(self.src_path):
                directory = Path(dirname)
                for filename in filenames:
                    self.files[file_id] = directory.joinpath(filename)  # 记录文件路径
                    file_id += 1  # File ID 自增
            self.n_files = file_id + 1

        elif self.src_path.is_file():
            # 目标路径是单文件，直接加入文件列表
            self.src_dir = self.src_path.parent
            self.files[file_id] = self.src_path
            self.n_files = 1

        else:
            raise TypeError(f'The dest file `{self.src_path}` is not a regular file.')

    def pack_file_count(self) -> Packet:
        '''封装文件总量信息'''
        return Packet(Flag.FILE_COUNT, pack('>H', self.n_files))

    def pack_file_info(self, file_id: int) -> Packet:
        '''
        封装文件信息报文

        @file_id: 文件编号
        @file_path: 文件路径

            | file_id | perm  | size  | ctime | mtime | atime | chksum |path  |
            | :-----: | :---: | :---: | :---: | :---: | :---: | :----: |:---: |
            |   2B    |  2B   |  8B   |  8B   |  8B   |  8B   |  16B   | ...  |
        '''
        # 整理信息
        file_path = self.files[file_id]
        file_info = FileInfo.load(file_id, file_path)
        rel_path = str(file_info.path.relative_to(self.src_dir)).encode('utf8')  # 相对路径
        # 封包
        fmt = f'>2HQ3d16s{len(rel_path)}s'
        body = pack(fmt, *file_info[:-1], rel_path)
        return Packet(Flag.FILE_INFO, body)

    def read_chunk(self, file_id: int, seq: int):
        '''
        读取文件块

        @file_id: 文件编号
        @seq: 区块序号
        '''
        file_path = self.files[file_id]
        position = seq * CHUNK_SIZE
        with open(file_path, 'rb') as fp:
            fp.seek(position)
            return fp.read(CHUNK_SIZE)

    def pack_file_chunks(self, file_id: int) -> Generator[Packet, None, None]:
        '''
        封装文件数据块报文

        @file_id: 文件编号

            | file_id |  seq  | data  |
            | :-----: | :---: | :---: |
            |   2B    |  4B   |  ...  |
        '''
        seq = 0
        flag = Flag.FILE_CHUNK

        with open(self.files[file_id], 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):  # 读取单位长度的数据，如果为空则跳出循环
                length = len(chunk)
                fmt = f'>HI{length}s'
                body = pack(fmt, file_id, seq, chunk)
                yield Packet(flag, body)
                seq += 1
            else:
                body = pack('>HI', file_id, EOF)
                yield Packet(flag, body)

    def run(self):
        # 整理所有文件
        self.prepare_all_files()

        # 将文件数量写入队列
        packet = self.pack_file_count()
        self.output_q.put(packet)

        # 将文件信息写入队列
        for f_id in range(self.n_files):
            packet = self.pack_file_info(f_id)
            self.output_q.put(packet)

        # 将对端准备就绪的文件读入 output_q
        finished = 0
        while finished < self.n_files:
            packet = self.input_q.get()

            for packet in self.pack_file_chunks(f_id):
                self.output_q.put(packet)
            finished += 1


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

        self.dst_dir = ''
        self.n_files = 0
        self.n_finished = 0
        self.files: Dict[int, FileInfo] = {}
        self.use_custom_dst_path = False

    @staticmethod
    def make_empty_file(file_path: str, file_size: int):
        block_size = 1024 * 1024  # 一次写入的块大小，默认为 1Mb
        count, remain = divmod(file_size, block_size)
        chunk = b'\x00' * block_size
        ending = b'\x00' * remain
        with open(file_path, 'wb') as dst_fp:
            for _ in range(count):
                dst_fp.write(chunk)
            else:
                dst_fp.write(ending)

    @staticmethod
    def iwrite(file_info: FileInfo) -> Generator[None, Tuple[int, bytes], None]:
        seqs = {i for i in range(file_info.n_chunks)}
        with open(file_info.path, 'rb+') as fp:
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

    def run(self):
        # 等待接收文件总数
        packet = self.input_q.get()
        if packet.flag != Flag.FILE_COUNT:
            raise ValueError

        # 取出文件总数，并确认目标路径
        # NOTE: unpack_body 的输出是元组，所以等号前须有逗号
        self.n_files, = packet.unpack_body()
        self.check_dst_path()

        # 等待接收文件信息和数据
        while True:
            packet = self.input_q.get()
            if packet.flag == Flag.FILE_INFO:
                result = packet.unpack_body()
                f_info = FileInfo(*result)
                full_path = self.dst_dir.joinpath(f_info.path)

                self.make_empty_file(full_path, f_info.size)
                ready_pkt = Packet.pack_ready()  # TODO
                self.output_q.put(ready_pkt)

            elif packet.flag == Flag.FILE_CHUNK:
                pass
            else:
                pass

import os
from hashlib import md5
from math import ceil
from queue import Queue
from struct import pack
from threading import Thread
from typing import Dict, Generator, NamedTuple, Tuple, Union

from const import CHUNK_SIZE, EOF, Flag
from network import Packet


class FileInfo(NamedTuple):
    '''文件基础信息'''
    file_id: int
    perm: int
    size: int
    ctime: float
    mtime: float
    atime: float
    checksum: bytes
    path: Union[str, bytes]

    @property
    def n_chunks(self):
        return ceil(self.size / CHUNK_SIZE)


def filehash(filepath: str):
    h = md5()
    with open(filepath, 'rb') as fp:
        while chunk := fp.read(CHUNK_SIZE):
            h.update(chunk)
    return h.digest()


class Reader(Thread):
    '''文件读取器'''

    def __init__(self, dst_path: str, input_q: Queue[Packet], output_q: Queue[Packet]):
        '''
        @dst_path: 目标路径
        '''
        super().__init__(daemon=True)

        if os.path.exists(dst_path):
            self.dst_path = dst_path
        else:
            raise FileNotFoundError(dst_path)

        self.base_path = ''
        self.n_files = 0
        self.files: Dict[int, str] = {}
        self.input_q = input_q
        self.output_q = output_q

    def prepare_all_files(self):
        '''整理要传输的文件列表'''
        file_id = 0  # 文件初始 ID 为 0

        if os.path.isdir(self.dst_path):
            # 目标路径是文件夹，遍历整个目录，将所有文件整理出来
            self.base_path = self.dst_path
            for directory, _, filenames in os.walk(self.dst_path):
                for filename in filenames:
                    self.files[file_id] = os.path.join(directory, filename)  # 记录文件路径
                    file_id += 1  # File ID 自增
            self.n_files = file_id + 1

        elif os.path.isfile(self.dst_path):
            # 目标路径是单文件，直接加入文件列表
            self.base_path = os.path.dirname(self.dst_path)
            self.files[file_id] = self.dst_path
            self.n_files = 1

        else:
            raise TypeError(f'The dest file `{self.dst_path}` is not a regular file.')

    def pack_file_count(self) -> Packet:
        '''封装文件总量信息'''
        return Packet.load(Flag.FILE_COUNT, pack('>H', self.n_files))

    def pack_file_info(self, file_id: int) -> Packet:
        '''
        封装文件信息报文

        @file_id: 文件编号
        @file_path: 文件路径

            | file_id | perm  | size  | ctime | mtime | atime | path  |
            | :-----: | :---: | :---: | :---: | :---: | :---: | :---: |
            |   2B    |  2B   |  8B   |  8B   |  8B   |  8B   |  ...  |
        '''
        file_path = self.files[file_id]
        # 读取文件状态信息
        stat = os.stat(file_path)
        perm = stat.st_mode    # 权限, 2 Bytes
        size = stat.st_size    # 大小, 8 Bytes
        ctime = stat.st_ctime  # 创建时间, 8 Bytes
        mtime = stat.st_mtime  # 修改时间, 8 Bytes
        atime = stat.st_atime  # 访问时间, 8 Bytes
        # 计算 MD5 校验码
        chksum = filehash(file_path)
        # 获得文件的相对路径
        path = os.path.relpath(file_path, self.base_path).encode('utf8')  # 相对路径
        # 封包
        fmt = f'>2HQ3d16s{len(path)}s'
        body = pack(fmt, file_id, perm, size, ctime, mtime, atime, chksum, path)
        return Packet.load(Flag.FILE_INFO, body)

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
                yield Packet.load(flag, body)
                seq += 1
            else:
                body = pack('>HI', file_id, EOF)
                yield Packet.load(flag, body)

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
        super().__init__(daemon=True)

        self.dst_path = dst_path
        self.input_q = input_q
        self.output_q = output_q

        self.base_path = ''
        self.n_files = 0
        self.files: Dict[int, FileInfo] = {}

    @staticmethod
    def make_empty_file(file_path: str, file_size: int):
        block_size = 1024 * 1024  # 一次写入的块大小，默认为 1Mb
        count, remain = divmod(file_size, block_size)
        with open('/dev/zero', 'rb') as src_fp, open(file_path, 'wb') as dst_fp:
            for i in range(count):
                dst_fp.write(src_fp.read(block_size))
            if remain > 0:
                dst_fp.write(src_fp.read(remain))

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

    @staticmethod
    def write_chunk(file_path: str, seq: int, chunk: bytes):
        with open(file_path, 'rb+') as fp:
            position = seq * CHUNK_SIZE
            fp.seek(position)
            fp.write(chunk)

    def run(self):
        # 等待接收文件总数
        # packet = self.input_q.get()
        # 等待接收文件信息
        # 等待接收文件数据
        pass

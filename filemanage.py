import os
from collections import namedtuple
from math import ceil
from queue import Queue
from struct import pack, unpack
from threading import Thread
from typing import Dict, Tuple

from const import CHUNK_SIZE, QUEUE_SIZE, EOF, Ptype


FileInfo = namedtuple('FileInfo', ['file_id', 'perm', 'size', 'ctime', 'mtime', 'atime', 'path'])


class Reader(Thread):
    '''文件读取器'''

    def __init__(self, dst_path: str):
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
        self.input_q: Queue[Tuple[Ptype, bytearray]] = Queue()
        self.output_q: Queue[Tuple[Ptype, bytearray]] = Queue(QUEUE_SIZE)

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

    def pack_file_count(self) -> Tuple[Ptype, bytes]:
        '''封装文件总量信息'''
        return Ptype.FILE_COUNT, pack('>H', self.n_files)

    def pack_file_info(self, file_id: int, file_path: str) -> Tuple[Ptype, bytes]:
        '''
        封装文件信息报文

        @file_id: 文件编号
        @file_path: 文件路径

            | file_id | perm  | size  | ctime | mtime | atime | path  |
            | :-----: | :---: | :---: | :---: | :---: | :---: | :---: |
            |   2B    |  2B   |  8B   |  8B   |  8B   |  8B   |  ...  |
        '''
        stat = os.stat(file_path)
        perm = stat.st_mode    # 权限, 2 Bytes
        size = stat.st_size    # 大小, 8 Bytes
        ctime = stat.st_ctime  # 创建时间, 8 Bytes
        mtime = stat.st_mtime  # 修改时间, 8 Bytes
        atime = stat.st_atime  # 访问时间, 8 Bytes
        path = os.path.relpath(file_path, self.base_path).encode('utf8')  # 相对路径
        fmt = f'>2HQ3d{len(path)}s'
        return Ptype.FILE_INFO, pack(fmt, file_id, perm, size, ctime, mtime, atime, path)

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

    def pack_file_chunks(self, file_id: int):
        '''
        封装文件数据块报文

        @file_id: 文件编号

            | file_id |  seq  | data  |
            | :-----: | :---: | :---: |
            |   2B    |  4B   |  ...  |
        '''
        seq = 0
        with open(self.files[file_id], 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):  # 读取单位长度的数据，如果为空则跳出循环
                length = len(chunk)
                fmt = f'>HI{length}s'
                yield Ptype.FILE_CHUNK, pack(fmt, file_id, seq, chunk)
                seq += 1
            else:
                yield Ptype.FILE_CHUNK, pack('>HI', file_id, EOF)

    def run(self):
        # 整理所有文件
        self.prepare_all_files()

        # 将文件数量写入队列
        pkg = self.pack_file_count()
        self.output_q.put(pkg)

        # 将文件信息写入队列
        for f_id in range(self.n_files):
            pkg = self.pack_file_info(f_id, self.files[f_id])
            self.output_q.put(pkg)

        # 将对端准备就绪的文件读入 output_q
        finished = 0
        while finished < self.n_files:
            f_id = self.input_q.get()

            for pkg in self.pack_file_chunks(f_id):
                self.output_q.put(pkg)
            finished += 1


class Writer(Thread):
    '''文件写入线程'''

    def __init__(self, file_path: str, file_size: int) -> None:
        '''
        @file_path: 文件路径
        @file_size: 文件大小
        '''
        super().__init__()
        self.daemon = True

        self.file_path = file_path
        self.file_size = file_size
        self.input_q: Queue[bytes] = Queue(QUEUE_SIZE)
        self.n_chunks = ceil(file_size / CHUNK_SIZE)

    @ staticmethod
    def make_empty_file(file_path: str, file_size: int):
        block_size = 1024 * 1024  # 一次写入的块大小，默认为 1Mb
        count, remain = divmod(file_size, block_size)
        with open('/dev/zero', 'rb') as src_fp, open(file_path, 'wb') as dst_fp:
            for i in range(count):
                dst_fp.write(src_fp.read(block_size))
            if remain > 0:
                dst_fp.write(src_fp.read(remain))

    def make_all_files(self, remove_exist=False):
        pass

    def write_chunk(self, seq: int, chunk: bytes):
        with open(self.file_path, 'rb+') as fp:
            position = seq * CHUNK_SIZE
            fp.seek(position)
            fp.write(chunk)

    @ staticmethod
    def unpack_file_info(package: bytes):
        '''解包文件信息'''
        path_length = len(package) - 36  # 在 Package 中 path 前面的字段共占 36 字节
        fields = unpack(f'>2HQ3d{path_length}s', package)
        return FileInfo(*fields)

    def run(self):
        # 创建空文件
        if not os.path.isfile(self.file_path):
            self.make_empty_file(self.file_path, self.file_size)

        while self.n_chunks > 0:
            seq, chunk = self.input_q.get()
            self.write_chunk(seq, chunk)

import os
from collections import namedtuple
from math import ceil
from queue import Queue
from struct import pack, unpack
from threading import Thread

from const import CHUNK_SIZE, PKG_END


FileInfo = namedtuple(
    'FileInfo',
    field_names=['file_id', 'perm', 'size', 'ctime', 'mtime', 'atime', 'path']
)


class Reader(Thread):

    def __init__(self, dst_path: str, qsize: int):
        super().__init__(daemon=True)

        self.dst_path = dst_path
        self.files = {}
        self.file_info_q = Queue(qsize)
        self.file_chunk_q = Queue(qsize)

    def all_files(self):
        file_id = 0
        for directory, _, filenames in os.walk(self.dst_path):
            for filename in filenames:
                filepath = os.path.join(directory, filename)
                self.files[file_id] = filepath
                file_id += 1

    @staticmethod
    def pack_file_info(file_id, filepath, basepath):
        '''
        封装文件信息报文

            | file_id | perm  | size  | ctime | mtime | atime | path  |
            | :-----: | :---: | :---: | :---: | :---: | :---: | :---: |
            |   2B    |  2B   |  8B   |  8B   |  8B   |  8B   |  ...  |
        '''
        stat = os.stat(filepath)
        perm = stat.st_mode  # 权限, 2 Bytes
        size = stat.st_size  # 大小, 8 Bytes
        ctime = stat.st_ctime  # 创建时间, 8 Bytes
        mtime = stat.st_mtime  # 修改时间, 8 Bytes
        atime = stat.st_atime  # 访问时间, 8 Bytes
        path = os.path.relpath(filepath, basepath).encode('utf8')  # 相对路径
        fmt = f'>2HQ3d{len(path)}s'
        return pack(fmt, file_id, perm, size, ctime, mtime, atime, path)

    def set_files(self):
        if os.path.isfile(self.dst_path):
            relative_path = os.path.basename(self.dst_path)
            self.files = {1: [relative_path, os.path.getsize(self.dst_path)]}
        elif os.path.isdir(self.dst_path):
            for base_dir, _, filenames in os.walk(self.dst_path):
                for filename in filenames:
                    path = os.path.join(base_dir, filename)
                    size = os.path.getsize(path)
                    print(size)
        else:
            raise FileNotFoundError

    def read_chunk(self, file_id: int, seq: int):
        filepath = self.files[file_id]
        position = seq * CHUNK_SIZE
        with open(filepath, 'rb') as fp:
            fp.seek(position)
            return fp.read(CHUNK_SIZE)

    def pack_file_chunk(self, file_id: int, seq: int, chunk: bytes):
        '''
        封装文件数据块报文

            | file_id |  seq  | data  |
            | :-----: | :---: | :---: |
            |   2B    |  4B   |  ...  |
        '''
        length = len(chunk)
        fmt = f'>HI{length}s'
        return pack(fmt, file_id, seq, chunk)

    def run(self):
        if os.path.isdir(self.dst_path):
            raise FileNotFoundError(f'File `{self.dst_path}` not found')
        else:
            seq = 0
            with open(self.dst_path, 'rb') as fp:
                while chunk := fp.read(CHUNK_SIZE):           # 读取单位长度的数据，如果为空则跳出循环
                    pkg = self.pack_file_chunk(123, seq, chunk)
                    self.file_q.put(pkg)                      # 写入队列
                    seq += 1
                else:
                    self.file_q.put(PKG_END)  # 文件读完，Head 全部写 1
            self.file_q.join()
            self.done.set()


class Writer(Thread):
    '''单文件写入线程'''

    def __init__(self, file_path: str, file_size: int) -> None:
        '''
        @file_path: 文件路径
        @file_size: 文件大小
        '''
        super().__init__()
        self.daemon = True

        self.file_path = file_path
        self.file_size = file_size
        self.chunk_q = Queue()
        self.n_chunks = ceil(file_size / CHUNK_SIZE)

    @staticmethod
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

    @staticmethod
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
            seq, chunk = self.chunk_q.get()
            self.write_chunk(seq, chunk)

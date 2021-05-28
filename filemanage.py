import os
from hashlib import md5
from math import ceil
from pathlib import Path
from queue import Queue
from threading import Thread
from typing import Dict, Generator, NamedTuple, Tuple

from const import CHUNK_SIZE, EOF, Flag
from network import Packet


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
    def load(cls, file_id: int, filepath: Path, base_dir: Path):
        # 读取文件状态信息
        stat = filepath.stat()
        perm = stat.st_mode              # 权限, 2 Bytes
        size = stat.st_size              # 大小, 8 Bytes
        mtime = stat.st_mtime            # 修改时间, 8 Bytes
        chksum = cls.filehash(filepath)  # 文件 MD5 校验码
        # 计算相对路径
        _relpath = filepath.absolute().relative_to(base_dir.absolute())
        relpath = str(_relpath).encode('utf-8')
        return cls(file_id, perm, size, mtime, chksum, relpath)

    def set_stat(self, base_dir: Path):
        '''设置文件属性'''
        path = self.fullpath(base_dir)
        # 设置权限
        path.chmod(self.perm)
        # 设置时间
        os.utime(path, (self.mtime, self.mtime))

    @staticmethod
    def filehash(filepath: Path) -> bytes:
        hasher = md5()
        with open(filepath, 'rb') as fp:
            while chunk := fp.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.digest()

    def fullpath(self, base_dir: Path):
        return base_dir.joinpath(self.relpath.decode('utf-8')).absolute()

    def is_vaild(self, base_dir: Path):
        '''检查文件校验和'''
        return self.filehash(self.fullpath(base_dir)) == self.chksum


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
                    filepath = directory.joinpath(filename)
                    if filepath.is_file() or filepath.is_dir():
                        print(f'find file {file_id}: {filepath}')
                        self.files[file_id] = filepath  # 记录文件路径
                        file_id += 1  # File ID 自增

            # 记录文件总数
            self.n_files = file_id
            print(f'files num: {self.n_files}')

        elif self.src_path.is_file():
            # 目标路径是单文件，直接加入文件列表
            self.src_dir = self.src_path.parent
            self.files[file_id] = self.src_path
            self.n_files = 1

        else:
            raise TypeError(f'The dest file `{self.src_path}` is not a regular file.')

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

    def iread(self, file_id: int) -> Generator[Packet, None, None]:
        '''封装文件数据块报文'''
        with open(self.files[file_id], 'rb') as fp:
            seq = 0
            while chunk := fp.read(CHUNK_SIZE):  # 读取单位长度的数据，如果为空则跳出循环
                print(f'read: FILE_CHUNK  {file_id=}  {seq=}')
                yield Packet.load(Flag.FILE_CHUNK, file_id, seq, chunk)
                seq += 1

    def run(self):
        # 整理所有文件
        self.prepare_all_files()

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
                print('recv done')
                break
            else:
                print(f'unknow packet: {packet}')

            print(f'finished: {finished}')

        print('all files finished')


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
    def make_empty_file(file_path: str, file_size: int):
        print(f'make file: {file_path}')
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
    def iwrite(filepath: Path, n_chunks: int) -> Generator[None, Tuple[int, bytes], None]:
        seqs = {i for i in range(n_chunks)}
        with open(filepath, 'rb+') as fp:
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
        print(f'File ready: id={f_info.fid} path={f_info.relpath.decode("utf8")}')
        ready_pkt = Packet.load(Flag.FILE_READY, f_info.fid)
        self.output_q.put(ready_pkt)

    def handle_file_chunk(self, packet: Packet):
        '''处理文件数据块'''
        file_id, seq, chunk = packet.unpack_body()
        try:
            print(f'write file: {file_id=} {seq=}')
            self.iwriters[file_id].send((seq, chunk))
        except StopIteration:
            # 检查文件 Hash
            if not self.files[file_id].is_vaild(self.dst_dir):
                raise ValueError
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
            print('all file finished')

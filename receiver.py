'''
数据的接收端

TODO:
- [x] 单个文件写入线程
- [ ] 多目录、多文件的支持
- [ ] 断点续传: 记录已完成、未完成的数据块
- [ ] 网络部分的处理
'''

import os
from socket import socket, MSG_WAITALL
from binascii import crc32
from queue import Queue
from threading import Thread
from math import ceil

from packages import PKG_BAD, PKG_END, CHUNK_SIZE


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

    def write_chunk(self, seq: int, chunk: bytes):
        with open(self.file_path, 'rb+') as fp:
            position = seq * CHUNK_SIZE
            fp.seek(position)
            fp.write(chunk)

    def run(self):
        # 创建空文件
        if not os.path.isfile(self.file_path):
            self.make_empty_file(self.file_path, self.file_size)

        while self.n_chunks > 0:
            seq, chunk = self.chunk_q.get()
            self.write_chunk(seq, chunk)


class Receiver:
    def __init__(self, host, port) -> None:
        self.addr = (host, port)
        self.sock = self.connect()

    def connect(self) -> socket:
        sock = socket()
        sock.connect(self.addr)
        return sock

    def whole_recv(self, length: int) -> bytes:
        '''接收指定长度的完整数据'''
        buffer = bytearray(length)
        self.sock.recv_into(buffer, length, MSG_WAITALL)
        return buffer

    def recv_pkg(self, retry: int = 5) -> tuple:
        for i in range(retry):
            seq = self.whole_recv(4)  # 序号 4 字节
            if seq == PKG_END:
                return
            else:
                chksum = self.whole_recv(4)  # 校验和 4 字节
                chksum = int.from_bytes(chksum, 'big')

                length = self.whole_recv(2)  # 长度占 2 字节
                length = int.from_bytes(length, 'big')

                chunk = self.whole_recv(length)

                if crc32(chunk) != chksum:
                    # 数据包错误，则要求服务器重传 (TODO：按照错误包格式封包)
                    self.sock.send(PKG_BAD)
                    print('数据包错误，请求重传')
                    continue
                else:
                    sn = int.from_bytes(seq, 'big')
                    print(f'接收正常: {sn}')
                    return (sn, chunk)
        else:
            raise ValueError('pkg ')

    def write(self, path):
        data = {}
        seq = b''
        end = int.from_bytes(PKG_END, 'big')
        while seq != end:
            seq, chunk = self.recv_pkg()
            data[seq] = chunk

        with open(path, 'wb') as fp:
            for i in range(len(data)):
                fp.write(data[i])

'''
数据的接收端

TODO:
- [x] 单个文件写入线程
- [ ] 多目录、多文件的支持
- [ ] 断点续传: 记录已完成、未完成的数据块
- [ ] 网络部分的处理
'''

# import os
from socket import socket, MSG_WAITALL
from binascii import crc32
# from queue import Queue
# from threading import Thread
# from math import ceil

from const import PKG_BAD, PKG_END


class Receiver:
    def __init__(self, host, port) -> None:
        self.addr = (host, port)
        self.sock = self.connect()

    def connect(self) -> socket:
        sock = socket()
        sock.connect(self.addr)
        return sock

    def recv_all(self, length: int) -> bytearray:
        '''接收指定长度的完整数据'''
        buffer = bytearray(length)
        self.sock.recv_into(buffer, length, MSG_WAITALL)
        return buffer

    def recv_pkg(self, retry: int = 5) -> tuple:
        for i in range(retry):
            seq = self.recv_all(4)  # 序号 4 字节
            if seq == PKG_END:
                return
            else:
                chksum = self.recv_all(4)  # 校验和 4 字节
                chksum = int.from_bytes(chksum, 'big')

                length = self.recv_all(2)  # 长度占 2 字节
                length = int.from_bytes(length, 'big')

                chunk = self.recv_all(length)

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

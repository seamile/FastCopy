import socket
from binascii import crc32
from struct import pack, unpack
from typing import Tuple

from const import Ptype


class NetworkMixin:
    def connect(self, server_addr: Tuple[str, int]):
        '''建立连接'''
        self.sock = socket.create_connection(server_addr, timeout=30)

    def recv_all(self, length: int) -> bytearray:
        '''接收指定长度的完整数据'''
        buffer = bytearray(length)
        self.sock.recv_into(buffer, length, socket.MSG_WAITALL)
        return buffer

    def send_msg(self, ptype: Ptype, payload: bytes):
        '''发送数据报文'''
        chksum = crc32(payload)
        length = len(payload)
        fmt = f'>BIH{length}s'
        return pack(fmt, ptype, chksum, length, payload)

    def recv_msg(self):
        '''接收数据报文'''
        head = self.recv_all(7)
        ptype, chksum, length = unpack('>BIH', head)
        payload = self.recv_all(length)

        # TODO: 报文错误，需重传
        if crc32(payload) != chksum:
            pass

        return ptype, chksum, length, payload

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
        try:
            ptype = Ptype(ptype)
        except (ValueError, TypeError):
            # TODO: 更好的错误处理
            print('ptype error')
            return Ptype.ERROR, 0, 0, b''

        payload = self.recv_all(length)

        # 错误重传
        # TODO: 不完善
        if crc32(payload) != chksum:
            self.send_msg(Ptype.ERROR, head)

        return Ptype(ptype), chksum, length, payload

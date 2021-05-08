import socket
from binascii import crc32
from struct import pack, unpack
from const import PKG_BAD


class Network:
    def connect(self, server_addr: tuple):
        '''建立连接'''
        self.sock = socket.create_connection(server_addr, timeout=30)

    def recv_all(self, length: int) -> bytearray:
        '''接收指定长度的完整数据'''
        buffer = bytearray(length)
        self.sock.recv_into(buffer, length, socket.MSG_WAITALL)
        return buffer

    def send_msg(self, ptype: int, datagram: bytes):
        '''发送数据报文'''
        chksum = crc32(datagram)
        length = len(datagram)
        fmt = f'>BIH{length}s'
        return pack(fmt, ptype, chksum, length, datagram)

    def recv_msg(self):
        '''接收数据报文'''
        head = self.recv_all(7)
        ptype, chksum, length = unpack('>BIH', head)
        datagram = self.recv_all(length)

        # TODO: 报文错误，需重传
        if crc32(datagram) != chksum:
            self.sock.send(PKG_BAD)

        return ptype, chksum, length, datagram

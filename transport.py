import logging
from threading import Thread
from typing import List, Union

from filemanage import Reader, Writer
from network import ConnectionPool


class Sender(Thread):
    def __init__(self, sid: bytes, src_paths: List[str], pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.reader = Reader(src_paths, self.conn_pool.recv_q, self.conn_pool.send_q)

    def handshake(self, channel, remote_path: Union[str, list]):
        '''握手'''
        packet = Packet.load(self.action, remote_path)
        send_msg(channel, packet)
        packet = recv_msg(channel)
        self.session_id, = packet.unpack_body()

    def run(self):
        logging.debug(f'Sender-{self.sid.hex()} is running')
        self.conn_pool.start()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        self.conn_pool.stop()
        logging.debug(f'Sender-{self.sid.hex()} exit')


class Receiver(Thread):
    def __init__(self, sid: bytes, dst_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.writer = Writer(dst_path, self.conn_pool.recv_q, self.conn_pool.send_q)

    def handshake(self, channel, remote_path: Union[str, list]):
        '''握手'''
        packet = Packet.load(self.action, remote_path)
        send_msg(channel, packet)
        packet = recv_msg(channel)
        self.session_id, = packet.unpack_body()

    def run(self):
        logging.debug(f'Receiver-{self.sid.hex()} is running')
        self.conn_pool.start()  # 启动连接池
        self.writer.start()  # 启动写入线程

        self.writer.join()
        self.conn_pool.stop()
        logging.debug(f'Receiver-{self.sid.hex()} exit')


Transporter = Union[Sender, Receiver]

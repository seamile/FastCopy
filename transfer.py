from queue import Queue
from threading import Thread
from typing import Union

from const import QUEUE_SIZE
from filemanage import Reader, Writer
from network import Packet, ConnectionPool


class Sender(Thread):
    def __init__(self, sid: int, src_path: str) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.send_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.recv_q: Queue[Packet] = Queue(QUEUE_SIZE)

        self.reader = Reader(src_path, self.recv_q, self.send_q)
        self.conn_pool = ConnectionPool(self.send_q, self.recv_q)

    def run(self) -> None:
        self.conn_pool.launch()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        self.conn_pool.close_all()


class Receiver(Thread):
    def __init__(self, sid: int, dst_path: str) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.send_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.recv_q: Queue[Packet] = Queue(QUEUE_SIZE)

        self.writer = Writer(dst_path, self.recv_q, self.send_q)
        self.conn_pool = ConnectionPool(self.send_q, self.recv_q)

    def run(self):
        self.conn_pool.launch()  # 启动连接池
        self.writer.start()  # 启动写入线程

        self.writer.join()
        self.conn_pool.close_all()


Transfer = Union[Sender, Receiver]

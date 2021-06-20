import logging
from threading import Thread
from typing import List, Union

from filemanage import Reader, Writer
from network import ConnectionPool


class Sender(Thread):
    def __init__(self, sid: int, src_paths: List[str], pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.reader = Reader(src_paths, self.conn_pool.recv_q, self.conn_pool.send_q)

    def run(self):
        logging.info(f'Sender({self.sid}) is running')
        self.conn_pool.launch()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        self.conn_pool.close_all()
        logging.info(f'Sender({self.sid}) exit')


class Receiver(Thread):
    def __init__(self, sid: int, dst_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.conn_pool = ConnectionPool(pool_size)
        self.writer = Writer(dst_path, self.conn_pool.recv_q, self.conn_pool.send_q)

    def run(self):
        logging.info(f'Receiver({self.sid}) is running')
        self.conn_pool.launch()  # 启动连接池
        self.writer.start()  # 启动写入线程

        self.writer.join()
        self.conn_pool.close_all()
        logging.info(f'Receiver({self.sid}) exit')


Transporter = Union[Sender, Receiver]

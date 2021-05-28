from threading import Thread
from typing import Union

from filemanage import Reader, Writer
from network import ConnectionPool


class Sender(Thread):
    def __init__(self, sid: int, src_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid

        self.conn_pool = ConnectionPool(pool_size)
        self.reader = Reader(src_path, self.conn_pool.recv_q, self.conn_pool.send_q)

    def run(self) -> None:
        self.conn_pool.launch()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        print('Reader exit')
        self.conn_pool.close_all()
        print(f'Sender({self.sid}) exit')


class Receiver(Thread):
    def __init__(self, sid: int, dst_path: str, pool_size: int) -> None:
        super().__init__(daemon=True)

        self.sid = sid

        self.conn_pool = ConnectionPool(pool_size)
        self.writer = Writer(dst_path, self.conn_pool.recv_q, self.conn_pool.send_q)

    def run(self):
        self.conn_pool.launch()  # 启动连接池
        self.writer.start()  # 启动写入线程

        self.writer.join()
        print('Writer exit')
        self.conn_pool.close_all()
        print(f'Receiver({self.sid}) exit')


Transfer = Union[Sender, Receiver]

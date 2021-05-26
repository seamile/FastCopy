from queue import Queue
import socket
from functools import wraps
from struct import unpack
from threading import Lock, Thread
from typing import Dict, Union

from const import Flag, QUEUE_SIZE
from filemanage import Reader, Writer
from network import ConnectionPool, NetworkMixin, Packet


def singleton(cls):
    '''Singleton Pattern Decorator'''
    obj = None

    @wraps(cls)
    def wrapper(*args, **kwargs):
        nonlocal obj
        if isinstance(obj, cls):
            return obj
        else:
            obj = cls(*args, **kwargs)
            return obj
    return wrapper


class Sender(Thread):
    def __init__(self, sid: int, dst_path: str) -> None:
        super().__init__(daemon=True)

        self.sid = sid
        self.send_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.recv_q: Queue[Packet] = Queue(QUEUE_SIZE)

        self.reader = Reader(dst_path, self.recv_q, self.send_q)
        self.conn_pool = ConnectionPool(self.send_q, self.recv_q)

    def run(self) -> None:
        self.conn_pool.launch()  # 启动网络连接池
        self.reader.start()  # 启动读取线程

        self.reader.join()
        for t in self.conn_pool.threads:
            t.join()


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

    def close(self):
        '''关闭所有连接'''
        self.conn_pool.close_all()
        self.writer.start()

        self.writer.join()
        for t in self.conn_pool.threads:
            t.join()


Worker = Union[Sender, Receiver]


class WatchDog(Thread, NetworkMixin):
    def __init__(self, server: 'Server', sock: socket.socket):
        super().__init__(daemon=True)
        self.server = server
        self.sock = sock

    def run(self):
        try:
            # 等待接收新连接的第一个数据报文
            self.sock.settimeout(10)
            cli_flag, *_, payload = self.recv_msg()
            self.sock.settimeout(None)
        except socket.timeout:
            # 超时退出
            self.sock.close()
            return

        if cli_flag == Flag.PULL or cli_flag == Flag.PUSH:
            dst_path = payload.decode('utf8')
            worker = self.server.create_worker(cli_flag, dst_path)
            worker.conn_pool.add(self.sock)
            worker.start()

        elif cli_flag == Flag.ATTACH:
            print('run as a follower')
            sid = unpack('>H', payload)[0]
            worker = self.server.workers[sid]
            worker.conn_pool.add(self.sock)

        else:
            # 对于错误的类型，直接关闭连接
            print('close conn')
            self.sock.close()


@singleton
class Server(Thread):

    def __init__(self, host: str, port: int, max_conn=256) -> None:
        super().__init__(daemon=True)
        self.addr = (host, port)
        self.max_workers = 65535  # 最大 Worker 数量，与 Session ID 相关
        self.max_conn = max_conn  # 一个 Worker 的最大连接数
        self.is_running = True
        self.mutex = Lock()
        self.next_id = 1
        self.workers: Dict[int, Worker] = {}

    def geneate_sid(self) -> int:
        with self.mutex:
            if len(self.workers) >= self.max_workers:
                raise ValueError('已达到最大 Worker 数量，无法创建')

            while self.next_id in self.workers:
                if self.next_id < self.max_workers:
                    self.next_id += 1
                else:
                    self.next_id = 1
            else:
                return self.next_id

    def create_worker(self, cli_flag: Flag, dst_path: str) -> Worker:
        '''创建新 Worker'''
        sid = self.geneate_sid()
        if cli_flag == Flag.PULL:
            self.workers[sid] = Sender(sid, dst_path)
        else:
            self.workers[sid] = Receiver(sid, dst_path)
        return self.workers[sid]

    def close_all_workers(self):
        '''关闭所有 Worker'''
        for worker in self.workers.values():
            worker.close()

    def run(self):
        self.srv_sock = socket.create_server(self.addr, backlog=2048, reuse_port=True)
        while self.is_running:
            # wait for new connection
            cli_sock, cli_addr = self.srv_sock.accept()
            print('new connection: %s:%s' % cli_addr)

            # launch a WatchDog for handshake
            dog = WatchDog(self, cli_sock)
            dog.start()


####################################################################################################
#                                              Client                                              #
####################################################################################################


class Client(Thread):
    def __init__(self, src: str, dst: str, max_conn: int) -> None:
        super().__init__(daemon=True)

        self.src = src
        self.dst = dst
        self.host = ''
        self.port = 0

        self.max_conn = max_conn
        self.send_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.recv_q: Queue[Packet] = Queue(QUEUE_SIZE)
        self.conn_pool = ConnectionPool(self.send_q, self.recv_q)

    def parse_args(self):
        if ':' in self.src:
            netloc, path = self.src.split(':')
        elif ':' in self.dst:
            pass
        else:
            raise ValueError

    def run(self):
        pass


if __name__ == '__main__':
    # Server 启动方式: fcpd -h host -p port -w 256 -c 128
    # Client 启动方式: fcp -c 100 host:/foo/bar ./loc/
    pass

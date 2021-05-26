#!/usr/bin/env python
import sys
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from textwrap import dedent


class Client:
    def __init__(self, host: str, port: int, src: str, dst: str, n_conn: int) -> None:
        self.addr = (host, port)
        self.src = src
        self.dst = dst
        self.n_conn = n_conn

    def run_as_sender(self):
        '''作为发送端端运行'''
        # 创建 Reader
        # 遍历目录
        # 发送文件信息
        # 等待反馈准备就绪的文件
        # 发送文件

    def run_as_receiver(self):
        '''作为接收端端运行'''
        pass

    def run(self):
        fst_sock = self.connect()
        fst_sock.send()


def main(parser: ArgumentParser):
    args = parser.parse_args()
    port = args.port

    if ':' in args.src:
        netloc, src = args.src.split(':')
        user, host = netloc.split('@')
        dst = args.dst
        print(f'PULL: {user}@{host}:{port}:{src} -> {dst}')

    elif ':' in args.dst:
        netloc, dst = args.dst.split(':')
        user, host = netloc.split('@')
        src = args.src
        print(f'PUSH: {src} -> {user}@{host}:{port}:{dst}')

    else:
        parser.print_help()
        sys.exit(1)


####################################################################################################
#                                              Client                                              #
####################################################################################################


# class Client2:
#     def __init__(self, src: str, dst: str, max_conn: int) -> None:
#         super().__init__(daemon=True)

#         self.src = src
#         self.dst = dst
#         self.host = ''
#         self.port = 0

#         self.max_conn = max_conn
#         self.send_q: Queue[Packet] = Queue(QUEUE_SIZE)
#         self.recv_q: Queue[Packet] = Queue(QUEUE_SIZE)
#         self.conn_pool = ConnectionPool(self.send_q, self.recv_q)

#     def parse_args(self):
#         if ':' in self.src:
#             netloc, path = self.src.split(':')
#         elif ':' in self.dst:
#             pass
#         else:
#             raise ValueError

#     def run(self):
#         pass


if __name__ == '__main__':
    parser = ArgumentParser(
        prog='fcp',
        formatter_class=RawDescriptionHelpFormatter,
        description=dedent('''
            PULL : fcp [-p PORT] [USER@]HOST:SRC DST
            PUSH : fcp [-p PORT] SRC [USER@]HOST:DST
        ''')
    )
    parser.add_argument('-p', dest='port', default=7325,
                        help='server port (default: 7325)')

    parser.add_argument('-n', dest='num', default=16,
                        help='maximum number of connections (default: 16)')

    parser.add_argument(dest='src', help='source path')
    parser.add_argument(dest='dst', help='destination path')
    main(parser)

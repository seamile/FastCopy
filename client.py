#!/usr/bin/env python
import sys
from typing import Dict, Tuple
from threading import Thread

from const import Flag, Role
from network import NetworkMixin
from filemanage import Reader, Writer


class Porter(Thread, NetworkMixin):
    def __init__(self, addr: Tuple[str, int]) -> None:
        super().__init__(daemon=True)
        self.addr = addr


class Client:
    def __init__(self, host: str, port: int, role: Role, loc_path: str, rem_path: str) -> None:
        self.addr = (host, port)
        self.role = role
        self.loc_path = loc_path
        self.rem_path = rem_path
        self.workers: Dict[int, Porter] = {}

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


def main(arg1: str, arg2: str):
    if ':' in arg1:
        role = Role.Receiver
        print(f'Run as {role.name}.')
        local_dir = arg2
        host, dst_dir = arg1.split(':')

    elif ':' in arg2:
        role = Role.Sender
        print(f'Run as {role.name}.')

    else:
        print('Usage: fcp SRC DST')
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage:fcp SRC DST')
        sys.exit(1)
    else:
        # fcp ./ root@firefly:/xx/yy
        arg1, arg2 = sys.argv[1:3]
        main(arg1, arg2)

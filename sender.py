import os
from zlib import crc32
from threading import Thread
from queue import Queue

from packages import PKG_END, CHUNK_SIZE


class Reader(Thread):
    def __init__(self, dst_path: str, qsize: int):
        super().__init__(daemon=True)

        self.dst_path = dst_path
        self.file_q = Queue(qsize)

        # e.g.
        # self.files = {
        #   1: ["./foo/bar/example.txt", 271, 123, 123, 123],  # 依次为：路径，大小，创建时间、修改时间、访问时间
        #   2: ["./other/music.mp3", 82379]
        #   3: [...]
        # }
        self.files = {}

    def file_extra_info(self, path):
        pass

    def set_files(self):
        if os.path.isfile(self.dst_path):
            relative_path = os.path.basename(self.dst_path)
            self.files = {1: [relative_path, os.path.getsize(self.dst_path)]}
        elif os.path.isdir(self.dst_path):
            for base_dir, _, filenames in os.walk(self.dst_path):
                for filename in filenames:
                    path = os.path.join(base_dir, filename)
                    size = os.path.getsize(path)

        else:
            raise FileNotFoundError

    def read_chunk(self, file_id: int, seq: int):
        pass

    def run(self):
        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f'File `{self.file_path}` not found')
        else:
            num = 0
            with open(self.file_path, 'rb') as fp:
                while chunk := fp.read(CHUNK_SIZE):           # 读取单位长度的数据，如果为空则跳出循环
                    seq = num.to_bytes(4, 'big')              # 序号 4 字节
                    chksum = crc32(chunk).to_bytes(4, 'big')  # 校验和 4 字节
                    length = len(chunk).to_bytes(2, 'big')    # 长度占 2 字节
                    pkg = seq + chksum + length + chunk       # 组装完整数据包
                    self.file_q.put(pkg)                      # 写入队列
                    num += 1
                else:
                    self.file_q.put(PKG_END)  # 文件读完，Head 全部写 1
            self.file_q.join()
            self.done.set()

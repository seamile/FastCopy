import sys
import socket


class Client:
    def __init__(self, host: str, port: int) -> None:
        self.addr = (host, port)

    def connect(self) -> socket.socket:
        sock = socket.create_connection(self.addr, timeout=30)
        return sock

    def set_role(self):
        '''设置自身角色：接收端、发送端'''
        pass

    def run(self):
        fst_sock = self.connect()
        fst_sock.send()


def base(host, port):
    sock = ...  # connect(host, port)
    packages = {}

    while True:
        seq = sock.recv(4)
        if seq != b'\xff\xff\xff\xff':
            data = sock.recv(512)
            seq = int.from_bytes(seq, 'big')
            packages[seq] = data
        else:
            break

    with open('rr', 'wb') as fp:
        for seq in sorted(packages.keys()):
            data = packages[seq]
            fp.write(data)


def main(src, dst, n_thread):
    pass


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage:ffs SRC DST')
        sys.exit(1)
    else:
        *src, dst = sys.argv[1:]
        main(src, dst)

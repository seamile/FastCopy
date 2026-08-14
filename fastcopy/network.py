import logging
import time
from binascii import crc32
from enum import IntEnum
from queue import Empty, Queue
from socket import socket
from struct import pack, unpack
from threading import Event, Lock, Thread
from typing import Any, NamedTuple

from paramiko import Channel

from fastcopy.config import IDLE_TIMEOUT, LEN_HEAD, TIMEOUT

Connection = socket | Channel


class Flag(IntEnum):
    PUSH = 1  # 推送申请
    PULL = 2  # 拉取申请
    SID = 3  # 建立会话
    ATTACH = 4  # 后续连接
    MONOFILE = 5  # 传输模式
    DIR_INFO = 6  # 目录信息
    FILE_INFO = 7  # 文件信息
    FILE_COUNT = 8  # 文件数量
    FILE_READY = 9  # 文件就绪
    FILE_CHUNK = 10  # 数据传输
    DONE = 11  # 完成
    EXCEPTION = 12  # 异常退出
    FILE_CHUNK_ACK = 13  # 分块确认 (file_id + seq)
    FILE_DONE_ACK = 14  # 文件完成确认 (file_id)
    BLOCK_SIG = 15  # 增量同步签名 (接收端 -> 发送端)
    DELTA_LITERAL = 16  # 增量同步字面量 (发送端 -> 接收端)
    DELTA_COPY = 17  # 增量同步块拷贝 (发送端 -> 接收端)
    DELTA_DONE = 18  # 增量同步结束 (发送端 -> 接收端)

    @classmethod
    def contains(cls, member: object) -> bool:
        return member in cls.__members__.values()


class Packet(NamedTuple):
    flag: Flag
    body: bytes

    def __str__(self) -> str:
        return f'Packet: {self.flag.name} len={self.length} chk={self.chksum:08x}'

    @property
    def length(self) -> int:
        return len(self.body)

    @property
    def chksum(self) -> int:
        return crc32(self.body)

    @staticmethod
    def load(flag: Flag, *args) -> 'Packet':  # noqa: C901
        """将包体封包"""
        match flag:
            case Flag.PULL | Flag.PUSH:
                body = args[0] if isinstance(args[0], bytes) else str(args[0]).encode('utf8')

            case Flag.SID | Flag.ATTACH:
                body = pack('>16s', *args)

            case Flag.MONOFILE:
                body = pack('>?', *args)

            case Flag.DIR_INFO:
                length = len(args[-1])
                body = pack(f'>IH{length}s', *args)

            case Flag.FILE_INFO:
                length = len(args[-1])
                body = pack(f'>IHQd16s{length}s', *args)

            case Flag.FILE_COUNT:
                body = pack('>I', *args)

            case Flag.FILE_READY:
                body = pack('>I', *args)

            case Flag.FILE_CHUNK:
                length = len(args[-1])
                body = pack(f'>2I{length}s', *args)

            case Flag.FILE_CHUNK_ACK:
                body = pack('>2I', *args)  # file_id | seq

            case Flag.FILE_DONE_ACK:
                body = pack('>I', *args)  # file_id

            case Flag.BLOCK_SIG:
                # file_id | block_size | nblocks | [(weak, strong), ...]
                file_id, block_size, sigs = args
                parts = [pack('>III', file_id, block_size, len(sigs))]
                for weak, strong in sigs:
                    parts.append(pack('>I16s', weak, strong))
                body = b''.join(parts)

            case Flag.DELTA_LITERAL:
                # file_id | seq | offset | data
                file_id, seq, offset, data = args
                body = pack(f'>IIQ{len(data)}s', file_id, seq, offset, data)

            case Flag.DELTA_COPY:
                # file_id | seq | offset | block_index | length
                body = pack('>IIQII', *args)

            case Flag.DELTA_DONE:
                # file_id | seq
                body = pack('>II', *args)

            case Flag.DONE:
                body = pack('>?', True)

            case Flag.EXCEPTION:
                body = str(args[0]).encode('utf8')

            case _:
                raise ValueError(f'{flag} is not a valid Flag')
        return Packet(flag, body)

    def pack(self) -> bytes:
        """封包"""
        fmt = f'>BII{self.length}s'
        return pack(fmt, self.flag, self.chksum, self.length, self.body)

    @staticmethod
    def unpack_head(head: bytes) -> tuple[Flag, int, int]:
        """解析 head"""
        flag, chksum, length = unpack('>BII', head)
        if not Flag.contains(flag):
            raise PacketError
        else:
            return Flag(flag), chksum, length

    def unpack_body(self) -> tuple[Any, ...]:  # noqa: C901
        """将 body 解包"""
        match self.flag:
            case Flag.PULL | Flag.PUSH:
                return (self.body.decode('utf-8'),)  # connection info

            case Flag.SID | Flag.ATTACH:
                return unpack('>16s', self.body)  # Worker ID

            case Flag.MONOFILE:
                return unpack('>?', self.body)  # is monofile

            case Flag.DIR_INFO:
                # file_id | perm | path
                fmt = f'>IH{self.length - 6}s'
                return unpack(fmt, self.body)

            case Flag.FILE_INFO:
                # file_id | perm | size | mtime | chksum | path
                fmt = f'>IHQd16s{self.length - 38}s'
                return unpack(fmt, self.body)

            case Flag.FILE_COUNT:
                return unpack('>I', self.body)  # file count

            case Flag.FILE_READY:
                return unpack('>I', self.body)  # file id

            case Flag.FILE_CHUNK:
                # file_id |  seq  | chunk
                fmt = f'>2I{self.length - 8}s'
                return unpack(fmt, self.body)

            case Flag.FILE_CHUNK_ACK:
                return unpack('>2I', self.body)  # file_id | seq

            case Flag.FILE_DONE_ACK:
                return unpack('>I', self.body)  # file id

            case Flag.BLOCK_SIG:
                file_id, block_size, nblocks = unpack('>III', self.body[:12])
                sigs = []
                offset = 12
                for _ in range(nblocks):
                    weak, strong = unpack('>I16s', self.body[offset:offset + 20])
                    sigs.append((weak, strong))
                    offset += 20
                return (file_id, block_size, sigs)

            case Flag.DELTA_LITERAL:
                # file_id | seq | offset | data
                fmt = f'>IIQ{self.length - 16}s'
                return unpack(fmt, self.body)

            case Flag.DELTA_COPY:
                return unpack('>IIQII', self.body)  # file_id | seq | offset | block_index | length

            case Flag.DELTA_DONE:
                return unpack('>II', self.body)  # file_id | seq

            case Flag.DONE:
                return unpack('>?', self.body)

            case Flag.EXCEPTION:
                return (self.body.decode('utf-8'),)

            case _:
                raise ValueError(f'{self.flag} is not a valid Flag')

    def is_valid(self, chksum: int):
        """是否是有效的包体"""
        return self.chksum == chksum


class PacketError(Exception):
    pass


def _send_all(conn: Connection, data: bytes):
    """可靠发送全部字节。

    不使用 sendall：paramiko 的 Channel.sendall 在窗口耗尽时会阻塞，
    甚至在 send 返回 0 时可能死循环。这里显式处理部分发送并检测 0 返回。
    """
    offset = 0
    total = len(data)
    while offset < total:
        n = conn.send(data[offset:])
        if n is None or n <= 0:
            raise ConnectionResetError('connection closed on send')
        offset += n


def send_pkt(conn: Connection, packet: Packet):
    """发送数据报文"""
    datagram = packet.pack()
    _send_all(conn, datagram)


def recv_all(conn: Connection, length: int) -> bytes:
    """接受完整数据"""
    datagram = bytearray()
    while length > 0:
        rcv_data = conn.recv(length)
        n_recv = len(rcv_data)
        if n_recv > 0:
            length -= n_recv
            datagram += rcv_data
        else:
            raise ConnectionResetError

    return bytes(datagram)


def recv_pkt(conn: Connection) -> Packet:
    """接收数据报文"""
    # 接收并解析 head 部分
    head = recv_all(conn, LEN_HEAD)
    flag, chksum, len_body = Packet.unpack_head(head)

    # 接收 body 部分
    body = recv_all(conn, len_body)
    if crc32(body) == chksum:
        return Packet(flag, body)
    else:
        raise PacketError


class ConnectionPool:
    """连接池。

    每个连接拥有独立的发送队列与发送线程，因此某个连接卡死（TCP 窗口满、
    paramiko channel 窗口耗尽、半开连接）只会阻塞它自己的发送线程，不会拖垮全局。
    另有一个空闲看门狗线程：当一个连接在发送方向上停滞超过 idle_timeout 秒
    时强制关闭它；发送端随后会把该连接上未确认的数据交给其它连接重传。
    """
    _max_size = 128

    def __init__(self, size: int = 16, idle_timeout: float = IDLE_TIMEOUT):
        self.size = min(size, self._max_size)
        self.idle_timeout = idle_timeout
        self.recv_q: Queue = Queue()
        self.done = Event()
        self.connections: set[Connection] = set()

        self._lock = Lock()
        self._out_q: dict[Connection, Queue] = {}
        self._n_queued: dict[Connection, int] = {}
        self._last_send: dict[Connection, float] = {}
        self._last_recv: dict[Connection, float] = {}
        self._send_threads: dict[Connection, Thread] = {}
        self._recv_threads: dict[Connection, Thread] = {}
        self._watchdog: Thread | None = None
        self._ready = Event()
        self._pending_sends = 0  # 正在发送中的报文数 (由 _lock 保护)

    def send(self, packet: Packet) -> Connection:
        """把报文投递给负载最轻的连接，并返回被选中的连接。"""
        while not self.done.is_set():
            with self._lock:
                alive = [c for c in self.connections if c in self._out_q]
                if alive:
                    conn = min(alive, key=lambda c: self._n_queued.get(c, 0))
                    self._n_queued[conn] = self._n_queued.get(conn, 0) + packet.length + LEN_HEAD
                    self._out_q[conn].put(packet)
                    return conn
            self._ready.wait(timeout=0.2)
        raise ConnectionError('ConnectionPool is closed')

    def send_or_drop(self, packet: Packet) -> bool:
        """尽力投递一个报文；若当前没有可用连接则直接丢弃。

        用于接收端发送的控制报文（FILE_READY / ACK / DONE 等），它们都是幂等或可
        周期性重发的，因此丢弃是安全的，避免在连接全部断开时阻塞接收线程。
        """
        with self._lock:
            alive = [c for c in self.connections if c in self._out_q]
            if not alive:
                return False
            conn = min(alive, key=lambda c: self._n_queued.get(c, 0))
            self._n_queued[conn] = self._n_queued.get(conn, 0) + packet.length + LEN_HEAD
            self._out_q[conn].put(packet)
        return True

    def send_on(self, conn: Connection, packet: Packet) -> bool:
        """把报文投递给指定连接（若该连接仍存活）。

        用于重发时主动避开疑似损坏（发送成功但数据无法送达）的连接。
        """
        with self._lock:
            if conn not in self.connections or conn not in self._out_q:
                return False
            self._n_queued[conn] = self._n_queued.get(conn, 0) + packet.length + LEN_HEAD
            self._out_q[conn].put(packet)
        return True

    def recv(self, timeout=TIMEOUT) -> Packet:
        return self.recv_q.get(timeout=timeout)

    def drain(self, timeout: float = 3) -> bool:
        """等待所有已入队的报文被实际发送出去。

        用于停止前冲刷控制报文（如 FILE_DONE_ACK / DONE），避免 stop() 关闭连接
        时把尚未发送的报文一起丢掉。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                all_empty = all(q.empty() for q in self._out_q.values())
                pending = self._pending_sends
            if all_empty and pending == 0:
                return True
            self.done.wait(0.05)
        return False

    def add(self, conn: Connection) -> bool:
        """添加一个连接"""
        with self._lock:
            if len(self.connections) >= self._max_size:
                return False
            if conn in self.connections:
                return True

            self.connections.add(conn)
            self._out_q[conn] = Queue()
            self._n_queued[conn] = 0
            now = time.time()
            self._last_send[conn] = now
            self._last_recv[conn] = now
            self._ready.set()

            t_send = Thread(target=self._send_loop, args=(conn,), daemon=True)
            t_recv = Thread(target=self._recv_loop, args=(conn,), daemon=True)
            self._send_threads[conn] = t_send
            self._recv_threads[conn] = t_recv
            t_send.start()
            t_recv.start()
        return True

    def pop(self, conn: Connection):
        """从连接池移除并关闭一个连接"""
        with self._lock:
            self._out_q.pop(conn, None)
            self._n_queued.pop(conn, None)
            self._last_send.pop(conn, None)
            self._last_recv.pop(conn, None)
            self._send_threads.pop(conn, None)
            self._recv_threads.pop(conn, None)
            self.connections.discard(conn)
            if not self.connections:
                self._ready.clear()
        try:
            conn.close()
        except Exception:  # noqa: BLE001
            pass

    def _requeue(self, packet: Packet):
        """把发送失败的报文转交到其它存活连接（若有）。

        这样即使某条连接在发送中途失效，报文（尤其是 MONOFILE / FILE_INFO 等
        一次性控制报文）也不会丢失，从而保证数据安全。
        """
        with self._lock:
            alive = [c for c in self.connections if c in self._out_q]
            if not alive:
                return
            target = min(alive, key=lambda c: self._n_queued.get(c, 0))
            self._n_queued[target] = self._n_queued.get(target, 0) + packet.length + LEN_HEAD
            self._out_q[target].put(packet)

    def _kill(self, conn: Connection):
        """强制关闭一个连接，解阻塞可能卡在 send/recv 上的线程。

        对 paramiko Channel，直接关闭其底层 SSH socket，从而让阻塞在
        write_all / read_all 中的调用立刻失败返回。
        """
        if not isinstance(conn, socket):
            try:
                transport = conn.get_transport()
                sock = getattr(transport, 'sock', None)
                if sock is not None:
                    sock.close()
            except Exception:  # noqa: BLE001
                pass
        self.pop(conn)

    def _send_loop(self, conn: Connection):
        name = f'{id(conn):x}'
        while not self.done.is_set():
            with self._lock:
                out_q = self._out_q.get(conn)
            if out_q is None:
                return
            try:
                packet = out_q.get(timeout=1)
            except Empty:
                continue
            if packet is None:
                return
            with self._lock:
                self._pending_sends += 1
            try:
                send_pkt(conn, packet)
            except Exception as e:  # noqa: BLE001
                if not self.done.is_set():
                    logging.warning(f'[Send] Conn-{name} send failed: {e}')
                self.pop(conn)
                self._requeue(packet)
                return
            finally:
                with self._lock:
                    self._pending_sends -= 1
            with self._lock:
                self._last_send[conn] = time.time()
                self._n_queued[conn] = max(0, self._n_queued.get(conn, 0) - packet.length - LEN_HEAD)

    def _recv_loop(self, conn: Connection):
        name = f'{id(conn):x}'
        while not self.done.is_set():
            try:
                packet = recv_pkt(conn)
            except ConnectionResetError:
                self.pop(conn)
                return
            except (OSError, EOFError) as e:
                if not self.done.is_set():
                    logging.warning(f'[Recv] Conn-{name}: {e}')
                self.pop(conn)
                return
            except PacketError:
                logging.error(f'[Recv] Conn-{name}: received an invalid packet')
                self.pop(conn)
                return

            with self._lock:
                self._last_recv[conn] = time.time()
            self.recv_q.put(packet)
            logging.debug(f'[Recv] Conn-{name}: {packet}')

    def _watchdog_loop(self):
        while not self.done.wait(1):
            now = time.time()
            with self._lock:
                conns = list(self.connections)
            for conn in conns:
                with self._lock:
                    n_queued = self._n_queued.get(conn, 0)
                    last_send = self._last_send.get(conn, now)
                # 仅在“有数据待发送却迟迟发不出去”时判定为发送停滞
                if n_queued > 0 and now - last_send > self.idle_timeout:
                    logging.warning(
                        f'[Watchdog] Conn-{id(conn):x} send stalled for {now - last_send:.0f}s, closing'
                    )
                    self._kill(conn)

    def start(self):
        self.done.clear()
        self._watchdog = Thread(target=self._watchdog_loop, daemon=True)
        self._watchdog.start()

    def stop(self):
        self.done.set()
        with self._lock:
            conns = list(self.connections)
        for conn in conns:
            self._kill(conn)
        with self._lock:
            threads = list(self._send_threads.values()) + list(self._recv_threads.values())
        for t in threads:
            t.join(timeout=2)

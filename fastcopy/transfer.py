import logging
import os
import re
import time
from collections import deque
from collections.abc import Generator, Iterable
from glob import has_magic, iglob
from hashlib import md5
from math import ceil
from pathlib import Path
from pwd import getpwnam
from queue import Empty
from threading import Semaphore, Thread

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskID, TextColumn, TransferSpeedColumn

from fastcopy.config import ACK_TIMEOUT, CHUNK_SIZE, DELTA_MAX_SIZE, MAX_LIT, SIG_BLOCK_SIZE
from fastcopy.network import Connection, ConnectionPool, Flag, Packet

trans_progress = Progress(
    TextColumn('[bold blue]{task.fields[filename]}'),
    SpinnerColumn(finished_text='✓'),
    BarColumn(bar_width=60),
    TransferSpeedColumn(),
    '•',
    '[progress.percentage]{task.percentage:>3.1f}%',
)


def handle_finished_task(progress: Progress):
    tasks = progress.tasks.copy()
    n_tasks = len(tasks)
    if n_tasks > 10:
        for task in tasks:
            if task.finished:
                progress.remove_task(task.id)
                n_tasks -= 1
                if n_tasks <= 10:
                    return


class DirInfo:
    """文件夹信息"""

    __slots__ = ('_values', 'abspath', 'id', 'perm', 'relpath')

    def __init__(self, id: int, perm: int, relpath: bytes) -> None:  # noqa: A002
        self.id = id
        self.perm = perm
        self.relpath = relpath
        self.abspath = Path()

    def __getitem__(self, index):
        if not hasattr(self, '_values'):
            self._values = [self.id, self.perm, self.relpath]
        return self._values[index]

    def __str__(self) -> str:
        return f'DirInfo(id={self.id}, perm={self.perm}, path={self.s_relpath})'

    @classmethod
    def load(cls, dir_id: int, fullpath: Path, relpath: Path):
        d_info = cls(dir_id, fullpath.stat().st_mode, bytes(relpath))
        d_info.abspath = fullpath
        return d_info

    @property
    def s_relpath(self):
        return self.relpath.decode('utf8')

    def set_parent(self, parent: Path):
        """通过上级目录设置绝对路径"""
        self.abspath = parent.joinpath(self.relpath.decode('utf8'))
        return self.abspath

    def set_stat(self):
        """设置目录属性"""
        self.abspath.chmod(self.perm)

    def make(self):
        logging.debug(f'[DirInfo] Make dir: {self.s_relpath}')
        self.abspath.mkdir(parents=True, exist_ok=True)
        self.abspath.chmod(self.perm)


class FileInfo:
    """文件基础信息"""

    __slots__ = (
        '_values',
        'abspath',
        'chksum',
        'id',
        'mtime',
        'perm',
        'relpath',
        'size',
    )

    def __init__(self, id: int, perm: int, size: int, mtime: float, chksum: bytes, relpath: bytes):  # noqa: A002
        self.id = id
        self.perm = perm
        self.size = size
        self.mtime = mtime
        self.chksum = chksum
        self.relpath = relpath
        self.abspath = Path()

    def __getitem__(self, index):
        if not hasattr(self, '_values'):
            self._values = [self.id, self.perm, self.size, self.mtime, self.chksum, self.relpath]
        return self._values[index]

    def __str__(self) -> str:
        return f'FileInfo(id={self.id}, perm={self.perm:o}, sz={self.size}, path={self.s_relpath})'

    @property
    def name(self) -> str:
        return self.abspath.name

    @property
    def n_chunks(self):
        return ceil(self.size / CHUNK_SIZE)

    @classmethod
    def load(cls, file_id: int, fullpath: Path, relpath: Path):
        stat = fullpath.stat()
        f_info = cls(
            file_id,
            stat.st_mode,
            stat.st_size,
            stat.st_mtime,
            cls.hash(fullpath),
            bytes(relpath),
        )
        f_info.abspath = fullpath
        return f_info

    @property
    def s_relpath(self):
        return self.relpath.decode('utf8')

    def set_parent(self, parent: Path):
        """通过上级目录设置绝对路径"""
        self.abspath = parent.joinpath(self.s_relpath)
        return self.abspath

    def set_stat(self):
        """设置文件属性"""
        self.abspath.chmod(self.perm)
        os.utime(self.abspath, (self.mtime, self.mtime))

    def touch(self):
        """创建（或清空为）空文件"""
        self.abspath.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        with open(self.abspath, 'wb'):
            pass
        self.set_stat()

    def iwrite(self) -> Generator[None, tuple[int, bytes], None]:
        """按数据块迭代写入"""
        self.abspath.parent.mkdir(mode=0o755, parents=True, exist_ok=True)

        seqs = set(range(self.n_chunks))
        mode = 'rb+' if self.abspath.is_file() else 'wb'
        with open(self.abspath, mode) as fp:
            while seqs:
                seq, chunk = yield
                if seq in seqs:
                    fp.seek(seq * CHUNK_SIZE)
                    fp.write(chunk)
                    seqs.remove(seq)

    @staticmethod
    def hash(filepath: Path) -> bytes:
        hasher = md5()  # noqa: S324
        with open(filepath, 'rb') as fp:
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if chunk:
                    hasher.update(chunk)
                else:
                    break
        return hasher.digest()

    def is_vaild(self):
        """检查文件校验和"""
        return self.abspath.is_file() and self.hash(self.abspath) == self.chksum


class DeltaReceiver:
    """增量同步接收端重建器：按偏移写临时文件，完成后校验并替换原文件。"""

    __slots__ = ('basis', 'block_size', 'chksum', 'fp', 'mtime', 'perm', 'relpath', 'tmp')

    def __init__(self, f_info: FileInfo, tmp_path: Path, block_size: int):
        self.basis = f_info.abspath
        self.tmp = tmp_path
        self.block_size = block_size
        self.chksum = f_info.chksum
        self.mtime = f_info.mtime
        self.perm = f_info.perm
        self.relpath = f_info.s_relpath
        self.fp = open(tmp_path, 'wb')

    def write_literal(self, offset: int, data: bytes):
        self.fp.seek(offset)
        self.fp.write(data)

    def copy_block(self, offset: int, block_index: int, length: int):
        with open(self.basis, 'rb') as bf:
            bf.seek(block_index * self.block_size)
            data = bf.read(length)
        self.fp.seek(offset)
        self.fp.write(data)

    def finish(self) -> bool:
        self.fp.flush()
        self.fp.close()
        if FileInfo.hash(self.tmp) != self.chksum:
            return False
        os.replace(self.tmp, self.basis)
        os.chmod(self.basis, self.perm)
        os.utime(self.basis, (self.mtime, self.mtime))
        return True


class Sender(Thread):
    def __init__(self, sid: bytes, username: str, src_paths: list[str], pool_size: int, include=None, exclude=None):
        super().__init__(daemon=True)

        self.sid = sid
        self.username = username
        self.srcs = src_paths
        self.conn_pool = ConnectionPool(pool_size)
        self.include = include or '*'
        self.exclude = exclude or []
        self.tree: dict[int, DirInfo | FileInfo] = {}

        # 可靠传输状态
        self.n_files = 0
        self._abort = False
        self._last_count_send = 0.0
        # 每文件在途分块上限。不能太大，否则会同时向所有连接灌入海量分块，
        # 导致 TCP 缓冲被塞满、看门狗误杀连接、整体吞吐暴跌。
        self.window = max(4, min(pool_size // 8, 16))
        self.active: dict[int, FileInfo] = {}
        self.unit_gen: dict[int, Generator[tuple[int, Packet], None, None]] = {}
        self.gen_done: dict[int, bool] = {}
        self.inflight: dict[int, dict[int, tuple[Connection, float, Packet]]] = {}
        self.done_files: set[int] = set()
        self.sigs: dict[int, list] = {}
        self.sig_block_size: dict[int, int] = {}
        self.conn_unacked: dict[Connection, int] = {}  # 每条连接上未确认的分块数

    @staticmethod
    def abspath(username: str, path: str):
        if path.startswith('/'):
            return Path(path)
        elif path.startswith('~/'):
            userhome = getpwnam(username).pw_dir
            return Path(f'{userhome}/{path[2:]}')
        elif path.startswith('$'):
            return Path(os.path.expandvars(path))
        else:
            return Path.home().joinpath(path)

    @staticmethod
    def traverse_directory(dir_path: str | Path, include):
        if isinstance(dir_path, str):
            dir_path = Path(dir_path)

        for item in dir_path.rglob(include):
            if item.is_file() or item.is_dir():
                yield item
            else:
                logging.debug(f'[Sender] The {item} is not a regular file or dir.')

    @staticmethod
    def need_exclude(path: Path, patterns: Iterable[str]) -> bool:
        for pattern in patterns:
            try:
                if path.match(pattern) or re.search(pattern, path.as_posix()):
                    return True
            except re.error:  # noqa: PERF203
                continue
        return False

    @classmethod
    def checkout_paths(
        cls, fullpath: Path, include: str, exclude: Iterable[str]
    ) -> Generator[tuple[Path, Path], None, None]:
        if fullpath.exists():
            if fullpath.is_file():
                relpath = fullpath.relative_to(fullpath.parent)
                if not cls.need_exclude(relpath, exclude):
                    yield fullpath, relpath
            elif fullpath.is_dir():
                for sub_path in cls.traverse_directory(fullpath, include):
                    relpath = sub_path.relative_to(fullpath)
                    if not cls.need_exclude(relpath, exclude):
                        yield sub_path, relpath
            else:
                logging.warning(f'[Sender] The {fullpath} is not a regular file or dir.')
        else:
            logging.warning(f'[Sender] No such file or directory: {fullpath}.')

    @classmethod
    def search_files_and_dirs(
        cls, username: str, path: str, include: str, exclude: list
    ) -> Generator[tuple[Path, Path], None, None]:
        target_path = cls.abspath(username, path)
        if has_magic(path):
            for matched_path in iglob(str(target_path)):
                matched = Path(matched_path)
                for paths in cls.checkout_paths(matched, include, exclude):
                    yield paths
        else:
            for paths in cls.checkout_paths(target_path, include, exclude):
                yield paths

    def prepare_all_files(self):
        f_id = 0
        relpaths = set()
        for src_path in self.srcs:
            items = self.search_files_and_dirs(self.username, src_path, self.include, self.exclude)
            for fullpath, relpath in items:
                if relpath not in relpaths:
                    relpaths.add(relpath)
                    if fullpath.is_file():
                        inf_cls, flag = FileInfo, Flag.FILE_INFO
                    else:
                        inf_cls, flag = DirInfo, Flag.DIR_INFO
                    self.tree[f_id] = inf_cls.load(f_id, fullpath, relpath)

                    info_pkt = Packet.load(flag, *self.tree[f_id])
                    self.conn_pool.send(info_pkt)
                    logging.debug(f'[Sender] Found {inf_cls.__name__}: id={f_id} path={relpath.as_posix()}')

                    f_id += 1
                else:
                    logging.debug(f'[Sender] Name conflict: {relpath.as_posix()}, ignore.')

        self.n_files = f_id
        self._last_count_send = time.time()
        if f_id == 0:
            self._abort = True
            packet = Packet.load(Flag.EXCEPTION, 'No such file or directory')
        else:
            packet = Packet.load(Flag.FILE_COUNT, f_id)
        self.conn_pool.send(packet)
        logging.info(f'[Sender] Num of files and dirs: {f_id}')

    # ---- 可靠传输：统一滑动窗口 + 分块确认 + 重传 ----

    def _chunk_units(self, f_id: int) -> Generator[tuple[int, Packet], None, None]:
        """全量传输：按块生成 FILE_CHUNK 报文。"""
        f_info = self.tree[f_id]
        seq = 0
        with open(f_info.abspath, 'rb') as fp:
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if not chunk:
                    break
                yield (seq, Packet.load(Flag.FILE_CHUNK, f_id, seq, chunk))
                seq += 1

    def _delta_units(self, f_id: int) -> Generator[tuple[int, Packet], None, None]:
        """增量传输：生成 DELTA_* 报文，最后以 DELTA_DONE 结束。"""
        f_info = self.tree[f_id]
        sigs = self.sigs[f_id]
        block_size = self.sig_block_size[f_id]
        seq = 0
        for tok in self._iter_delta_tokens(f_info, sigs, block_size):
            if tok[0] == 'lit':
                _, offset, data = tok
                yield (seq, Packet.load(Flag.DELTA_LITERAL, f_id, seq, offset, data))
            else:
                _, offset, block_index, length = tok
                yield (seq, Packet.load(Flag.DELTA_COPY, f_id, seq, offset, block_index, length))
            seq += 1
        yield (seq, Packet.load(Flag.DELTA_DONE, f_id, seq))

    def _iter_delta_tokens(self, f_info: FileInfo, sigs, block_size):
        """rsync 增量算法：滚动弱校验和 + 强校验和，产出 (lit|copy) 令牌流。"""
        lookup: dict[int, list] = {}
        for idx, (weak, strong) in enumerate(sigs):
            lookup.setdefault(weak, []).append((idx, strong))

        with open(f_info.abspath, 'rb') as fp:
            data = fp.read()
        n = len(data)

        literal = bytearray()
        lit_start = None

        def flush_literal():
            nonlocal literal, lit_start
            out = []
            if lit_start is None:
                return out
            buf = bytes(literal)
            pos = 0
            while pos < len(buf):
                chunk = buf[pos:pos + MAX_LIT]
                out.append(('lit', lit_start + pos, chunk))
                pos += len(chunk)
            literal.clear()
            lit_start = None
            return out

        i = 0
        w = sum(data[:block_size]) & 0xFFFFFFFF if n >= block_size else 0
        while i + block_size <= n:
            matched = None
            for (idx, strong) in lookup.get(w, []):
                if md5(data[i:i + block_size]).digest() == strong:
                    matched = idx
                    break
            if matched is not None:
                for t in flush_literal():
                    yield t
                yield ('copy', i, matched, block_size)
                i += block_size
                if i + block_size <= n:
                    w = sum(data[i:i + block_size]) & 0xFFFFFFFF
                continue
            # 无匹配：把当前字节作为字面量，窗口向前滚动一个字节
            if lit_start is None:
                lit_start = i
            literal.append(data[i])
            if len(literal) >= MAX_LIT:
                for t in flush_literal():
                    yield t
            if i + block_size < n:
                w = (w - data[i] + data[i + block_size]) & 0xFFFFFFFF
            i += 1

        if i < n:
            if lit_start is None:
                lit_start = i
            literal.extend(data[i:])
        for t in flush_literal():
            yield t

    def _activate(self, f_id: int, delta: bool):
        f_info = self.tree[f_id]
        self.active[f_id] = f_info
        self.inflight[f_id] = {}
        self.gen_done[f_id] = False
        self.unit_gen[f_id] = self._delta_units(f_id) if delta else self._chunk_units(f_id)
        logging.debug(f'[Sender] Activate file({f_id}) {"delta" if delta else "full"} {f_info.s_relpath}')
        self._pump(f_id)

    def _activate_file(self, f_id: int):
        if f_id in self.done_files or f_id in self.active:
            return
        if f_id not in self.tree:
            logging.warning(f'[Sender] FILE_READY for unknown file id {f_id}, ignore')
            return
        f_info = self.tree[f_id]
        if not isinstance(f_info, FileInfo) or f_info.size == 0:
            return
        self._activate(f_id, delta=False)

    def _on_block_sig(self, f_id: int, block_size: int, sigs):
        if f_id in self.done_files or f_id in self.active:
            return
        if f_id not in self.tree:
            return
        f_info = self.tree[f_id]
        if not isinstance(f_info, FileInfo) or f_info.size == 0:
            return
        self.sigs[f_id] = sigs
        self.sig_block_size[f_id] = block_size
        self._activate(f_id, delta=True)

    def _pump(self, f_id: int):
        inflight = self.inflight.get(f_id)
        if inflight is None:
            return
        gen = self.unit_gen.get(f_id)
        while len(inflight) < self.window:
            if not self.gen_done.get(f_id, False):
                try:
                    seq, packet = next(gen)
                except StopIteration:
                    self.gen_done[f_id] = True
                else:
                    try:
                        conn = self.conn_pool.send(packet)
                    except ConnectionError:
                        return
                    inflight[seq] = (conn, time.time(), packet)
                    self.conn_unacked[conn] = self.conn_unacked.get(conn, 0) + 1
                    continue
            if not inflight and self.gen_done.get(f_id, False):
                self._on_done_ack(f_id)
            return

    def _on_chunk_ack(self, f_id: int, seq: int):
        inflight = self.inflight.get(f_id)
        if inflight is None:
            return
        entry = inflight.pop(seq, None)
        if entry is not None:
            conn = entry[0]
            self.conn_unacked[conn] = max(0, self.conn_unacked.get(conn, 0) - 1)
        self._pump(f_id)

    def _on_done_ack(self, f_id: int):
        if f_id in self.done_files:
            return
        self.done_files.add(f_id)
        self.active.pop(f_id, None)
        inflight = self.inflight.pop(f_id, {})
        for (conn, _sent_at, _packet) in inflight.values():
            self.conn_unacked[conn] = max(0, self.conn_unacked.get(conn, 0) - 1)
        self.unit_gen.pop(f_id, None)
        self.gen_done.pop(f_id, None)
        self.sigs.pop(f_id, None)
        self.sig_block_size.pop(f_id, None)
        logging.debug(f'[Sender] File({f_id}) done')

    def _retransmit_stale(self):
        now = time.time()
        for f_id, inflight in list(self.inflight.items()):
            for seq, (conn, sent_at, packet) in list(inflight.items()):
                dead = conn not in self.conn_pool.connections
                stale = now - sent_at > ACK_TIMEOUT
                if not (dead or stale):
                    continue
                target = self._pick_retransmit_conn()
                if target is None:
                    continue
                if target is not conn:
                    self.conn_unacked[conn] = max(0, self.conn_unacked.get(conn, 0) - 1)
                if not self.conn_pool.send_on(target, packet):
                    continue
                if target is not conn:
                    self.conn_unacked[target] = self.conn_unacked.get(target, 0) + 1
                inflight[seq] = (target, now, packet)
        # 清理已失效连接的计数
        for c in [c for c in list(self.conn_unacked) if c not in self.conn_pool.connections]:
            del self.conn_unacked[c]

    def _pick_retransmit_conn(self) -> Connection | None:
        """选择在途分块最少的存活连接用于重发，避开疑似损坏（发送成功但无法送达）的连接。"""
        best = None
        best_count = None
        for c in self.conn_pool.connections:
            count = self.conn_unacked.get(c, 0)
            if best is None or count < best_count:
                best = c
                best_count = count
        return best

    def _maybe_resend_count(self):
        if self.n_files > 0 and time.time() - self._last_count_send > 3:
            self.conn_pool.send(Packet.load(Flag.FILE_COUNT, self.n_files))
            self._last_count_send = time.time()

    def _finished(self) -> bool:
        return self.n_files > 0 and len(self.done_files) >= self.n_files

    def run(self):
        logging.debug(f'[Sender] Sender-{self.sid.hex()[:8]} is running')
        self.conn_pool.start()

        is_monofile = (
            len(self.srcs) == 1 and not has_magic(self.srcs[0]) and self.abspath(self.username, self.srcs[0]).is_file()
        )
        self.conn_pool.send(Packet.load(Flag.MONOFILE, is_monofile))

        Thread(target=self.prepare_all_files, daemon=True).start()

        last_scan = 0.0
        while True:
            try:
                packet = self.conn_pool.recv(timeout=0.5)
            except Empty:
                packet = None

            now = time.time()
            if now - last_scan >= 1.0:
                # 周期性重传，不能只在 recv 超时时执行，否则繁忙时会被饿死
                self._retransmit_stale()
                self._maybe_resend_count()
                last_scan = now

            if packet is None:
                if self._abort or self._finished():
                    break
                continue

            try:
                if packet.flag == Flag.FILE_READY:
                    (f_id,) = packet.unpack_body()
                    self._activate_file(f_id)

                elif packet.flag == Flag.BLOCK_SIG:
                    f_id, block_size, sigs = packet.unpack_body()
                    self._on_block_sig(f_id, block_size, sigs)

                elif packet.flag == Flag.FILE_CHUNK_ACK:
                    f_id, seq = packet.unpack_body()
                    self._on_chunk_ack(f_id, seq)

                elif packet.flag == Flag.FILE_DONE_ACK:
                    (f_id,) = packet.unpack_body()
                    self._on_done_ack(f_id)

                elif packet.flag == Flag.DONE:
                    logging.info('[Sender] All files are processed, exit.')
                    break

                elif packet.flag == Flag.EXCEPTION:
                    (msg,) = packet.unpack_body()
                    logging.error(f'fcp: the receiver exit due to {msg}')
                    break

                else:
                    logging.error(f'[Sender] Unknown packet: {packet}')
            except Exception as e:  # noqa: BLE001
                logging.error(f'[Sender] Error processing {packet.flag.name}: {e}')

            if self._abort or self._finished():
                break

        self.conn_pool.stop()
        logging.debug(f'Sender-{self.sid.hex()[:8]} exit')


class Receiver(Thread):
    def __init__(self, sid: bytes, username: str, dst_path: str, pool_size: int):
        super().__init__(daemon=True)

        self.sid = sid
        self.dst_path = Sender.abspath(username, dst_path)
        self.conn_pool = ConnectionPool(pool_size)

        self.base_dir = Path.home()
        self.size = 0
        self.is_monofile = True
        self.n_recv = 0
        self.total = 0xFFFFFFFF
        self.use_custom_name = False
        self.concurrency = Semaphore(8)
        self.files: dict[int, FileInfo] = {}
        self.iwriters: dict[int, Generator] = {}
        self.ready_files: deque[int] = deque()
        self.trans_progress_tasks: dict[int, TaskID] = {}
        self.active: set[int] = set()
        self.done_files: set[int] = set()
        self._last_control_resend = 0.0
        self._done_ack_extra: dict[int, int] = {}
        # 增量同步状态
        self.delta: dict[int, DeltaReceiver] = {}
        self.delta_sigs: dict[int, tuple[int, list]] = {}
        self.delta_requested: dict[int, int] = {}
        self.delta_ready: deque[int] = deque()
        self.delta_received: dict[int, set[int]] = {}
        self.delta_n: dict[int, int] = {}

    def check_dst_path(self):
        if self.is_monofile:
            if self.dst_path.is_dir():
                self.base_dir = self.dst_path
            else:
                self.base_dir = self.dst_path.parent
                self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
                self.use_custom_name = True
        else:
            self.base_dir = self.dst_path
            self.base_dir.mkdir(mode=0o755, parents=True, exist_ok=True)

    def process_dir_info(self, packet: Packet):
        d_info = DirInfo(*packet.unpack_body())
        d_info.set_parent(self.base_dir)
        d_info.make()
        logging.info(f'[Receiver] Dir ready: {d_info}')
        self.n_recv += 1
        self.done_files.add(d_info.id)
        self._done_ack_extra[d_info.id] = 0
        self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, d_info.id))

    def ready_notice(self):
        while self.ready_files:
            if self.concurrency.acquire(False):
                f_id = self.ready_files[0]
                f_info = self.files[f_id]
                self.iwriters[f_id] = f_info.iwrite()  # type: ignore
                self.iwriters[f_id].send(None)

                self.conn_pool.send_or_drop(Packet.load(Flag.FILE_READY, f_id))
                self.ready_files.popleft()
                self.active.add(f_id)

                task_id = trans_progress.add_task(
                    f'download-{f_info.name}', filename=f_info.name, total=f_info.size, start=True
                )
                self.trans_progress_tasks[f_id] = task_id
            else:
                break

    def _should_delta(self, f_info: FileInfo) -> bool:
        """是否对该文件做增量同步。

        仅当目标端已有非空文件（可用作增量基础）时才做增量，否则退回全量传输，
        避免对空基础文件做无意义的“全字面量”增量。
        """
        if not (0 < f_info.size <= DELTA_MAX_SIZE):
            return False
        try:
            return f_info.abspath.is_file() and f_info.abspath.stat().st_size > 0
        except OSError:
            return False

    @staticmethod
    def _compute_signature(path: Path, block_size: int = SIG_BLOCK_SIZE):
        sigs = []
        with open(path, 'rb') as fp:
            while True:
                block = fp.read(block_size)
                if not block:
                    break
                weak = sum(block) & 0xFFFFFFFF
                strong = md5(block).digest()  # noqa: S324
                sigs.append((weak, strong))
        return sigs, block_size

    def _request_delta(self, f_info: FileInfo):
        if not self.concurrency.acquire(False):
            self.delta_ready.append(f_info.id)
            return
        self._start_delta(f_info)

    def _start_delta(self, f_info: FileInfo):
        sigs, block_size = self._compute_signature(f_info.abspath)
        tmp = f_info.abspath.with_name(f_info.abspath.name + '.fcp-delta')
        self.delta_sigs[f_info.id] = (block_size, sigs)
        self.delta[f_info.id] = DeltaReceiver(f_info, tmp, block_size)
        self.delta_received[f_info.id] = set()
        self.delta_requested[f_info.id] = 0
        self.conn_pool.send_or_drop(Packet.load(Flag.BLOCK_SIG, f_info.id, block_size, sigs))
        task_id = trans_progress.add_task(
            f'download-{f_info.name}', filename=f_info.name, total=f_info.size, start=True
        )
        self.trans_progress_tasks[f_info.id] = task_id

    def _notice_delta(self):
        while self.delta_ready:
            if not self.concurrency.acquire(False):
                return
            f_id = self.delta_ready.popleft()
            self._start_delta(self.files[f_id])

    def process_file_info(self, packet: Packet):
        f_info = FileInfo(*packet.unpack_body())
        if self.use_custom_name:
            f_info.abspath = self.dst_path
        else:
            f_info.set_parent(self.base_dir)

        if f_info.is_vaild():
            f_info.set_stat()
            self.n_recv += 1
            self.done_files.add(f_info.id)
            self._done_ack_extra[f_info.id] = 0
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_info.id))
            logging.info(f'[Receiver] File finished: {f_info.s_relpath}.')
        else:
            if f_info.size > 0:
                self.files[f_info.id] = f_info
                self.size += f_info.size
                if self._should_delta(f_info):
                    self._request_delta(f_info)
                else:
                    self.ready_files.append(f_info.id)
                    self.ready_notice()
            else:
                f_info.touch()
                self.n_recv += 1
                self.done_files.add(f_info.id)
                self._done_ack_extra[f_info.id] = 0
                self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_info.id))
                logging.info(f'[Receiver] File finished: {f_info.s_relpath}')

    def get_iwriter(self, f_id):
        if f_id not in self.iwriters:
            f_info = self.files[f_id]
            self.iwriters[f_id] = f_info.iwrite()  # type: ignore
            self.iwriters[f_id].send(None)
        return self.iwriters[f_id]

    def process_file_chunk(self, packet: Packet):
        f_id, seq, chunk = packet.unpack_body()
        if f_id in self.done_files:
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_id))
            return len(chunk)

        try:
            iwriter = self.get_iwriter(f_id)
            try:
                trans_progress.update(self.trans_progress_tasks[f_id], advance=len(chunk))
            except KeyError:
                pass  # 进度任务已被 handle_finished_task 移除
            handle_finished_task(trans_progress)
            iwriter.send((seq, chunk))  # type: ignore
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
        except StopIteration:
            # 补发触发完成的分块 ACK，避免发送端永远等待该分块的确认
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
            self.concurrency.release()
            if self.files[f_id].is_vaild():
                self.files[f_id].set_stat()
                self.n_recv += 1
                self.done_files.add(f_id)
                self._done_ack_extra[f_id] = 0
                self.active.discard(f_id)
                self.iwriters.pop(f_id, None)
                self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_id))
                self.ready_notice()
                logging.info(f'[Receiver] File finished: {self.files[f_id].s_relpath}')
            else:
                logging.error(f'[Receiver] Bad file hash: {self.files[f_id].s_relpath}')

        return len(chunk)

    def process_delta_literal(self, packet: Packet):
        f_id, seq, offset, data = packet.unpack_body()
        if f_id in self.done_files:
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
            return len(data)
        d = self.delta.get(f_id)
        if d is None:
            return len(data)
        self.delta_requested.pop(f_id, None)
        d.write_literal(offset, data)
        self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
        self.delta_received.setdefault(f_id, set()).add(seq)
        if f_id in self.trans_progress_tasks:
            try:
                trans_progress.update(self.trans_progress_tasks[f_id], advance=len(data))
            except KeyError:
                pass  # 进度任务已被移除
            handle_finished_task(trans_progress)
        self._maybe_finish_delta(f_id)
        return len(data)

    def process_delta_copy(self, packet: Packet):
        f_id, seq, offset, block_index, length = packet.unpack_body()
        if f_id in self.done_files:
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
            return length
        d = self.delta.get(f_id)
        if d is None:
            return length
        self.delta_requested.pop(f_id, None)
        d.copy_block(offset, block_index, length)
        self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
        self.delta_received.setdefault(f_id, set()).add(seq)
        if f_id in self.trans_progress_tasks:
            try:
                trans_progress.update(self.trans_progress_tasks[f_id], advance=length)
            except KeyError:
                pass  # 进度任务已被移除
            handle_finished_task(trans_progress)
        self._maybe_finish_delta(f_id)
        return length

    def process_delta_done(self, packet: Packet):
        f_id, seq = packet.unpack_body()
        if f_id in self.done_files:
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
            return
        d = self.delta.get(f_id)
        if d is None:
            return
        self.delta_requested.pop(f_id, None)
        self.conn_pool.send_or_drop(Packet.load(Flag.FILE_CHUNK_ACK, f_id, seq))
        # seq 即数据令牌数量 n_data；待所有数据令牌都到达后再完成重建
        self.delta_n[f_id] = seq
        self._maybe_finish_delta(f_id)

    def _maybe_finish_delta(self, f_id: int):
        if f_id in self.done_files:
            return
        n_data = self.delta_n.get(f_id)
        if n_data is None:
            return
        received = self.delta_received.get(f_id)
        if received is None or len(received) < n_data:
            return  # 仍有数据令牌未到达，等待
        d = self.delta.get(f_id)
        if d is None:
            return
        if d.finish():
            self.n_recv += 1
            self.done_files.add(f_id)
            self._done_ack_extra[f_id] = 0
            self.active.discard(f_id)
            self.delta.pop(f_id, None)
            self.delta_sigs.pop(f_id, None)
            self.delta_received.pop(f_id, None)
            self.delta_n.pop(f_id, None)
            self.concurrency.release()
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_id))
            self.ready_notice()
            self._notice_delta()
            logging.info(f'[Receiver] File finished (delta): {d.relpath}')
        else:
            logging.error(f'[Receiver] Bad delta hash: {d.relpath}')
            # 清理状态，避免后续报文写入已关闭的文件
            self.delta.pop(f_id, None)
            self.delta_received.pop(f_id, None)
            self.delta_n.pop(f_id, None)
            self.delta_sigs.pop(f_id, None)
            self.done_files.add(f_id)  # 忽略该文件后续报文
            try:
                d.tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _resend_control(self):
        now = time.time()
        if now - self._last_control_resend < 2:
            return
        self._last_control_resend = now
        for f_id in list(self.active - self.done_files):
            self.conn_pool.send_or_drop(Packet.load(Flag.FILE_READY, f_id))
        for f_id in list(self.delta_requested):
            if f_id in self.done_files:
                continue
            count = self.delta_requested[f_id]
            if count < 3:
                block_size, sigs = self.delta_sigs[f_id]
                self.conn_pool.send_or_drop(Packet.load(Flag.BLOCK_SIG, f_id, block_size, sigs))
                self.delta_requested[f_id] = count + 1
        for f_id in list(self._done_ack_extra):
            extra = self._done_ack_extra[f_id]
            if extra < 3:
                self.conn_pool.send_or_drop(Packet.load(Flag.FILE_DONE_ACK, f_id))
                extra += 1
                if extra >= 3:
                    del self._done_ack_extra[f_id]
                else:
                    self._done_ack_extra[f_id] = extra

    def run(self):
        logging.debug(f'Receiver-{self.sid.hex()[:8]} is running')
        self.conn_pool.start()

        packet = self.conn_pool.recv()
        if packet.flag == Flag.MONOFILE:
            (self.is_monofile,) = packet.unpack_body()
            self.check_dst_path()
        else:
            logging.error(f'[Receiver] The first packet must be MONOFILE but receive {packet.flag.name}')
            self.conn_pool.send_or_drop(Packet.load(Flag.EXCEPTION, 'packet type error.'))
            self.conn_pool.stop()
            return

        last_scan = 0.0
        while self.n_recv < self.total:
            try:
                packet = self.conn_pool.recv(timeout=0.5)
            except Empty:
                packet = None

            now = time.time()
            if now - last_scan >= 1.0:
                # 周期性补发控制报文，不能只在 recv 超时时执行，否则繁忙时会被饿死
                self._resend_control()
                last_scan = now

            if packet is None:
                continue

            try:
                if packet.flag == Flag.DIR_INFO:
                    self.process_dir_info(packet)

                elif packet.flag == Flag.FILE_INFO:
                    self.process_file_info(packet)

                elif packet.flag == Flag.FILE_CHUNK:
                    self.process_file_chunk(packet)

                elif packet.flag == Flag.DELTA_LITERAL:
                    self.process_delta_literal(packet)

                elif packet.flag == Flag.DELTA_COPY:
                    self.process_delta_copy(packet)

                elif packet.flag == Flag.DELTA_DONE:
                    self.process_delta_done(packet)

                elif packet.flag == Flag.FILE_COUNT:
                    (self.total,) = packet.unpack_body()

                elif packet.flag == Flag.EXCEPTION:
                    (msg,) = packet.unpack_body()
                    logging.error(f'fcp: the sender exit due to {msg}')
                    break

                else:
                    logging.error(f'[Receiver] Unknown packet flag: {packet.flag}')
            except Exception as e:  # noqa: BLE001
                logging.error(f'[Receiver] Error processing {packet.flag.name}: {e}')

        self.conn_pool.send_or_drop(Packet.load(Flag.DONE))
        logging.info('[Receiver] All files finished.')
        self.conn_pool.drain(3)

        self.conn_pool.stop()
        logging.info(f'Receiver-{self.sid.hex()[:8]} exit')


Porter = Sender | Receiver

from enum import Enum, IntEnum

CHUNK_SIZE = 8192  # 默认数据块大小 (单位: 字节)
TIMEOUT = 30  # 全局超时时间
QUEUE_SIZE = 256  # 队列大小

LEN_HEAD = 7
LEN_TYPE = 1
LEN_CHKSUM = 4
LEN_LENGTH = 2

EOF = 0xffffffff


class Role(Enum):
    Sender = 1
    Receiver = 2


class PacketSnippet(IntEnum):
    HEAD = 0
    BODY = 1


class Flag(IntEnum):
    PUSH = 1        # 推送申请
    PULL = 2        # 拉取申请
    SID = 3         # 建立会话
    ATTACH = 4      # 后续连接
    FILE_COUNT = 5  # 文件总量
    FILE_INFO = 6   # 文件信息
    FILE_READY = 7  # 文件就绪
    FILE_CHUNK = 8  # 数据传输
    ERROR = 9       # 错误回传

    @classmethod
    def contains(cls, member: object) -> bool:
        return member in cls.__members__.values()

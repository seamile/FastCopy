from enum import Enum, IntEnum

CHUNK_SIZE = 8192  # 默认数据块大小 (单位: 字节)
TIMEOUT = 30  # 全局超时时间

LEN_HEAD = 7
LEN_TYPE = 1
LEN_CHKSUM = 4
LEN_LENGTH = 2


class Ptype(IntEnum):
    PULL = 0x01  # 拉取申请
    PUSH = 0x02  # 推送申请
    SESSION = 0x03  # 建立会话
    FOLLOWER = 0x04  # 后续连接
    FILE_TOTAL = 0x05  # 文件总量
    FILE_INFO = 0x06  # 文件信息
    FILE_READY = 0x07  # 文件就绪
    TRANSFER = 0x08  # 数据传输
    ERROR = 0x09  # 错误回传


class Role(Enum):
    Sender = 1
    Receiver = 2

# FastCopy

[![PyPI Version](https://img.shields.io/pypi/v/fastcopy?color=blue&label=Version&logo=python&logoColor=white)](https://pypi.org/project/fastcopy/)
[![Installs](https://static.pepy.tech/personalized-badge/fastcopy?period=total&units=international_system&left_color=grey&right_color=blue&left_text=Installs)](https://pepy.tech/project/fastcopy)

A multi-threaded file transfer tool over SSH protocol.

Aims to replace `scp` and `rsync`.

## Features

- File chunking with parallel transfers for faster speeds
- Supports filename wildcards and regular expressions for file matching
- Automatically skips files with identical content on local and remote
- rsync-style delta sync: only transfers the differences of modified files
- Reliable transfer: per-chunk ACK + retransmission, idle-connection timeout with automatic failover
- Automatically preserves file permissions between sender and receiver
- Supports SSH Config
- Supports SSH Agent

## TODO

- [ ] Resume interrupted transfers
- [ ] Improve configuration management
- [ ] Confirm session parameters during handshake, remove global variables
- [ ] Version forward/backward compatibility
- [ ] Preserve symbolic links
- [ ] Replace sum-of-bytes weak checksum with Adler-32 rolling checksum in delta sync
- [ ] Stream delta sync for files larger than `DELTA_MAX_SIZE` (currently falls back to full transfer)

## Installation

The program must be installed on both the *server* and the *local* machine before use.

```shell
pip install fastcopy
```

## Usage

1. Server

    *Ensure port 7523 is not occupied on the server before running*

    ```shell
    fcpd -d
    ```

2. Local

    - Download

        ```shell
        fcp user@host:/foo/bar ./
        ```

        [![asciicast](https://asciinema.org/a/430555.svg)](https://asciinema.org/a/430555)

    - Upload

        ```shell
        fcp ./fake/file user@host:/foo/bar
        ```

        [![asciicast](https://asciinema.org/a/430553.svg)](https://asciinema.org/a/430553)

## Packet Design

All packets use **big-endian byte order**.

### 1. Unified Packet Format

|  flag   | chksum  | length  | payload |
|:-------:|:-------:|:-------:|:-------:|
| 1 Bytes | 4 Bytes | 4 Bytes |   ...   |

### 2. Packet Types

1. Push request: `0x1`
2. Pull request: `0x2`
3. Establish session: `0x3`
4. Subsequent connection: `0x4`
5. Transfer mode: `0x5`
6. Directory info: `0x6`
7. File info: `0x7`
8. File count: `0x8`
9. File ready: `0x9`
10. Data transfer: `0xa`
11. Transfer complete: `0xb`
12. Abnormal exit: `0xc`
13. Chunk acknowledgment: `0xd`
14. File done acknowledgment: `0xe`
15. Block signature (delta sync): `0xf`
16. Delta literal: `0x10`
17. Delta block copy: `0x11`
18. Delta done: `0x12`

### 3. Packet Details

1. Data Request

    After the connection is established, the client must first request a *pull* or *push* from the server and pass the *destination path* to the server.

    - The direction (pull/push) is determined by the `flag` field
    - Direction: Client -> Server
    - Payload format:

        | connection info |
        |:---------------:|
        |   json string   |

2. Establish Session

    Upon receiving the request in step 1, the server generates a SessionID and sends it back to the client. The client saves it locally.

    - Direction: Server -> Client
    - Payload format:

        | session_id |
        |:----------:|
        |  16 Bytes  |

3. Subsequent Connections

    Concurrent connections established by the client after the initial handshake must send the SessionID as the first packet.

    - Direction: Client -> Server
    - Payload format:

        | session_id |
        |:----------:|
        |  16 Bytes  |

4. File Count

    Once the connection is ready, the sender must inform the receiver of the total number of files.

    - Payload length is 4 bytes, so the maximum number of files is 4,294,967,296
    - Direction: Sender -> Receiver
    - Payload format:

        | n_files |
        |:-------:|
        | 4 Bytes |

5. File Info

    The sender must communicate the information of each file to the receiver.
    This includes file ID, permissions, size, creation time, modification time, access time, checksum, and path.
    The path is relative.

    - Direction: Sender -> Receiver
    - Payload format:

        | file_id |  perm   |  size   |  mtime  |  chksum  | path |
        |:-------:|:-------:|:-------:|:-------:|:--------:|:----:|
        | 4 Bytes | 2 Bytes | 8 Bytes | 8 Bytes | 16 Bytes | ...  |

6. Receiver File Ready

    After receiving the file info, the receiver records the information and creates an empty file of the same size locally.

    - Direction: Receiver -> Sender
    - Payload format:

        | file_id |
        |:-------:|
        | 4 Bytes |

7. File Data Chunk Packet

    The chunk sequence field occupies 4 bytes, so the maximum supported file size is: 4 GB * ChunkSize

    - Direction: Sender -> Receiver
    - Payload format:

        | file_id |   seq   | data |
        |:-------:|:-------:|:----:|
        | 4 Bytes | 4 Bytes | ...  |

### 4. Handshake Process

| Step |                      Client                       |                 Server                 |
|------|:-------------------------------------------------:|:--------------------------------------:|
| 1    |                   Client starts                   |             Server starts              |
| 2    |                                                   |           Waiting for client           |
| 3    |                Initiate connection                |                                        |
| 4    |                                                   |           Accept connection            |
| 5    |                                                   | Wait for request (timeout disconnects) |
| 6    |           Send `PUSH` or `PULL` request           |                                        |
| 7    |                                                   |           Generate SessionID           |
| 8    |                                                   |        Send SessionID to client        |
| 9    |            Receive and save SessionID             |                                        |
| 10   |       Create multiple parallel connections        |                                        |
| 11   | Each new connection sends `ATTACH` with SessionID |                                        |
| 12   |                                                   |       Verify SessionID is valid        |
| 13   |                                                   |     Add connection to session pool     |

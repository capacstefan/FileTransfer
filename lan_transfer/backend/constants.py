from dataclasses import dataclass

DEFAULT_UDP_PORT = 48201
DEFAULT_TCP_PORT = 48202
DEFAULT_BROADCAST_INTERVAL = 3.0  # seconds
DEFAULT_MAX_STREAMS = 4
DEFAULT_MAX_FILE_SIZE_BYTES = 3 * 1024 * 1024 * 1024  # 3 GiB


@dataclass(slots=True)
class BackendSettings:
    udp_port: int = DEFAULT_UDP_PORT
    tcp_port: int = DEFAULT_TCP_PORT
    broadcast_interval: float = DEFAULT_BROADCAST_INTERVAL
    max_concurrent_streams: int = DEFAULT_MAX_STREAMS
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES

from dataclasses import dataclass
import datetime


@dataclass
class PacketData:
    src: str
    dst: str
    srcport: str
    dstport: str
    timestamp: datetime.datetime
    transport_layer: str

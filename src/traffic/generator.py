# GNU General Public License v2.0

import time
from multiprocessing import Queue
import warnings
from cryptography.utils import CryptographyDeprecationWarning
from src.util import sha3_hash

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from scapy.all import *
from scapy.utils import rdpcap

from src.config import (
    LEGITIMATE_TRAFFIC_INTERVAL,
    ILLEGITIMATE_TRAFFIC_INTERVAL,
    EVAL_SIMULATED_TRAFFIC_PATH,
    EVAL_SIMULATED_ATK_TRAFFIC_PATH,
    USE_HASH,
)
from src.models import PacketData
import datetime
import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger("trafficGen")
log.setLevel(logging.DEBUG)


class TrafficGenerator:
    transport_layers = ["UDP", "TCP"]

    def __init__(self, queue: Queue):
        self.queue = queue

    def send_packet_data(self, src, dst):
        if USE_HASH:
            src = sha3_hash(src)
            dst = sha3_hash(dst)

        packet_data: PacketData = PacketData(
            src=src,
            dst=dst,
            srcport="80",
            dstport="80",
            timestamp=datetime.datetime.now(),
            transport_layer="TCP",
        )
        self.queue.put(packet_data)

    def read_simulated_traffic(self):
        time.sleep(1)
        log.info(f"sending traffic")
        self._read_traffic(EVAL_SIMULATED_TRAFFIC_PATH, LEGITIMATE_TRAFFIC_INTERVAL)

    def read_simulated_attack_traffic(self):
        time.sleep(3)
        log.info(f"attacking")
        self._read_traffic(
            EVAL_SIMULATED_ATK_TRAFFIC_PATH, ILLEGITIMATE_TRAFFIC_INTERVAL
        )

    def sleep(self, wait_time):
        time.sleep(wait_time)

    def _read_traffic(self, file_path: str, wait_time: float):
        log.info("read_traffic")
        iteration = 0
        scapy_cap = rdpcap(file_path)
        for packet in scapy_cap:
            # start = time.time_ns()
            self.send_packet_data(packet.src, packet.dst)
            iteration += 1
            if iteration % 1000 == 0:
                log.info(f"{iteration} for {file_path} done")
            # stop = time.time_ns()
            # print(f'_read_traffic - took {(stop - start)} ns')
            self.sleep(wait_time)

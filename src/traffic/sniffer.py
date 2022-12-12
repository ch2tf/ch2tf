# GNU General Public License v2.0

from multiprocessing import Queue
import pyshark
from pyshark.packet.packet import Packet
from src.models import PacketData


# inspired by pyshark documentation: http://kiminewt.github.io/pyshark/
class Sniffer:
    """
    Reference for a traffic sniffer class.
    """

    transport_layers = ["UDP", "TCP"]

    def __init__(self, queue: Queue, iface_name: str = "en0"):
        self.queue: Queue = queue
        self.iface_name: str = iface_name

    def get_packet_information(self, packet: Packet):
        transport_layer = packet.transport_layer
        if transport_layer not in self.transport_layers:
            return
        ip = packet.ipv6 if hasattr(packet, "ipv6") else packet.ip
        timestamp = packet.sniff_time.isoformat()

        packet_data: PacketData = PacketData(
            src=ip.src,
            dst=ip.dst,
            srcport=packet[transport_layer].srcport,
            dstport=packet[transport_layer].dstport,
            timestamp=timestamp,
            transport_layer=transport_layer,
        )
        self.queue.put(packet_data)

    def start_sniffing(self):
        capture = pyshark.LiveCapture(interface=self.iface_name)
        print(capture.interfaces)
        capture.apply_on_packets(self.get_packet_information)

from abc import ABC, abstractmethod
from typing import List
import logging

log = logging.getLogger("Mitigation")


class Mitigation(ABC):
    """
    Abstract class to filter IPs to achieve DDoS mitigation.
    """

    @abstractmethod
    def filter_ips(self, ip_list: List[str]):
        pass

    @abstractmethod
    def filter_ip(self, ip: str):
        pass


class NoMitigation(Mitigation):
    """
    Extends the Mitigation class, though does not do anything.
    """

    def filter_ip(self, ip: str):
        pass

    def filter_ips(self, ip_list: List[str]):
        pass

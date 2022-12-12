import logging
from collections import defaultdict
from typing import Tuple, Any
from abc import abstractmethod, ABC

from src.config import (
    THRESHOLD_SRC_1,
    THRESHOLD_SRC_2,
    THRESHOLD_SRC_3,
    THRESHOLD_SRC_3_MIN,
    THRESHOLD_TRAFFIC_PROPORTIONALITY,
    THRESHOLD_VICTIM_LO,
    THRESHOLD_VICTIM_TIME_MIN,
    THRESHOLD_VICTIM_TIME_PERCENTAGE,
)
from src.enums import DetectionEnum

log = logging.getLogger("analysis")


class Analysis(ABC):
    @abstractmethod
    def run_analysis(
        self,
        attacker_ip: str,
        victim_ip: str,
        src_dict: defaultdict,
        dst_dict: defaultdict,
        *args,
        **kwargs,
    ) -> Any:
        raise NotImplementedError


class AttackerAnalysis(Analysis):
    @abstractmethod
    def run_analysis(
        self,
        attacker_ip: str,
        victim_ip: str,
        src_dict: defaultdict,
        dst_dict: defaultdict,
        *args,
        **kwargs,
    ) -> bool:
        raise NotImplementedError


class AttackAnalysis(Analysis):
    @abstractmethod
    def run_analysis(
        self,
        attacker_ip: str,
        victim_ip: str,
        src_dict: defaultdict,
        dst_dict: defaultdict,
        *args,
        **kwargs,
    ) -> Tuple[bool, DetectionEnum, float]:
        raise NotImplementedError


class DDoSAttackAnalysis(AttackAnalysis):
    @staticmethod
    def check_timed_difference(
        victim_ip: str, dest_dict: defaultdict, dest_dict_aggregated: defaultdict
    ) -> tuple[bool, float]:
        new = dest_dict
        old = dest_dict_aggregated

        num_old = old.get(victim_ip, 0)
        num_new = sum(new[victim_ip].values())

        if num_old == 0 or num_new < THRESHOLD_VICTIM_TIME_MIN:
            return False, 0.0
        difference = float(num_new / num_old)
        return difference > THRESHOLD_VICTIM_TIME_PERCENTAGE, difference

    # @stopwatch(name="AttackAnalysis")
    def run_analysis(
        self, attacker_ip: str, victim_ip: str, src_dict, dst_dict, *args, **kwargs
    ) -> Tuple[bool, DetectionEnum, float]:
        # case 1: amount of packets arriving at destination is above threshold
        num_packets_destination = sum(dst_dict[victim_ip].values())
        if num_packets_destination > THRESHOLD_VICTIM_LO:
            return True, DetectionEnum.THRESHOLD, num_packets_destination

        # case 2: increase in traffic above threshold
        dest_dict_aggregated = kwargs.pop("dest_dict_aggregated")
        rel_new_requests, ratio = self.check_timed_difference(
            victim_ip, dst_dict, dest_dict_aggregated
        )
        if rel_new_requests:
            return True, DetectionEnum.TRAFFIC_INCREASE, ratio
        return False, DetectionEnum.NONE, 0


class HeavyHitterAnalysis(AttackerAnalysis):
    @staticmethod
    def is_traffic_direction_proportional(
        atk_ip: str,
        vic_ip: str,
        num_packets_from_src_to_victim_only: int,
        dst_dict: dict,
    ):
        """
        Considers the proportionality in flow between src and destination.
        If one side sends significantly more traffic to the other, this is seen as malicious traffic.
        :return: True if the traffic is proportional, False if malicious
        """
        # number of packets attacker sent to victim
        num_to_vic = num_packets_from_src_to_victim_only
        # number of packets attacker got from victim
        num_from_vic = dst_dict[atk_ip].get(vic_ip, 0)
        # case where attacker has not received any traffic from victim
        # these are considered as likelier attackers here => weighted 10x more
        if num_from_vic == 0:
            num_from_vic = 1e-1

        # only consider the case atk_to_vic > atk_from_vic.
        # since we are not concerned here with the victim being an attacker
        if THRESHOLD_TRAFFIC_PROPORTIONALITY <= num_to_vic / num_from_vic:
            log.info(f"Proportionality: False - {num_to_vic} / {num_from_vic}")
            return False
        return True

    # @stopwatch(name="AttackerAnalysis")
    def run_analysis(
        self,
        attacker_ip: str,
        victim_ip: str,
        src_dict: defaultdict,
        dst_dict: defaultdict,
        *args,
        **kwargs,
    ) -> bool:
        src_dict = src_dict.copy()
        dst_dict = dst_dict.copy()
        src_dict_tm1 = kwargs.pop("src_dict_tm1")

        num_packets_from_src_to_victim_only = src_dict.get(attacker_ip, {}).get(
            victim_ip, 0
        )
        num_packets_from_src_to_victim_only_prev = src_dict_tm1.get(
            attacker_ip, {}
        ).get(victim_ip, 0)

        num_packets_from_src_to_victim_only = max(
            num_packets_from_src_to_victim_only,
            num_packets_from_src_to_victim_only_prev,
        )
        # case 1: source sends too many packets to victim
        if num_packets_from_src_to_victim_only > THRESHOLD_SRC_1:
            log.info("depth - case1")
            return True
        # case 2: source sends many packets to many victims
        packets_from_this_src = sum(src_dict.get(attacker_ip, {}).values())
        packets_from_this_src_prev = sum(src_dict_tm1.get(attacker_ip, {}).values())
        num_packets_from_this_src = max(
            packets_from_this_src, packets_from_this_src_prev
        )
        if num_packets_from_this_src > THRESHOLD_SRC_2:
            log.info("depth - case2")
            return True
        # case 3: source is sending packets only to the victim, though not enough packets to enter the other thresholds
        if num_packets_from_this_src > THRESHOLD_SRC_3_MIN and (
            (ratio := (num_packets_from_src_to_victim_only / num_packets_from_this_src))
            >= THRESHOLD_SRC_3
        ):
            log.info(
                f"depth - case3: {num_packets_from_src_to_victim_only} / {num_packets_from_this_src} packets = {ratio}"
            )
            return True
        # case 4: traffic direction proportionality
        if not self.is_traffic_direction_proportional(
            attacker_ip, victim_ip, num_packets_from_src_to_victim_only, dst_dict
        ):
            log.info("depth - case4")
            return True
        return False

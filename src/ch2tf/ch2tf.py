import copy
import os
import time
from multiprocessing import Queue
from collections import defaultdict
import logging
from kafka.consumer.fetcher import ConsumerRecord
from kafka import KafkaConsumer, KafkaProducer
from src.enums import DetectionEnum, DecisionEnum
from .analyses import (
    AttackerAnalysis,
    AttackAnalysis,
)
from src.util import (
    is_sampling_skip,
    init_managed_ips,
    init_bloom_filter,
    add_to_bloom_filter,
)
from collections import Counter

from src.config import (
    KAFKA,
    TOPICS,
    TOPIC_HIGH,
    TOPIC_LOW,
    AS_SIZE,
    THRESHOLD_VICTIM_LO,
    THRESHOLD_VICTIM_HI,
    AS_NAME,
    THRESHOLD_VICTIM_TIME_PERCENTAGE,
    MANAGED_IPS_PATH,
    ANALYSIS_PERIOD,
    MSG_LENGTH,
    SAMPLING_RATE,
    USE_HASH,
    TOPICS_USE_ADDITIONAL,
)

from src.mitigation import Mitigation
from src.models import (
    DefenseCollaborationRequestData,
    DefenseCollaborationResponseData,
    PacketData,
)
from src.util.jsonSerializer import json_serializer, json_deserializer

log = logging.getLogger("ch2tf")


class CH2TF:
    dest_dict: defaultdict = defaultdict(Counter)
    src_dict: defaultdict = defaultdict(Counter)
    src_dict_tm1: defaultdict = defaultdict(Counter)
    reputation_dict: defaultdict = defaultdict(lambda: 1.0)
    req_dict: defaultdict = defaultdict(lambda: DefenseCollaborationRequestData)
    responses: defaultdict = defaultdict(
        lambda: defaultdict(lambda: DefenseCollaborationResponseData)
    )

    def __init__(
        self,
        queue: Queue,
        mitigation: Mitigation,
        attacker_analysis: AttackerAnalysis,
        attack_analysis: AttackAnalysis,
    ):
        self.dest_dict_aggregated: defaultdict = defaultdict(Counter)
        self.queue = queue
        self.mitigation = mitigation
        self.sub_topics = [top + "." for top in TOPICS]
        self.managed_ips = init_managed_ips(MANAGED_IPS_PATH, USE_HASH)
        self.heavy_hitter_table = init_bloom_filter()

        self.producer = KafkaProducer(
            bootstrap_servers=[KAFKA],
            api_version=(0, 10, 0),
            value_serializer=json_serializer,
        )
        self.attacker_analysis = attacker_analysis
        self.attack_analysis = attack_analysis

    def _init_consumer_topics(self, topics: list, standard: list) -> list:
        """
        Concatenates the additional topics with the standard topics.
        Adds .REQ and .RES for each topic for the consumer.
        :param topics: additional topics
        :type topics: list
        :param standard: standard topics
        :type standard: list
        :return: concatenated list with .RES and .REQ
        :rtype: list
        """
        topics = copy.copy(topics) + standard
        tpcs = []
        for topic in topics:
            tpcs.append(topic + ".REQ")
            tpcs.append(topic + ".RES")
        return tpcs

    def check_if_is_managed(self, ip_address: str) -> bool:
        """
        Checks whether a given ip_address is probably managed by the AS.
        This is done by verifying if it is contained in the bloom filter.
        Due to the bloom filter's working, it is possible that `True` is returned, though it is not contained.
        :param ip_address: a given ip address to check if it is in bloom filter
        :type ip_address: str
        :return: whether ip_address is in the bloom filter
        """
        return ip_address in self.managed_ips

    def collect_packages(self) -> None:
        """
        Collect traffic packages that the method receives through the queue.

        :return: None
        """

        dest_dict = self.dest_dict
        src_dict = self.src_dict
        while True:
            received: PacketData = self.queue.get()
            self._store_data(received, dest_dict, src_dict)

    # noinspection PyMethodMayBeStatic
    # (using references here, cannot be static)
    def _store_data(
        self, received: PacketData, dest_dict: defaultdict, src_dict: defaultdict
    ) -> None:
        """
        Aggregates packages.

        :param received: A received packet
        :type received: PacketData
        :param dest_dict: Destination perspective dict
        :type dest_dict: defaultdict(Counter)
        :param src_dict: Source perspective dict
        :type src_dict: defaultdict(Counter)
        :return: None
        """
        if is_sampling_skip(SAMPLING_RATE):
            return
        dest_dict[received.dst][received.src] += 1
        if not self.check_if_is_managed(received.src):
            return
        src_dict[received.src][received.dst] += 1

    def run_analysis(self) -> None:
        """
        Every x seconds the shallow analysis is run.
        This is done for all packets that arrive at an AS,
        whether it will be routed further or are managed by this AS
        :return:
        :rtype:
        """
        req_dict = self.req_dict
        iteration = 0
        while True:
            iteration += 1
            log.info(f"running analysis: {iteration}")
            # use copy here since during execution new packets are being collected
            dest_dict = self.dest_dict.copy()
            src_dict = self.src_dict.copy()
            for dest_ip, src_ips in dest_dict.items():
                detected, detection_case, ratio = self.attack_analysis.run_analysis(
                    "",
                    dest_ip,
                    src_dict,
                    dest_dict,
                    dest_dict_aggregated=self.dest_dict_aggregated,
                )
                if not detected:
                    continue
                num_packets_for_this_destination = sum(dest_dict[dest_ip].values())
                # pick topic based on threshold. i.e. probable vs highly certain of attack
                # checks are simple here, to improve performance.
                topic = TOPIC_LOW
                if num_packets_for_this_destination > THRESHOLD_VICTIM_HI:
                    topic = TOPIC_HIGH
                publish_topics = [topic]
                # if this env is true, will skip 'default' topics! and send to each additional one
                if TOPICS_USE_ADDITIONAL:
                    publish_topics = TOPICS
                potential_attacker_ips = list(dest_dict[dest_ip])

                # split list into more manageable list of MSG_LENGTH
                splitted_potential_attacker_ips = [
                    potential_attacker_ips[x : x + MSG_LENGTH]
                    for x in range(0, len(potential_attacker_ips), MSG_LENGTH)
                ]
                for e in splitted_potential_attacker_ips:
                    request = DefenseCollaborationRequestData(
                        potential_attacker_ips=e,
                        potential_victim=dest_ip,
                        request_detection=detection_case,
                        requests_relative_to_size=ratio / AS_SIZE,
                    )
                    for top in publish_topics:
                        topic = top + ".REQ"
                        self.producer.send(
                            topic=topic,
                            value=request.to_json(),  # type: ignore
                            key=str.encode(request.request_id),
                        )
                        log.info(
                            f"{AS_NAME} sending collab request - {topic} - with id: {request.request_id} for victim {request.potential_victim}"
                        )

                    req_dict[str(request.request_id)] = request
                    # go directly to analysis, do not need to go through kafka
                    self.handle_collab_req(
                        def_collab_req=request, topics=publish_topics
                    )

                    log.info(f"{len(request.potential_attacker_ips)}")
                # light mitigation
                self.mitigation.filter_ips(potential_attacker_ips)
            self.dest_dict_aggregated = self.create_aggregate(self.dest_dict.copy())
            self.reset_data()
            time.sleep(ANALYSIS_PERIOD)
            log.info(f"Analysis: {iteration} done")

    def create_aggregate(self, dest_dict):
        dest_dict_aggregated = {}
        for k, v in dest_dict.items():
            dest_dict_aggregated[k] = sum(v.values())
        return dest_dict_aggregated

    def reset_data(self):
        try:
            self.src_dict_tm1 = copy.deepcopy(dict(self.src_dict))
            self.src_dict.clear()
            self.dest_dict.clear()
            log.info("resetted!")
        except Exception as e:
            log.error(f"resetting failed!")
            log.error(e)

    def listen(self) -> None:
        """
        listens as a consumer to the topics and delegates according to topic
        :return:
        """

        log.info("listening")
        consumer = KafkaConsumer(
            bootstrap_servers=[KAFKA],
            api_version=(0, 10, 0),
            value_deserializer=json_deserializer,
            auto_offset_reset="latest",
            enable_auto_commit=False,
        )

        topics = self._init_consumer_topics(TOPICS, [TOPIC_HIGH, TOPIC_LOW])
        consumer.subscribe(topics)
        log.info(consumer.topics())

        message: ConsumerRecord
        for message in consumer:
            topic = message.topic
            if "REQ" in topic:
                if TOPIC_HIGH in topic:
                    self.handle_collab_req(message, high_prio=True, topic=topic)
                else:
                    # low prio or non-standard topics
                    self.handle_collab_req(message, topic=topic)
            elif "RES" in topic:
                self.handle_collab_res(message, topic=topic)

    def handle_collab_req(
        self,
        message: ConsumerRecord = None,
        def_collab_req: DefenseCollaborationRequestData = None,  # type: ignore
        high_prio: bool = False,
        topic: str = "",
        topics: list | None = None,
    ):
        """
        Given a collaboration request, this method verifies for each potential attacker
            if this attacker is managed by this AS.
            In the case that it is, the method responds whether the potential attacker is above a certain threshold.

        :param message:
        :type message: ConsumerRecord
        :param def_collab_req:
        :type def_collab_req: DefenseCollaborationRequestData
        :param high_prio:
        :type high_prio: bool
        :param topic:
        :type topic: str
        :param topics:
        :type topics: list | None
        :return:
        """
        topic = topic.replace(".REQ", "")

        dest_dict = copy.deepcopy(self.dest_dict.copy())
        src_dict = copy.deepcopy(self.src_dict.copy())
        src_dict_tm1 = copy.deepcopy(self.src_dict_tm1.copy())
        req_dict = self.req_dict
        def_collab_req = (
            DefenseCollaborationRequestData.from_json(message.value)  # type: ignore
            if message
            else def_collab_req
        )

        # ignore own request that receives through kafka consumer
        if def_collab_req.request_originator == AS_NAME and message is not None:
            return

        log.info(
            f"{AS_NAME}: handle request from {def_collab_req.request_originator} "
            f"with id: {def_collab_req.request_id} for victim {def_collab_req.potential_victim} "
            f"with topic(s) {topic or topics}"
        )

        req_dict[str(def_collab_req.request_id)] = def_collab_req

        # in the case that reputation of the originator is OK (> 0.5)
        # and it has been sent with high priority (= 2nd topic)
        # then some mitigation (not part of this work) will already be put in place
        if high_prio and self.reputation_dict[def_collab_req.request_originator] > 0.5:
            self.mitigation.filter_ips(def_collab_req.potential_attacker_ips)

        # note: if is_larger_than_own_threshold is true,
        # it means that this AS agrees that an attack is happening.
        # though it does not know yet which ips are attackers. which is part of this (2nd) analysis.
        is_larger_than_own_threshold: bool = self._is_larger_than_own_threshold(
            def_collab_req
        )

        list_ack_attacker = []  # acknowledged attackers

        list_not_managed = (
            []
        )  # potential attackers ips, but this AS cannot mitigate (not managed)
        list_not_attacker = (
            []
        )  # potential attacker ips (managed), but not seen as attacker

        highest_amount_of_pkts_sent_from_this_src = -9999999

        if not is_larger_than_own_threshold:
            decision = DecisionEnum.NOT_ACK
            def_collab_req.potential_attacker_ips = []
        else:
            highest_amount_of_pkts_sent_from_this_src = 0
            for potential_attacker in def_collab_req.potential_attacker_ips:
                # check if ip of a potential attacker is managed by this AS. if not, nothing is done.
                if self.check_if_is_managed(potential_attacker):
                    highest_amount_of_pkts_sent_from_this_src = max(
                        highest_amount_of_pkts_sent_from_this_src,
                        src_dict_tm1.get(potential_attacker, {}).get(
                            def_collab_req.potential_victim, 0
                        ),
                        src_dict.get(potential_attacker, {}).get(
                            def_collab_req.potential_victim, 0
                        ),
                    )
                    if self.attacker_analysis.run_analysis(
                        potential_attacker,
                        def_collab_req.potential_victim,
                        src_dict,
                        dest_dict,
                        src_dict_tm1=src_dict_tm1,
                    ):
                        list_ack_attacker.append(potential_attacker)
                    else:
                        list_not_attacker.append(potential_attacker)
                else:
                    list_not_managed.append(potential_attacker)
            decision = (
                DecisionEnum.UNDER_THRS
                if len(list_ack_attacker) == 0
                else DecisionEnum.FOUND
            )
            decision = (
                DecisionEnum.NOT_MANAGED
                if len(list_not_managed) == len(def_collab_req.potential_attacker_ips)
                else decision
            )
        def_collab_res: DefenseCollaborationResponseData = (
            DefenseCollaborationResponseData(
                request_id=def_collab_req.request_id,
                ack_potential_attacker_ips=list_ack_attacker,
                decision=decision,
                request_originator=def_collab_req.request_originator,
                as_name=os.getenv("AS_NAME", default=""),
            )
        )

        log.info(
            f"Highest amount of pckts from a single src to this victim: {highest_amount_of_pkts_sent_from_this_src}"
        )
        log.info(f"decision: {decision}")
        log.info(f"NOT managed: {len(list_not_managed)}")
        log.info(f"Managed, but not attacking: {len(list_not_attacker)}")
        log.info(f"Managed, and ack attacking: {len(list_ack_attacker)}")

        if topics is None:  # if message received through kafka topics is None
            topics = [topic]
        for topic in topics:
            topic = topic + ".RES"
            log.info(
                f"{def_collab_res.as_name} sending collab response - {topic} with id: {def_collab_res.request_id}"
            )
            self.producer.send(
                topic=topic,
                value=def_collab_res.to_json(),  # type: ignore
                key=str.encode(def_collab_res.request_id),
            )
        self.mitigation.filter_ips(def_collab_res.ack_potential_attacker_ips)

    def handle_collab_res(self, message, topic):
        """
        Handling of collaboration response

        :param message: pubsub message
        :type message: ConsumerRecord
        :param topic: str |
        :type topic: str | None
        :return: None
        :rtype: None
        """
        topic = topic.replace(".RES", "")
        responses: defaultdict = self.responses

        collab_response: DefenseCollaborationResponseData = (
            DefenseCollaborationResponseData.from_json(message.value)
        )
        responses[collab_response.request_id][collab_response.as_name] = collab_response
        given_decision: DecisionEnum = collab_response.decision

        log.info(
            f"handle response with id: {collab_response.request_id} from {collab_response.as_name}"
            f" with topic {topic} - decision: {given_decision}"
        )

        match given_decision:
            case DecisionEnum.FOUND:
                log.info("Found Attackers")
                # mitigation starts here, but not part of this work
                self.mitigation.filter_ips(collab_response.ack_potential_attacker_ips)
                if collab_response.request_originator == AS_NAME:
                    self.reputation_dict[collab_response.as_name] += 0.1
                self.heavy_hitter_table = add_to_bloom_filter(
                    self.heavy_hitter_table, collab_response.ack_potential_attacker_ips
                )
            case DecisionEnum.NOT_ACK:
                # in the case that it originates from this AS, build reputation scheme
                if collab_response.request_originator == AS_NAME:
                    self.reputation_dict[collab_response.as_name] -= 0.1

                # note: future work could include dynamic thresholds that are adjusted accordingly based on the replies
                # such that each AS keeps track of the thresholds from the other and adjusts them if they are not ACK
            case DecisionEnum.UNDER_THRS:
                # ack attack and has managed ips but claims no attackers from this AS
                pass
            case DecisionEnum.NOT_MANAGED:
                # no managed ip addresses. could build knowledge of managed ips here (?)
                pass
            case _:
                pass

    def _is_larger_than_own_threshold(
        self, def_collab_req: DefenseCollaborationRequestData
    ) -> bool:
        """
        adjust the collaboration request to the relative sizes
        => is a request originating from another AS (or my AS)
        also above my threshold when adjusted to the relative sizes and
        thresholds? Essentially, would these flows also trigger my threshold?
        :param def_collab_req:
        :type def_collab_req: DefenseCollaborationRequestData
        :return: whether this AS agrees that an attack has been detected
        :rtype: bool
        """

        requests_relative_to_size = AS_SIZE * def_collab_req.requests_relative_to_size
        match def_collab_req.request_detection:
            case DetectionEnum.THRESHOLD:
                is_larger_than_own_threshold = (
                    requests_relative_to_size > THRESHOLD_VICTIM_LO
                )
            case DetectionEnum.TRAFFIC_INCREASE:
                is_larger_than_own_threshold = (
                    requests_relative_to_size > THRESHOLD_VICTIM_TIME_PERCENTAGE
                )
            case _:
                is_larger_than_own_threshold = False
        return is_larger_than_own_threshold

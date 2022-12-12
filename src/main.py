from multiprocessing import Process, Queue
import time
import os
import kafka
from ch2tf import CH2TF
from threading import Thread

from src.ch2tf import HeavyHitterAnalysis, DDoSAttackAnalysis
from src.traffic import Sniffer, TrafficGenerator
from src.config import KAFKA
from src.mitigation import NoMitigation
import logging
from logging.handlers import RotatingFileHandler

log = logging.getLogger("")


def check_kafka_conn() -> None:
    """
    Upon startup, kafka and its zookeeper dependency might not be ready yet.
    To avoid errors resulting from these issues, this method ensures that the program flow only continues
     when the connection is fully established and ready.
    :return:
    :rtype: None
    """
    for _ in range(100):
        try:
            consumer = kafka.KafkaConsumer(group_id="test", bootstrap_servers=[KAFKA])
            topics = consumer.topics()
            log.info(topics)
            log.info("Kafka connection up")
            return
        except RuntimeError as e:
            log.info("Kafka connection not up yet...")
            time.sleep(1)


if __name__ == "__main__":
    # create logging dir if it does not exist
    if not os.path.exists("../logs"):
        os.makedirs("../logs")
    # logging setup & config => log to files and console
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - [%(levelname)s] - %(message)s",
        handlers=[
            RotatingFileHandler("../logs/log.log", maxBytes=1_000_000, backupCount=10),
            logging.StreamHandler(),
        ],
    )
    kafka_logger = logging.getLogger("kafka")
    kafka_logger.setLevel(logging.ERROR)
    # upon startup kafka and zookeeper might not be ready yet,
    # check their continue and continue only when services are ready
    check_kafka_conn()

    # queue is used to pass packets.
    # cannot use pipe here, since for attack evaluation, there are multiple senders, which pipe does not support.
    queue: Queue = Queue()
    traffic_gen = TrafficGenerator(queue)
    sniffer = Sniffer(queue)
    ch2tf = CH2TF(
        queue=queue,
        mitigation=NoMitigation(),
        attacker_analysis=HeavyHitterAnalysis(),
        attack_analysis=DDoSAttackAnalysis(),
    )

    # for eval only
    p_read_simulated_traffic = Process(
        target=traffic_gen.read_simulated_traffic, args=()
    )
    p_read_simulated_atk_traffic = Process(
        target=traffic_gen.read_simulated_attack_traffic, args=()
    )
    p_sniff_traffic = Process(target=sniffer.start_sniffing, args=())

    # ch2tf threads
    t1 = Thread(target=ch2tf.collect_packages, args=())
    t2 = Thread(target=ch2tf.listen, args=())
    t3 = Thread(target=ch2tf.run_analysis, args=())

    t1.start()
    t2.start()
    t3.start()

    # for eval only
    p_read_simulated_traffic.start()
    p_read_simulated_atk_traffic.start()
    # p_sniff_traffic.start()

    time.sleep(1000)
    log.info("stopping attack after 1000s")
    p_read_simulated_atk_traffic.kill()
    time.sleep(1000)
    log.info("stopping normal traffic")
    p_read_simulated_traffic.kill()
    log.info("done")

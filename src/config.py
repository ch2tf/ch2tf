import os
import logging
from dotenv import load_dotenv
from src.util.envFileUtil import env_splitter

log = logging.getLogger("config")

load_dotenv()


def get_bool(var: str) -> bool:
    return var.lower() in ("True", "true")


KAFKA = str(
    os.getenv("KAFKA_HOST", default="") + ":" + os.getenv("KAFKA_PORT", default="")
)

# not in container:
# KAFKA = 'localhost:9092'

# TOPICS
TOPICS = env_splitter(os.getenv("AS_TOPICS", default=""))
TOPIC_HIGH = str(os.getenv("TOPIC_HIGH", ""))
TOPIC_LOW = str(os.getenv("TOPIC_LOW", ""))
TOPICS_USE_ADDITIONAL = get_bool(os.getenv("TOPICS_USE_ADDITIONAL", default="False"))

AS_SIZE = int(os.getenv("AS_SIZE", default=0))
SAMPLING_RATE = float(os.getenv("SAMPLING_RATE", default=1))
AS_NAME = os.getenv("AS_NAME", default="")
MSG_LENGTH = int(os.getenv("MSG_LENGTH", default=10_000))

THRESHOLD_VICTIM_LO = int(os.getenv("THRESHOLD_VICTIM_LO", default=0))
THRESHOLD_VICTIM_HI = int(os.getenv("THRESHOLD_VICTIM_HI", default=0))
THRESHOLD_VICTIM_TIME_PERCENTAGE = float(
    os.getenv("THRESHOLD_VICTIM_TIME_PERCENTAGE", default=0)
)
THRESHOLD_VICTIM_TIME_MIN = float(os.getenv("THRESHOLD_VICTIM_TIME_MIN", default=0))

THRESHOLD_SRC_1 = float(os.getenv("THRESHOLD_SRC_1", default=0))
THRESHOLD_SRC_2 = float(os.getenv("THRESHOLD_SRC_2", default=0))
THRESHOLD_SRC_3 = float(os.getenv("THRESHOLD_SRC_3", default=0))
THRESHOLD_SRC_3_MIN = float(os.getenv("THRESHOLD_SRC_3_MIN", default=0))

THRESHOLD_TRAFFIC_PROPORTIONALITY = int(
    os.getenv("THRESHOLD_TRAFFIC_PROPORTIONALITY", default=0)
)
ANALYSIS_PERIOD = float(os.getenv("ANALYSIS_PERIOD", default=0))

# for attack evaluation:
MANAGED_IPS_PATH = os.getenv("MANAGED_IPS_PATH", default="")
EVAL_SIMULATED_ATK_TRAFFIC_PATH = os.getenv("EVAL_SIMULATED_ATK_TRAFFIC_PATH")
EVAL_SIMULATED_TRAFFIC_PATH = os.getenv("EVAL_SIMULATED_TRAFFIC_PATH")

LEGITIMATE_TRAFFIC_INTERVAL = float(os.getenv("LEGITIMATE_TRAFFIC_INTERVAL", default=0))
ILLEGITIMATE_TRAFFIC_INTERVAL = float(
    os.getenv("ILLEGITIMATE_TRAFFIC_INTERVAL", default=0)
)

USE_HASH = get_bool(os.getenv("USE_HASH", default="True"))

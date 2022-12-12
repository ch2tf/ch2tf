from enum import Enum


class DecisionEnum(Enum):
    NOT_MANAGED = "AS does not manage any of the ip"
    NOT_ACK = "AS does not acknowledge this as an attack"
    UNDER_THRS = "No potential attacker pass the thresholds"
    FOUND = "Attacker(s) found"

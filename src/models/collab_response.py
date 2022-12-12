# mypy: ignore-errors
from dataclasses import dataclass
from typing import List
from dataclasses_json import dataclass_json
from src.enums import DecisionEnum


@dataclass_json
@dataclass
class DefenseCollaborationResponseData:
    """
    Response for a defense collaboration

    """

    # potential attackers that the AS acknowledges.
    # subset of the potential attackers that is sent in the request
    ack_potential_attacker_ips: List[str]
    decision: DecisionEnum
    as_name: str
    request_id: str  # use same id as original request
    request_originator: str  # from which AS the request came from

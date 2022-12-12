import os
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json
import uuid
from typing import List
from src.enums import DetectionEnum


@dataclass_json
@dataclass
class DefenseCollaborationRequestData:
    """
    Request for a defense collaboration
    """

    potential_attacker_ips: List[str]  # the ips to be checked by the receivers
    potential_victim: str
    requests_relative_to_size: float
    request_detection: DetectionEnum
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    request_originator: str = os.getenv("AS_NAME", default="")

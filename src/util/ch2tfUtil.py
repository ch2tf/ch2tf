import hashlib
import random
from typing import Any, List

import pybloom_live


def is_sampling_skip(sampling_rate: float, rand: float | None = None) -> bool:
    """
    Returns whether the element should be skipped.

    :param sampling_rate: pos number >= 0
    :type sampling_rate: float
    :param rand: random number in the interval [0,1)
    :type rand: float
    :return: True if entry should be skipped
    :rtype: bool
    """
    if rand is None:
        rand = random.random()
    return rand > sampling_rate


def sha3_hash(var: Any) -> str:
    var = var.encode()
    return hashlib.sha3_256(var).hexdigest()


def init_managed_ips(
    managed_ip_path: str, is_use_hash: bool, capacity: int = 100_000
) -> pybloom_live.BloomFilter:
    """
    Initializes the bloom filter by adding the managed ip addresses
    :param is_use_hash: whether the managed ips should be hashed
    :type is_use_hash: bool
    :param managed_ip_path: path of textfile containing ips
    :type managed_ip_path: str
    :param capacity: capacity of the bloom filter
    :type capacity: int
    :return: populated bloom filter
    :rtype: pybloom_live.BloomFilter
    """
    bloom_filter = init_bloom_filter(capacity)
    with open(managed_ip_path, mode="r", encoding="utf-8") as f:
        for line in f:
            entry = line.rstrip("\n")
            if is_use_hash:
                entry = sha3_hash(entry)
            bloom_filter.add(entry)
    return bloom_filter


def init_bloom_filter(capacity: int = 10_000):
    return pybloom_live.BloomFilter(capacity=capacity)


def add_to_bloom_filter(bloom_filter: pybloom_live.BloomFilter, entries: List[str]):
    for entry in entries:
        bloom_filter.add(entry)
    return bloom_filter

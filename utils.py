#!/usr/bin/env python3
import random
from typing import Optional


def flip_random_bit(data: bytes, pos: Optional[int] = None) -> bytes:
    """
    Randomly flips one bit in the first 16 bytes of `data`.

    :param data: The actual data where the flip will occure.
    :param pos: The position (index, starting at 0) of a byte in data, whose
                least significant bit will get flipped. By default the position
                is randomly chosen from the range [0, 15].

    :return: The original data with a single bit flipped.

    Example:
    >>> word = b'hello'
    >>> flip_random_bit(word, pos=0)
    b'iello'
    >>> flip_random_bit(bytes([0b101, 0b101]), pos=0) == b'\x04\x05'
    True
    """
    data = bytearray(data)
    if pos is None:
        pos = random.randint(0, 15)
    data[pos] ^= 1
    return bytes(data)

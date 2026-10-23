from __future__ import annotations

import socket
import struct
import threading

import pytest

from remote_exec.protocol import ProtocolError, recv_message, send_message


def test_message_round_trip() -> None:
    left, right = socket.socketpair()
    try:
        send_message(left, {"type": "test", "text": "你好"})
        assert recv_message(right) == {"type": "test", "text": "你好"}
    finally:
        left.close()
        right.close()


def test_recv_handles_fragmented_frame() -> None:
    left, right = socket.socketpair()
    payload = b'{"type":"fragmented","value":7}'
    wire = struct.pack(">I", len(payload)) + payload

    def writer() -> None:
        for byte in wire:
            left.sendall(bytes([byte]))
        left.close()

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        assert recv_message(right) == {"type": "fragmented", "value": 7}
    finally:
        right.close()
        thread.join()


def test_duplicate_json_keys_are_rejected() -> None:
    left, right = socket.socketpair()
    payload = b'{"type":"one","type":"two"}'
    try:
        left.sendall(struct.pack(">I", len(payload)) + payload)
        with pytest.raises(ProtocolError, match="duplicate"):
            recv_message(right)
    finally:
        left.close()
        right.close()


def test_oversized_frame_is_rejected_before_body_read() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(struct.pack(">I", 101))
        with pytest.raises(ProtocolError, match="frame size"):
            recv_message(right, max_frame_size=100)
    finally:
        left.close()
        right.close()


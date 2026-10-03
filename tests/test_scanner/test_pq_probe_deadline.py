"""A slow server cannot hold the hybrid-KEM probe open."""

from __future__ import annotations

import socket
import threading
import time

from src.scanner.pq_probe import probe_pq_kem


def test_slow_drip_server_cannot_hold_the_probe():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return

            def drip(c=conn):
                try:
                    c.recv(4096)
                    c.sendall(b"\x16\x03\x03\x40\x00")  # promises a 16 KiB record
                    while True:
                        time.sleep(0.2)
                        c.sendall(b"\x00")  # one byte, well inside the socket timeout
                except OSError:
                    pass

            threading.Thread(target=drip, daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    start = time.monotonic()
    result = probe_pq_kem("127.0.0.1", port, timeout=0.5)
    srv.close()
    assert time.monotonic() - start < 3
    assert result.supported is False

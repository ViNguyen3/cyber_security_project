from scapy.all import AsyncSniffer, IP, IPv6, TCP, UDP, PcapWriter
import threading, queue, time, os
from typing import Optional

class PacketCapture:
    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: Optional[str] = None,     # e.g. "tcp or udp"
        queue_maxsize: int = 10000,
        pcap_dir: Optional[str] = None,       # e.g. "/var/log/ids"
        rotate_sec: int = 300                 # 5 min files
    ):
        self.iface = interface
        self.bpf = bpf_filter
        self.q = queue.Queue(maxsize=queue_maxsize)
        self._stop = threading.Event()
        self._sniffer = None

        # metrics
        self.pkts_seen = 0
        self.pkts_enqueued = 0
        self.pkts_dropped_queue = 0

        # optional PCAP rotation
        self.pcap_dir = pcap_dir
        self.rotate_sec = rotate_sec
        self._pw = None
        self._next_rotate = 0

        if self.pcap_dir:
            os.makedirs(self.pcap_dir, exist_ok=True)

    # ---- internals ----
    def _maybe_rotate(self):
        if not self.pcap_dir:
            return
        now = time.time()
        if self._pw is None or now >= self._next_rotate:
            if self._pw:
                self._pw.close()
            ts = time.strftime("%Y%m%d-%H%M%S")
            path = os.path.join(self.pcap_dir, f"capture-{ts}.pcap")
            self._pw = PcapWriter(path, append=False, sync=True)
            self._next_rotate = now + self.rotate_sec

    def _on_packet(self, pkt):
        # Accept IPv4/IPv6 + TCP/UDP (extend as needed)
        if not ( (IP in pkt or IPv6 in pkt) and (TCP in pkt or UDP in pkt) ):
            return
        self.pkts_seen += 1

        # optional write-to-PCAP for auditing
        if self._pw:
            self._maybe_rotate()
            self._pw.write(pkt)

        # non-blocking enqueue to avoid stalling capture thread
        try:
            self.q.put_nowait(pkt)
            self.pkts_enqueued += 1
        except queue.Full:
            self.pkts_dropped_queue += 1  # monitor this; increase queue or speed up analyzer

    # ---- public API ----
    def start(self):
        # rotate immediately if pcap_dir set
        if self.pcap_dir:
            self._maybe_rotate()

        self._stop.clear()
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            prn=self._on_packet,
            store=False,
            filter=self.bpf  # kernel-level BPF filter for performance
        )
        self._sniffer.start()  # runs in its own daemon thread

    def stop(self):
        self._stop.set()
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        if self._pw:
            self._pw.close()
            self._pw = None

    def get_packet(self, timeout: Optional[float] = 0.5):
        """Consumer side: call in your analyzer loop."""
        try:
            return self.q.get(timeout=timeout)
        except queue.Empty:
            return None

    def stats(self) -> dict:
        return {
            "seen": self.pkts_seen,
            "enqueued": self.pkts_enqueued,
            "dropped_queue": self.pkts_dropped_queue,
            "queue_size": self.q.qsize()
        }

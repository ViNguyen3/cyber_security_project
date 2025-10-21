# test_simulated_capture.py
from scapy.all import IP, TCP, UDP
import time
import threading
import os

# import the class you uploaded
from packet_capture_v1 import PacketCapture

LOG_DIR = "./logs"
PCAP_DIR = "./pcaps"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

def packet_logger(pc: PacketCapture, stop_event: threading.Event, log_path: str):
    """Consumer loop: take packets off the queue and append to the log."""
    with open(log_path, "a", encoding="utf-8") as f:
        while not stop_event.is_set():
            pkt = pc.get_packet(timeout=0.5)
            if pkt is None:
                continue
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            try:
                if pkt.haslayer("IP"):
                    ip = pkt.getlayer("IP")
                    proto = pkt.payload.name if pkt.payload is not None else "IP"
                    src, dst = ip.src, ip.dst
                    sport = getattr(pkt.payload.payload, "sport", "")
                    dport = getattr(pkt.payload.payload, "dport", "")
                else:
                    # fallback if no IP layer
                    proto = pkt.name
                    src = dst = "?"
                    sport = dport = ""
            except Exception:
                proto = src = dst = sport = dport = "?"
            f.write(f"{ts}  {proto}  {src}:{sport} -> {dst}:{dport}\n")
            f.flush()

def make_test_packets():
    """Return a short list of synthetic packets (IPv4 TCP/UDP)."""
    return [
        IP(src="192.168.1.1",   dst="192.168.1.2") / TCP(sport=1234, dport=80,  flags="A"),
        IP(src="192.168.1.3",   dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),
        IP(src="10.0.0.1",      dst="192.168.1.2") / TCP(sport=5678, dport=80,  flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22,  flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / UDP(sport=5555, dport=53),
    ]

def build_packet_capture():
    """
    Build PacketCapture in a way that's compatible with both versions:
    - If your class supports enable_sniffer, we pass enable_sniffer=False.
    - Otherwise, we instantiate without it and later neutralize _sniffer.
    """
    kwargs = dict(interface="lo", bpf_filter="tcp or udp", pcap_dir=PCAP_DIR, rotate_sec=60)
    try:
        # Try clean simulated mode if supported
        return PacketCapture(enable_sniffer=False, **kwargs)
    except TypeError:
        # Fallback for older versions without the flag
        return PacketCapture(**kwargs)

def main():
    pc = build_packet_capture()
    stop_event = threading.Event()

    # Start the consumer logger thread
    t = threading.Thread(target=packet_logger, args=(pc, stop_event, os.path.join(LOG_DIR, "packets.log")), daemon=True)
    t.start()

    # Start PacketCapture (creates writer/rotation etc.)
    pc.start()
    print("PacketCapture started (simulated test). Injecting synthetic packets...")

    # Inject synthetic packets by calling the _on_packet handler directly
    for pkt in make_test_packets():
        pc._on_packet(pkt)      # simulate sniffer callback
        time.sleep(0.15)

    # allow consumer to drain queue
    time.sleep(1.0)

    # print stats
    print("Stats:", pc.stats())

    # ---- Windows/Npcap-safe shutdown ----
    # If the class doesn't support simulated mode, ensure no attempt is made to stop a non-running sniffer
    if hasattr(pc, "_sniffer"):
        pc._sniffer = None  # neutralize to avoid Scapy stop errors on Windows when service isn't running

    # stop everything
    try:
        pc.stop()
    finally:
        stop_event.set()
        t.join(timeout=1.0)

    print("Simulated test finished. Check logs/packets.log and pcaps/ for outputs.")

if __name__ == "__main__":
    main()

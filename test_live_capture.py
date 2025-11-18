# test_live_capture.py
import time, json
import scapy.all
from scapy.all import IP, IPv6, TCP, UDP
from packet_capture_v1 import PacketCapture  # your v1

#setting which interface to sniff 
IFACE = "Intel(R) I211 Gigabit Network Connection"   # Linux: eth0/wlan0/lo ; macOS: en0/lo0
LOG_PATH = "packets_live.jsonl" #where we gonna save the json file log of the packet 

#sumarrize one Scapy packet into a small JSON serializable dict 
def pkt_meta(p):
    d = {"ts": float(getattr(p, "time", time.time())), "len": int(len(p))}
    if IP in p:    d.update(l3="IPv4", src=p[IP].src,  dst=p[IP].dst)
    elif IPv6 in p:d.update(l3="IPv6", src=p[IPv6].src, dst=p[IPv6].dst)
    if TCP in p:   d.update(l4="TCP", sport=int(p[TCP].sport), dport=int(p[TCP].dport), flags=int(p[TCP].flags))
    elif UDP in p: d.update(l4="UDP", sport=int(p[UDP].sport), dport=int(p[UDP].dport))
    return d

pc = PacketCapture(
    interface=IFACE,
    bpf_filter="tcp or udp", #only capture tcp/udp 
    pcap_dir=None)#dont write to .pcap file 

pc.start() #start AsyncSniffer in the background 
print(f"[+] capturing on {IFACE} for 15s… try in another terminal:\n"
      f"    curl http://example.com\n    dig openai.com\n    ssh localhost (then exit)")

out = open(LOG_PATH, "w", encoding="utf-8")
t0 = time.time()
n = 0
try:
    while time.time() - t0 < 15:
        pkt = pc.get_packet(timeout=0.5)
        if not pkt: 
            continue
        json.dump(pkt_meta(pkt), out); out.write("\n")
        n += 1
finally:
    pc.stop(); out.close()

print("[+] stats:", pc.stats())
print(f"[+] wrote {n} packet summaries to {LOG_PATH}")

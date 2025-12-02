#!/usr/bin/env python3
"""
pcap2csv_simple.py — PCAP -> UNSW-NB15-style flow CSV

- Uses dpkt (no NFStream, no pandas)
- Builds bidirectional flows (5-tuple canonicalized)
- Derives a subset of UNSW-NB15 flow features and fills the rest with 0

Usage:
  python pcap2csv_simple.py input.pcap out_unsw.csv
"""

import sys, csv, math, socket
from dataclasses import dataclass, field
from collections import defaultdict

try:
    import dpkt
except Exception:
    print("Missing dependency: dpkt. Install with: pip install dpkt", file=sys.stderr)
    sys.exit(1)


# ---------- Utils ----------

def inet_to_str(addr_bytes):
    """Bytes -> dotted (v4) or compressed (v6) string."""
    if len(addr_bytes) == 4:
        return socket.inet_ntop(socket.AF_INET, addr_bytes)
    elif len(addr_bytes) == 16:
        return socket.inet_ntop(socket.AF_INET6, addr_bytes)
    return "0.0.0.0"


class OnlineStats:
    """Welford online mean/std for numeric streams."""
    __slots__ = ("n", "mean", "M2")
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0
    def add(self, x: float):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.M2 += delta * (x - self.mean)
    def get_mean(self) -> float:
        return self.mean if self.n > 0 else 0.0
    def get_std(self) -> float:
        return math.sqrt(self.M2 / (self.n - 1)) if self.n > 1 else 0.0


# ---------- Flow structure ----------

@dataclass
class Flow:
    proto: int
    fwd_ip: str
    fwd_port: int
    bwd_ip: str
    bwd_port: int
    start_ts: float
    end_ts: float

    # counters
    fwd_pkts: int = 0
    bwd_pkts: int = 0
    fwd_bytes: int = 0
    bwd_bytes: int = 0

    # pkt length stats
    fwd_len: OnlineStats = field(default_factory=OnlineStats)
    bwd_len: OnlineStats = field(default_factory=OnlineStats)
    all_len: OnlineStats = field(default_factory=OnlineStats)

    # IAT stats (ms)
    fwd_last_ts: float | None = None
    bwd_last_ts: float | None = None
    all_last_ts: float | None = None
    fwd_iat: OnlineStats = field(default_factory=OnlineStats)
    bwd_iat: OnlineStats = field(default_factory=OnlineStats)
    all_iat: OnlineStats = field(default_factory=OnlineStats)

    # Per-direction TTL stats (for sttl/dttl)
    fwd_ttl: OnlineStats = field(default_factory=OnlineStats)
    bwd_ttl: OnlineStats = field(default_factory=OnlineStats)

    # TCP flags (counts)
    fwd_syn: int = 0; fwd_ack: int = 0; fwd_fin: int = 0; fwd_rst: int = 0
    bwd_syn: int = 0; bwd_ack: int = 0; bwd_fin: int = 0; bwd_rst: int = 0

    # (Optional: could track TCP window, seq, etc. for swin/dwin/stcpb/dtcpb)

    def update(self, ts: float, src_ip: str, sport: int,
               dst_ip: str, dport: int, ip_len: int,
               tcp_flags: int | None, ttl: int):
        """Update flow stats with one packet."""
        self.end_ts = ts
        is_fwd = (src_ip == self.fwd_ip and sport == self.fwd_port
                  and dst_ip == self.bwd_ip and dport == self.bwd_port)

        # direction
        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += ip_len
            self.fwd_len.add(ip_len)
            self.fwd_ttl.add(ttl)
            if self.fwd_last_ts is not None:
                self.fwd_iat.add((ts - self.fwd_last_ts) * 1000.0)
            self.fwd_last_ts = ts
            if tcp_flags is not None:
                if tcp_flags & 0x02: self.fwd_syn += 1   # SYN
                if tcp_flags & 0x10: self.fwd_ack += 1   # ACK
                if tcp_flags & 0x01: self.fwd_fin += 1   # FIN
                if tcp_flags & 0x04: self.fwd_rst += 1   # RST
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += ip_len
            self.bwd_len.add(ip_len)
            self.bwd_ttl.add(ttl)
            if self.bwd_last_ts is not None:
                self.bwd_iat.add((ts - self.bwd_last_ts) * 1000.0)
            self.bwd_last_ts = ts
            if tcp_flags is not None:
                if tcp_flags & 0x02: self.bwd_syn += 1
                if tcp_flags & 0x10: self.bwd_ack += 1
                if tcp_flags & 0x01: self.bwd_fin += 1
                if tcp_flags & 0x04: self.bwd_rst += 1

        # overall
        self.all_len.add(ip_len)
        if self.all_last_ts is not None:
            self.all_iat.add((ts - self.all_last_ts) * 1000.0)
        self.all_last_ts = ts


def flow_key(proto: int, a_ip: str, a_p: int, b_ip: str, b_p: int):
    """Canonicalize 5-tuple so both directions map to same key."""
    left = (a_ip, a_p, b_ip, b_p)
    right = (b_ip, b_p, a_ip, a_p)
    return (proto, left) if left <= right else (proto, right)


def decode_packet(buf: bytes):
    """
    Return tuple:
      (proto_num, src_ip, sport, dst_ip, dport, ip_total_len, tcp_flags|None, ttl)
    or None if unsupported.
    """
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        # IPv4
        if isinstance(ip, dpkt.ip.IP):
            proto = ip.p
            src, dst = inet_to_str(ip.src), inet_to_str(ip.dst)
            ip_len = int(ip.len)
            ttl = int(ip.ttl)
            if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                return (6, src, tcp.sport, dst, tcp.dport, ip_len, tcp.flags, ttl)
            if proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                return (17, src, udp.sport, dst, udp.dport, ip_len, None, ttl)
            return None
        # IPv6
        if isinstance(ip, dpkt.ip6.IP6):
            nxt = ip.nxt
            src, dst = inet_to_str(ip.src), inet_to_str(ip.dst)
            ip_len = len(bytes(ip))
            ttl = int(ip.hlim)  # hop limit
            l4 = ip.data
            if nxt == dpkt.ip.IP_PROTO_TCP and isinstance(l4, dpkt.tcp.TCP):
                return (6, src, l4.sport, dst, l4.dport, ip_len, l4.flags, ttl)
            if nxt == dpkt.ip.IP_PROTO_UDP and isinstance(l4, dpkt.udp.UDP):
                return (17, src, l4.sport, dst, l4.dport, ip_len, None, ttl)
            return None
        return None
    except Exception:
        return None


# ---------- UNSW helpers ----------

PORT_SERVICE_MAP = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    8080: "http-alt",
}

def guess_service(sport, dport, proto_name: str):
    # UNSW uses 'service' as basic application label
    for p in (dport, sport):
        if p in PORT_SERVICE_MAP:
            return PORT_SERVICE_MAP[p]
    if proto_name == "tcp":
        return "other"
    if proto_name == "udp":
        return "other"
    return "unknown"


def proto_to_name(proto_num: int) -> str:
    if proto_num == 6:
        return "tcp"
    if proto_num == 17:
        return "udp"
    return str(proto_num)


def infer_state(flow: Flow) -> str:
    """
    Rough TCP 'state' approximation like UNSW's 'state' feature.
    Very simplified: looks at SYN/FIN/RST presence.
    """
    # Combine flags from both directions
    syn = flow.fwd_syn + flow.bwd_syn
    fin = flow.fwd_fin + flow.bwd_fin
    rst = flow.fwd_rst + flow.bwd_rst

    if flow.proto != 6:  # non-TCP
        return "CON"    # generic connected

    if rst > 0 and syn == 0:
        return "RST"
    if syn > 0 and fin > 0:
        return "SF"
    if syn > 0 and fin == 0 and rst == 0:
        return "S0"
    return "OTH"


UNSW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto",
    "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss",
    "service", "Sload", "Dload",
    "Spkts", "Dpkts",
    "swin", "dwin", "stcpb", "dtcpb",
    "smeans", "dmeans",
    "trans_depth", "res_bdy_len",
    "Sjit", "Djit", "Sintpkt", "Dintpkt",
    "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports",
    "ct_state_ttl", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "ct_ftp_cmd", "is_ftp_login",
    "attack_cat", "label",
]


def flows_to_unsw_rows(flows: dict):
    """Convert Flow objects -> UNSW-NB15-style dict rows."""
    rows = []

    for fl in flows.values():
        dur = max(fl.end_ts - fl.start_ts, 0.0)
        sbytes = fl.fwd_bytes
        dbytes = fl.bwd_bytes
        Spkts = fl.fwd_pkts
        Dpkts = fl.bwd_pkts

        sttl = int(fl.fwd_ttl.get_mean()) if fl.fwd_ttl.n > 0 else 0
        dttl = int(fl.bwd_ttl.get_mean()) if fl.bwd_ttl.n > 0 else 0

        smeans = fl.fwd_len.get_mean()
        dmeans = fl.bwd_len.get_mean()

        if dur > 0:
            Sload = sbytes / dur
            Dload = dbytes / dur
        else:
            Sload = 0.0
            Dload = 0.0

        Sintpkt = fl.fwd_iat.get_mean()
        Dintpkt = fl.bwd_iat.get_mean()
        Sjit = fl.fwd_iat.get_std()
        Djit = fl.bwd_iat.get_std()

        proto_name = proto_to_name(fl.proto)
        state = infer_state(fl)
        service = guess_service(fl.fwd_port, fl.bwd_port, proto_name)

        is_sm_ips_ports = int(fl.fwd_ip == fl.bwd_ip and fl.fwd_port == fl.bwd_port)

        # Placeholders for advanced stuff we don't compute (yet)
        sloss = 0
        dloss = 0
        swin = 0
        dwin = 0
        stcpb = 0
        dtcpb = 0
        trans_depth = 0
        res_bdy_len = 0
        tcprtt = 0.0
        synack = 0.0
        ackdat = 0.0
        ct_state_ttl = 0
        ct_flw_http_mthd = 0
        ct_src_ltm = 0
        ct_dst_ltm = 0
        ct_src_dport_ltm = 0
        ct_dst_sport_ltm = 0
        ct_dst_src_ltm = 0
        ct_ftp_cmd = 0
        is_ftp_login = 0

        row = {
            "srcip": fl.fwd_ip,
            "sport": fl.fwd_port,
            "dstip": fl.bwd_ip,
            "dsport": fl.bwd_port,
            "proto": proto_name,

            "state": state,
            "dur": dur,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "sttl": sttl,
            "dttl": dttl,
            "sloss": sloss,
            "dloss": dloss,
            "service": service,
            "Sload": Sload,
            "Dload": Dload,
            "Spkts": Spkts,
            "Dpkts": Dpkts,
            "swin": swin,
            "dwin": dwin,
            "stcpb": stcpb,
            "dtcpb": dtcpb,
            "smeans": smeans,
            "dmeans": dmeans,
            "trans_depth": trans_depth,
            "res_bdy_len": res_bdy_len,
            "Sjit": Sjit,
            "Djit": Djit,
            "Sintpkt": Sintpkt,
            "Dintpkt": Dintpkt,
            "tcprtt": tcprtt,
            "synack": synack,
            "ackdat": ackdat,
            "is_sm_ips_ports": is_sm_ips_ports,
            "ct_state_ttl": ct_state_ttl,
            "ct_flw_http_mthd": ct_flw_http_mthd,
            "ct_src_ltm": ct_src_ltm,
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_dport_ltm": ct_src_dport_ltm,
            "ct_dst_sport_ltm": ct_dst_sport_ltm,
            "ct_dst_src_ltm": ct_dst_src_ltm,
            "ct_ftp_cmd": ct_ftp_cmd,
            "is_ftp_login": is_ftp_login,
            "attack_cat": "Normal",
            "label": 0,
        }
        rows.append(row)

    return rows


def write_unsw_csv(flows: dict, path: str):
    rows = flows_to_unsw_rows(flows)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=UNSW_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(r)


# ---------- Main ----------

def main():
    if len(sys.argv) < 3:
        print("Usage: python pcap2csv_simple.py input.pcap out_unsw.csv")
        sys.exit(2)

    in_pcap, out_csv = sys.argv[1], sys.argv[2]
    flows: dict[tuple, Flow] = {}

    with open(in_pcap, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            decoded = decode_packet(buf)
            if not decoded:
                continue
            proto, src_ip, sport, dst_ip, dport, ip_len, tcp_flags, ttl = decoded
            k = flow_key(proto, src_ip, sport, dst_ip, dport)
            if k not in flows:
                flows[k] = Flow(proto, src_ip, sport, dst_ip, dport, ts, ts)
            flows[k].update(ts, src_ip, sport, dst_ip, dport, ip_len, tcp_flags, ttl)

    write_unsw_csv(flows, out_csv)
    print(f"[+] Wrote {len(flows)} flows → {out_csv} (UNSW-style)")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
pcap2csv.py — Convert PCAP -> CSV with flow features for ML training.

Profiles:
  - wide    : rich, model-friendly features (default)
  - cic     : CICIDS-like columns (subset/approximation)
  - unsw    : UNSW-NB15-like columns (subset/approximation)

Usage:
  python pcap2csv.py input.pcap -o out.csv --profile wide
"""

import argparse
import math
import sys
from datetime import datetime, timezone

import pandas as pd

try:
    from nfstream import NFStreamer
except ImportError:
    print("Missing dependency: nfstream. Install with: pip install nfstream pandas", file=sys.stderr)
    sys.exit(1)


def _safe_div(a, b):
    try:
        return float(a) / float(b) if b not in (0, 0.0, None) else 0.0
    except Exception:
        return 0.0


def _to_utc_ms(dt):
    # NFStream gives Python datetime objects (naive UTC). Normalize to epoch ms.
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def compute_wide_features(df: pd.DataFrame) -> pd.DataFrame:
    """A rich set of features good for general ML models."""
    # Basic renames for readability
    base = pd.DataFrame({
        "flow_id": df["id"],
        "src_ip": df["src_ip"], "src_port": df["src_port"],
        "dst_ip": df["dst_ip"], "dst_port": df["dst_port"],
        "protocol": df["protocol"],
        "start_ms": df["start"].apply(_to_utc_ms),
        "end_ms": df["end"].apply(_to_utc_ms),
        "flow_duration_ms": (df["end"] - df["start"]).dt.total_seconds() * 1000.0,
        "fwd_pkts": df["src2dst_packets"], "bwd_pkts": df["dst2src_packets"],
        "fwd_bytes": df["src2dst_bytes"], "bwd_bytes": df["dst2src_bytes"],
        "fwd_psh": df.get("src2dst_psh_flags", 0), "bwd_psh": df.get("dst2src_psh_flags", 0),
        "fwd_urg": df.get("src2dst_urg_flags", 0), "bwd_urg": df.get("dst2src_urg_flags", 0),
        "fwd_rst": df.get("src2dst_rst_flags", 0), "bwd_rst": df.get("dst2src_rst_flags", 0),
        "fwd_ack": df.get("src2dst_ack_flags", 0), "bwd_ack": df.get("dst2src_ack_flags", 0),
        "fwd_syn": df.get("src2dst_syn_flags", 0), "bwd_syn": df.get("dst2src_syn_flags", 0),
        "fwd_fin": df.get("src2dst_fin_flags", 0), "bwd_fin": df.get("dst2src_fin_flags", 0),
        "app_name": df.get("application_name", None),
    })

    # Totals & ratios
    base["tot_pkts"] = base["fwd_pkts"] + base["bwd_pkts"]
    base["tot_bytes"] = base["fwd_bytes"] + base["bwd_bytes"]
    base["pkt_per_ms"] = base.apply(lambda r: _safe_div(r["tot_pkts"], r["flow_duration_ms"]), axis=1)
    base["byte_per_ms"] = base.apply(lambda r: _safe_div(r["tot_bytes"], r["flow_duration_ms"]), axis=1)
    base["bwd_to_fwd_pkt_ratio"] = base.apply(lambda r: _safe_div(r["bwd_pkts"], r["fwd_pkts"]), axis=1)
    base["bwd_to_fwd_byte_ratio"] = base.apply(lambda r: _safe_div(r["bwd_bytes"], r["fwd_bytes"]), axis=1)

    # Packet length stats if available (NFStream statistical_analysis=True)
    # Fall back to simple derived values otherwise
    def get_or_zero(name): return df[name] if name in df.columns else 0

    derived = pd.DataFrame({
        "fwd_pkt_len_min": get_or_zero("src2dst_min_ps"),
        "fwd_pkt_len_max": get_or_zero("src2dst_max_ps"),
        "fwd_pkt_len_mean": get_or_zero("src2dst_mean_ps"),
        "fwd_pkt_len_std": get_or_zero("src2dst_stddev_ps"),
        "bwd_pkt_len_min": get_or_zero("dst2src_min_ps"),
        "bwd_pkt_len_max": get_or_zero("dst2src_max_ps"),
        "bwd_pkt_len_mean": get_or_zero("dst2src_mean_ps"),
        "bwd_pkt_len_std": get_or_zero("dst2src_stddev_ps"),
        "iat_fwd_mean_ms": get_or_zero("src2dst_avg_iat"),
        "iat_bwd_mean_ms": get_or_zero("dst2src_avg_iat"),
        "iat_flow_mean_ms": get_or_zero("flow_avg_iat"),
        "iat_flow_std_ms": get_or_zero("flow_stddev_iat"),
    })

    # Throughputs (pps/bps)
    base["pps"] = base.apply(lambda r: _safe_div(r["tot_pkts"], r["flow_duration_ms"] / 1000.0), axis=1)
    base["bps"] = base.apply(lambda r: _safe_div(r["tot_bytes"] * 8.0, r["flow_duration_ms"] / 1000.0), axis=1)

    return pd.concat([base, derived], axis=1)


def compute_cic_like(df: pd.DataFrame) -> pd.DataFrame:
    """CICIDS-style subset/approximation."""
    duration_ms = (df["end"] - df["start"]).dt.total_seconds() * 1000.0
    out = pd.DataFrame({
        "Flow ID": df["id"],
        "Src IP": df["src_ip"], "Src Port": df["src_port"],
        "Dst IP": df["dst_ip"], "Dst Port": df["dst_port"],
        "Protocol": df["protocol"],
        "Timestamp": df["start"].apply(_to_utc_ms),
        "Flow Duration": duration_ms,
        "Total Fwd Packets": df["src2dst_packets"],
        "Total Backward Packets": df["dst2src_packets"],
        "Total Length of Fwd Packets": df["src2dst_bytes"],
        "Total Length of Bwd Packets": df["dst2src_bytes"],
        "Fwd Packet Length Mean": df.get("src2dst_mean_ps", 0),
        "Bwd Packet Length Mean": df.get("dst2src_mean_ps", 0),
        "Flow IAT Mean": df.get("flow_avg_iat", 0),
        "Fwd IAT Mean": df.get("src2dst_avg_iat", 0),
        "Bwd IAT Mean": df.get("dst2src_avg_iat", 0),
        "Fwd PSH Flags": df.get("src2dst_psh_flags", 0),
        "Bwd PSH Flags": df.get("dst2src_psh_flags", 0),
        "Fwd URG Flags": df.get("src2dst_urg_flags", 0),
        "Bwd URG Flags": df.get("dst2src_urg_flags", 0),
        "Bwd Packets/s": df.apply(
            lambda r: _safe_div(r["dst2src_packets"], (r["end"] - r["start"]).total_seconds()), axis=1
        ),
        "Min Packet Length": df.get("flow_min_ps", 0),
        "Max Packet Length": df.get("flow_max_ps", 0),
        "Packet Length Mean": df.get("flow_mean_ps", 0),
        "Packet Length Std": df.get("flow_stddev_ps", 0),
    })
    return out


def compute_unsw_like(df: pd.DataFrame) -> pd.DataFrame:
    """UNSW-NB15-style subset/approximation (Argus-inspired fields)."""
    flow_duration_ms = (df["end"] - df["start"]).dt.total_seconds() * 1000.0
    out = pd.DataFrame({
        "stime_ms": df["start"].apply(_to_utc_ms),
        "ltime_ms": df["end"].apply(_to_utc_ms),
        "dur_ms": flow_duration_ms,
        "proto": df["protocol"],
        "saddr": df["src_ip"], "sport": df["src_port"],
        "daddr": df["dst_ip"], "dport": df["dst_port"],
        "spkts": df["src2dst_packets"], "dpkts": df["dst2src_packets"],
        "sbytes": df["src2dst_bytes"], "dbytes": df["dst2src_bytes"],
        "rate_pps": (df["src2dst_packets"] + df["dst2src_packets"]) / (flow_duration_ms / 1000.0).replace(0, math.nan),
        "smean": df.get("src2dst_mean_ps", 0),
        "dmean": df.get("dst2src_mean_ps", 0),
        "stddev_pktlen": df.get("flow_stddev_ps", 0),
        "min_ps": df.get("flow_min_ps", 0),
        "max_ps": df.get("flow_max_ps", 0),
        "state_syn": df.get("src2dst_syn_flags", 0) + df.get("dst2src_syn_flags", 0),
        "state_ack": df.get("src2dst_ack_flags", 0) + df.get("dst2src_ack_flags", 0),
        "state_fin": df.get("src2dst_fin_flags", 0) + df.get("dst2src_fin_flags", 0),
        "state_rst": df.get("src2dst_rst_flags", 0) + df.get("dst2src_rst_flags", 0),
        # You can add TTL-like proxies if captured (not always available from NFStream).
    })
    # Clean inf/nan from rate_pps
    out["rate_pps"] = out["rate_pps"].replace([math.inf, -math.inf], 0).fillna(0)
    return out


def build_parser():
    p = argparse.ArgumentParser(description="Convert PCAP to CSV flow features.")
    p.add_argument("pcap", help="Path to input .pcap / .pcapng")
    p.add_argument("-o", "--out", default="flows.csv", help="Output CSV path")
    p.add_argument("--profile", choices=["wide", "cic", "unsw"], default="wide",
                   help="Feature profile to export")
    p.add_argument("--max-flows", type=int, default=None,
                   help="Optional cap on number of flows (for quick tests)")
    p.add_argument("--decode-tunnels", action="store_true",
                   help="Enable tunnel decoding (GRE, GTP, etc.)")
    p.add_argument("--bpf", default=None,
                   help="Optional Berkeley Packet Filter (e.g., 'tcp or udp')")
    return p


def main():
    args = build_parser().parse_args()

    streamer = NFStreamer(
        source=args.pcap,
        decode_tunnels=args.decode_tunnels,
        statistical_analysis=True,
        bpf_filter=args.bpf,
    )

    # Convert NFStream flows to dicts, respecting --max-flows if provided
    rows = []
    for i, flow in enumerate(streamer):
        rows.append(flow.to_dict())
        if args.max_flows is not None and (i + 1) >= args.max_flows:
            break

    if not rows:
        print("No flows parsed. Check your pcap path or BPF filter.", file=sys.stderr)
        sys.exit(2)

    df = pd.DataFrame(rows)

    # Convert time-like columns to pandas datetime
    for col in ("start", "end"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], utc=True)

    if args.profile == "wide":
        out = compute_wide_features(df)
    elif args.profile == "cic":
        out = compute_cic_like(df)
    else:
        out = compute_unsw_like(df)

    # Final cleanup: replace NaN/inf with zeros for ML-friendliness
    out = out.replace([math.inf, -math.inf], 0).fillna(0)

    out.to_csv(args.out, index=False)
    print(f"Wrote {len(out):,} flows to {args.out} with profile '{args.profile}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

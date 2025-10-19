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
from datetime import timezone
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
    if dt is None:
        return None
    if getattr(dt, "tzinfo", None) is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _col(df: pd.DataFrame, *names, default=0):
    """Return the first existing column among names; otherwise a scalar default."""
    for n in names:
        if isinstance(n, str) and n in df.columns:
            return df[n]
    return default


def normalize_time_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Ensure df has UTC datetime columns 'start' and 'end'.
    Supports both old ('start'/'end') and new ('*_seen_ms') NFStream schemas.
    """
    if "start" in df.columns and "end" in df.columns:
        df = df.copy()
        df["start"] = pd.to_datetime(df["start"], utc=True)
        df["end"] = pd.to_datetime(df["end"], utc=True)
        return df

    # look for ms epoch columns
    start_ms_col = None
    end_ms_col = None
    for cand in ["bidirectional_first_seen_ms", "first_seen_ms", "flow_start_ms"]:
        if cand in df.columns:
            start_ms_col = cand
            break
    for cand in ["bidirectional_last_seen_ms", "last_seen_ms", "flow_end_ms"]:
        if cand in df.columns:
            end_ms_col = cand
            break

    if start_ms_col and end_ms_col:
        df = df.copy()
        df["start"] = pd.to_datetime(df[start_ms_col], unit="ms", utc=True)
        df["end"] = pd.to_datetime(df[end_ms_col], unit="ms", utc=True)
        return df

    raise KeyError(
        "Could not find time columns. Expected 'start'/'end' or '*_seen_ms'. "
        f"Available columns sample: {list(df.columns)[:40]}"
    )


def compute_wide_features(df: pd.DataFrame) -> pd.DataFrame:
    """A rich set of features good for general ML models."""
    base = pd.DataFrame({
        "flow_id": _col(df, "id", default=None),
        "src_ip": _col(df, "src_ip"),
        "src_port": _col(df, "src_port"),
        "dst_ip": _col(df, "dst_ip"),
        "dst_port": _col(df, "dst_port"),
        "protocol": _col(df, "protocol"),
        "start_ms": df["start"].apply(_to_utc_ms),
        "end_ms": df["end"].apply(_to_utc_ms),
        "flow_duration_ms": (df["end"] - df["start"]).dt.total_seconds() * 1000.0,
        "fwd_pkts": _col(df, "src2dst_packets", "bidirectional_packets_src2dst", default=0),
        "bwd_pkts": _col(df, "dst2src_packets", "bidirectional_packets_dst2src", default=0),
        "fwd_bytes": _col(df, "src2dst_bytes", "bidirectional_bytes_src2dst", default=0),
        "bwd_bytes": _col(df, "dst2src_bytes", "bidirectional_bytes_dst2src", default=0),
        "fwd_psh": _col(df, "src2dst_psh_flags", default=0),
        "bwd_psh": _col(df, "dst2src_psh_flags", default=0),
        "fwd_urg": _col(df, "src2dst_urg_flags", default=0),
        "bwd_urg": _col(df, "dst2src_urg_flags", default=0),
        "fwd_rst": _col(df, "src2dst_rst_flags", default=0),
        "bwd_rst": _col(df, "dst2src_rst_flags", default=0),
        "fwd_ack": _col(df, "src2dst_ack_flags", default=0),
        "bwd_ack": _col(df, "dst2src_ack_flags", default=0),
        "fwd_syn": _col(df, "src2dst_syn_flags", default=0),
        "bwd_syn": _col(df, "dst2src_syn_flags", default=0),
        "fwd_fin": _col(df, "src2dst_fin_flags", default=0),
        "bwd_fin": _col(df, "dst2src_fin_flags", default=0),
        "app_name": _col(df, "application_name", default=None),
    })

    base["tot_pkts"] = base["fwd_pkts"] + base["bwd_pkts"]
    base["tot_bytes"] = base["fwd_bytes"] + base["bwd_bytes"]
    base["pkt_per_ms"] = base.apply(lambda r: _safe_div(r["tot_pkts"], r["flow_duration_ms"]), axis=1)
    base["byte_per_ms"] = base.apply(lambda r: _safe_div(r["tot_bytes"], r["flow_duration_ms"]), axis=1)
    base["bwd_to_fwd_pkt_ratio"] = base.apply(lambda r: _safe_div(r["bwd_pkts"], r["fwd_pkts"]), axis=1)
    base["bwd_to_fwd_byte_ratio"] = base.apply(lambda r: _safe_div(r["bwd_bytes"], r["fwd_bytes"]), axis=1)

    # NFStream naming varies; try both flow_* and bidirectional_* aliases
    derived = pd.DataFrame({
        "fwd_pkt_len_min": _col(df, "src2dst_min_ps", default=0),
        "fwd_pkt_len_max": _col(df, "src2dst_max_ps", default=0),
        "fwd_pkt_len_mean": _col(df, "src2dst_mean_ps", default=0),
        "fwd_pkt_len_std": _col(df, "src2dst_stddev_ps", default=0),
        "bwd_pkt_len_min": _col(df, "dst2src_min_ps", default=0),
        "bwd_pkt_len_max": _col(df, "dst2src_max_ps", default=0),
        "bwd_pkt_len_mean": _col(df, "dst2src_mean_ps", default=0),
        "bwd_pkt_len_std": _col(df, "dst2src_stddev_ps", default=0),

        "iat_fwd_mean_ms": _col(df, "src2dst_avg_iat", default=0),
        "iat_bwd_mean_ms": _col(df, "dst2src_avg_iat", default=0),
        "iat_flow_mean_ms": _col(df, "flow_avg_iat", "bidirectional_avg_iat", default=0),
        "iat_flow_std_ms": _col(df, "flow_stddev_iat", "bidirectional_stddev_iat", default=0),

        # Optional overall packet size stats if present
        "flow_pkt_len_min": _col(df, "flow_min_ps", "bidirectional_min_ps", default=0),
        "flow_pkt_len_max": _col(df, "flow_max_ps", "bidirectional_max_ps", default=0),
        "flow_pkt_len_mean": _col(df, "flow_mean_ps", "bidirectional_mean_ps", default=0),
        "flow_pkt_len_std": _col(df, "flow_stddev_ps", "bidirectional_stddev_ps", default=0),
    })

    base["pps"] = base.apply(lambda r: _safe_div(r["tot_pkts"], r["flow_duration_ms"] / 1000.0), axis=1)
    base["bps"] = base.apply(lambda r: _safe_div(r["tot_bytes"] * 8.0, r["flow_duration_ms"] / 1000.0), axis=1)

    return pd.concat([base, derived], axis=1)


def compute_cic_like(df: pd.DataFrame) -> pd.DataFrame:
    duration_ms = (df["end"] - df["start"]).dt.total_seconds() * 1000.0
    out = pd.DataFrame({
        "Flow ID": _col(df, "id", default=None),
        "Src IP": _col(df, "src_ip"),
        "Src Port": _col(df, "src_port"),
        "Dst IP": _col(df, "dst_ip"),
        "Dst Port": _col(df, "dst_port"),
        "Protocol": _col(df, "protocol"),
        "Timestamp": df["start"].apply(_to_utc_ms),
        "Flow Duration": duration_ms,
        "Total Fwd Packets": _col(df, "src2dst_packets", "bidirectional_packets_src2dst", default=0),
        "Total Backward Packets": _col(df, "dst2src_packets", "bidirectional_packets_dst2src", default=0),
        "Total Length of Fwd Packets": _col(df, "src2dst_bytes", "bidirectional_bytes_src2dst", default=0),
        "Total Length of Bwd Packets": _col(df, "dst2src_bytes", "bidirectional_bytes_dst2src", default=0),
        "Fwd Packet Length Mean": _col(df, "src2dst_mean_ps", default=0),
        "Bwd Packet Length Mean": _col(df, "dst2src_mean_ps", default=0),
        "Flow IAT Mean": _col(df, "flow_avg_iat", "bidirectional_avg_iat", default=0),
        "Fwd IAT Mean": _col(df, "src2dst_avg_iat", default=0),
        "Bwd IAT Mean": _col(df, "dst2src_avg_iat", default=0),
        "Fwd PSH Flags": _col(df, "src2dst_psh_flags", default=0),
        "Bwd PSH Flags": _col(df, "dst2src_psh_flags", default=0),
        "Fwd URG Flags": _col(df, "src2dst_urg_flags", default=0),
        "Bwd URG Flags": _col(df, "dst2src_urg_flags", default=0),
        "Bwd Packets/s": (_col(df, "dst2src_packets", default=0) /
                          ((df["end"] - df["start"]).dt.total_seconds().replace(0, pd.NA))),
        "Min Packet Length": _col(df, "flow_min_ps", "bidirectional_min_ps", default=0),
        "Max Packet Length": _col(df, "flow_max_ps", "bidirectional_max_ps", default=0),
        "Packet Length Mean": _col(df, "flow_mean_ps", "bidirectional_mean_ps", default=0),
        "Packet Length Std": _col(df, "flow_stddev_ps", "bidirectional_stddev_ps", default=0),
    })
    out["Bwd Packets/s"] = out["Bwd Packets/s"].replace([math.inf, -math.inf], 0).fillna(0)
    return out


def compute_unsw_like(df: pd.DataFrame) -> pd.DataFrame:
    flow_duration_ms = (df["end"] - df["start"]).dt.total_seconds() * 1000.0
    out = pd.DataFrame({
        "stime_ms": df["start"].apply(_to_utc_ms),
        "ltime_ms": df["end"].apply(_to_utc_ms),
        "dur_ms": flow_duration_ms,
        "proto": _col(df, "protocol"),
        "saddr": _col(df, "src_ip"), "sport": _col(df, "src_port"),
        "daddr": _col(df, "dst_ip"), "dport": _col(df, "dst_port"),
        "spkts": _col(df, "src2dst_packets", "bidirectional_packets_src2dst", default=0),
        "dpkts": _col(df, "dst2src_packets", "bidirectional_packets_dst2src", default=0),
        "sbytes": _col(df, "src2dst_bytes", "bidirectional_bytes_src2dst", default=0),
        "dbytes": _col(df, "dst2src_bytes", "bidirectional_bytes_dst2src", default=0),
        "rate_pps": (_col(df, "src2dst_packets", default=0) + _col(df, "dst2src_packets", default=0)) /
                    (flow_duration_ms / 1000.0).replace(0, math.nan),
        "smean": _col(df, "src2dst_mean_ps", default=0),
        "dmean": _col(df, "dst2src_mean_ps", default=0),
        "stddev_pktlen": _col(df, "flow_stddev_ps", "bidirectional_stddev_ps", default=0),
        "min_ps": _col(df, "flow_min_ps", "bidirectional_min_ps", default=0),
        "max_ps": _col(df, "flow_max_ps", "bidirectional_max_ps", default=0),
        "state_syn": _col(df, "src2dst_syn_flags", default=0) + _col(df, "dst2src_syn_flags", default=0),
        "state_ack": _col(df, "src2dst_ack_flags", default=0) + _col(df, "dst2src_ack_flags", default=0),
        "state_fin": _col(df, "src2dst_fin_flags", default=0) + _col(df, "dst2src_fin_flags", default=0),
        "state_rst": _col(df, "src2dst_rst_flags", default=0) + _col(df, "dst2src_rst_flags", default=0),
    })
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

    # Robust across NFStream versions
    df = streamer.to_pandas()
    if args.max_flows:
        df = df.head(args.max_flows)

    if df is None or df.empty:
        print("No flows parsed. Check your pcap path or BPF filter.", file=sys.stderr)
        return 2

    # Normalize time columns to 'start'/'end' (UTC datetimes)
    df = normalize_time_columns(df)

    if args.profile == "wide":
        out = compute_wide_features(df)
    elif args.profile == "cic":
        out = compute_cic_like(df)
    else:
        out = compute_unsw_like(df)

    out = out.replace([math.inf, -math.inf], 0).fillna(0)
    out.to_csv(args.out, index=False)
    print(f"Wrote {len(out):,} flows to {args.out} with profile '{args.profile}'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

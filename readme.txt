# 1) Install deps
python -m venv .venv && source .venv/bin/activate
pip install nfstream pandas

# 2) Convert a pcap using the rich "wide" profile (default)
python pcap2csv.py sample.pcap -o flows_wide.csv

# 3) CICIDS-like
python pcap2csv.py sample.pcap -o flows_cic.csv --profile cic

# 4) UNSW-like
python pcap2csv.py sample.pcap -o flows_unsw.csv --profile unsw

# 5) (Optional) Filter traffic or decode tunnels
python pcap2csv.py sample.pcap -o out.csv --bpf "tcp or udp" --decode-tunnels

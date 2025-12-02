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


# Finalize
# 1) Create virtual env
python -m venv .venv

# 2) Install dependencies INTO the venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install numpy pandas scikit-learn xgboost joblib

# 3) Converting PCAP to CSV (UNSW-style CSV)
.\.venv\Scripts\python.exe pcap2csv_simple_with_flow.py <input>.pcap <input>_unsw.csv

Input: dhcp.pcap 
Output: dhcp_unsw.csv
.\.venv\Scripts\python.exe pcap2csv_simple_with_flow.py dhcp.pcap dhcp_unsw.csv

# 4) Run XGB model on the CSV → predictions
.\.venv\Scripts\python.exe run_xgb_on_pcapcsv.py <input>_unsw.csv

.\.venv\Scripts\python.exe run_xgb_on_pcapcsv.py dhcp_unsw.csv

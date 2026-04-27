from scapy.all import rdpcap, IP, TCP, UDP, Raw
import pandas as pd
import numpy as np
import os

pcap_file = "traffic.pcap"

if not os.path.exists(pcap_file):
    print("PCAP file not found:", pcap_file)
    exit()

print("PCAP file found")

packets = rdpcap(pcap_file)
print("Total packets loaded:", len(packets))

features = []

for pkt in packets:
    if IP in pkt:

        length = len(pkt)
        protocol = pkt[IP].proto
        ttl = pkt[IP].ttl

        src_port = 0
        dst_port = 0
        flags = 0

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        payload_size = 0
        entropy = 0

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            payload_size = len(payload)

            if payload_size > 0:
                probs = [payload.count(b)/payload_size for b in set(payload)]
                entropy = -sum(p*np.log2(p) for p in probs)

        label = "BENIGN"
        if dst_port in [22, 23]:
            label = "SUSPICIOUS"

        features.append([
            length, protocol, ttl,
            src_port, dst_port,
            int(flags),
            payload_size, entropy,
            label
        ])

columns = [
    "length", "protocol", "ttl",
    "src_port", "dst_port",
    "tcp_flags",
    "payload_size", "entropy",
    "label"
]

df = pd.DataFrame(features, columns=columns)

print("Rows extracted:", len(df))

if len(df) > 0:
    output_file = "dataset.csv"
    output_path = os.path.join(os.getcwd(), output_file)
    df.to_csv(output_path, index=False)
    print("Dataset created successfully")
    print("File name:", output_file)
    print("Saved at:", output_path)
else:
    print("No data extracted. Check your capture file.")
from scapy.all import sniff, IP, TCP, UDP, Raw
import numpy as np
import joblib
import pandas as pd 

model = joblib.load("model.pkl")

def extract(pkt):

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

        features = pd.DataFrame([[
            length, protocol, ttl,
            src_port, dst_port,
            int(flags),
            payload_size, entropy
            ]], columns=[
                "length","protocol","ttl",
                "src_port","dst_port",
                "tcp_flags",
                "payload_size","entropy"
                ]
                )

        prediction = model.predict(features)[0]

        print("Traffic:", prediction)

print("Live detection started...")

sniff(prn=extract, store=False)
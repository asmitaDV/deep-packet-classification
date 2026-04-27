import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="Cyber IDS Dashboard", layout="wide")

st.title("Intelligent Network Intrusion Detection using Packet Classification & Deep Packet Inspection")

df = pd.read_csv("dataset.csv")

protocol_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP"
}

df["protocol_name"] = df["protocol"].map(protocol_map).fillna(df["protocol"].astype(str))

total_packets = len(df)
malicious_count = (df["label"] != "BENIGN").sum()
benign_count = (df["label"] == "BENIGN").sum()
protocol_count = df["protocol_name"].nunique()

threat_percent = (malicious_count / total_packets) * 100 if total_packets > 0 else 0

protocol_counts = df["protocol_name"].value_counts()
label_counts = df["label"].value_counts()

st.markdown("## Threat Overview")

c1, c2, c3, c4 = st.columns(4)

c1.metric("Total Packets", total_packets)
c2.metric("Benign Traffic", benign_count)
c3.metric("Malicious Traffic", malicious_count)
c4.metric("Threat Percentage", f"{threat_percent:.2f}%")

st.markdown("---")

left, right = st.columns(2)

with left:
    st.subheader("Protocol Distribution")
    fig1 = plt.figure()
    plt.bar(protocol_counts.index, protocol_counts.values)
    plt.xticks(rotation=45)
    plt.title("Protocol Usage")
    st.pyplot(fig1)

    st.subheader("Packet Size Distribution")
    fig2 = plt.figure()
    plt.hist(df["length"], bins=40)
    plt.title("Packet Length")
    st.pyplot(fig2)

with right:
    st.subheader("Traffic Classification")
    fig3 = plt.figure()
    plt.bar(label_counts.index, label_counts.values)
    plt.title("Malicious vs Benign")
    st.pyplot(fig3)

    if "payload_size" in df.columns:
        st.subheader("Payload Size Distribution")
        fig4 = plt.figure()
        plt.hist(df["payload_size"], bins=40)
        plt.title("Payload Size")
        st.pyplot(fig4)

st.markdown("---")

st.subheader("Deep Packet Inspection Metrics")

if "entropy" in df.columns:
    fig5 = plt.figure()
    plt.hist(df["entropy"], bins=40)
    plt.title("Payload Entropy")
    st.pyplot(fig5)

st.markdown("---")

st.subheader("Packet Dataset Preview")
st.dataframe(df, use_container_width=True)
from scapy.all import rdpcap, sendp

packets = rdpcap(r"C:\Users\anura\Downloads\4.pcap")
sendp(packets, iface="Ethernet 4")
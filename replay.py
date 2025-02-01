from scapy.all import rdpcap, sendp

packets = rdpcap(r"4.pcap")
sendp(packets, iface="Ethernet 5",inter=0.01)
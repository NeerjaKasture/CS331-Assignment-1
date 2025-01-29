from scapy.all import PcapReader, TCP

def extract_hidden_message(pcap_file):
    packets = PcapReader(pcap_file)  
    hidden_message=[]
    checksum=[]
    count = 0
    
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.sport == 1579 and tcp_layer.payload:
                payload = bytes(tcp_layer.payload).decode(errors='ignore')
                if "CS331" in payload:
                    # if not hidden_message:
                    hidden_message.append(payload)
                    checksum.append(tcp_layer.chksum)  
                    count += 1
    
    return hidden_message, count, checksum

pcap_file = "4.pcap"  
hidden_message, total_packets, checksum = extract_hidden_message(pcap_file)

if hidden_message:
    print(f"Extracted Hidden Message: {hidden_message[0]}")
    print(f"TCP Checksum: {checksum}")
print(f"Total packets containing the hidden message: {total_packets}")

#Output
# Extracted Hidden Message: Welcome to Computer Networks CS331
# TCP Checksum: [547, 755, 908, 703, 958, 599, 651, 858, 443, 807, 495]
# Total packets containing the hidden message: 11
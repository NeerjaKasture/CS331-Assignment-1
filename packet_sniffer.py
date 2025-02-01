
import socket
import time
import dpkt
import struct
import select
import matplotlib.pyplot as plt
from collections import defaultdict
from scapy.all import PcapReader, TCP

def raw_packet_sniffer(interface="eth0", capture_file="capture.pcap", inactivity_timeout=100):
    print(f"[*] Waiting for traffic on {interface}...")

    # Open raw socket (captures all protocols)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.bind((interface, 0))
    # We'll use select to wait with a timeout rather than settimeout on the socket.

    # Open a pcap file to save captured packets
    pcap_writer = dpkt.pcap.Writer(open(capture_file, "wb"))

    # Packet statistics
    packet_count = 0
    total_bytes = 0
    min_size = float("inf")
    max_size = 0
    packet_sizes = []  # For histogram

    # Flow tracking
    unique_flows = set()
    src_ip_flows = defaultdict(int)
    dst_ip_flows = defaultdict(int)
    data_transfers = defaultdict(int)  # flow -> total bytes transferred

    start_time = None  # When the first packet arrives
    last_packet_time = None

    try:
        while True:
            # Use select to wait for data with a timeout.
            ready, _, _ = select.select([sock], [], [], inactivity_timeout)
            if ready:
                # There is data ready to be read.
                raw_packet, addr = sock.recvfrom(65535)
                pcap_writer.writepkt(raw_packet, ts=time.time())

                packet_size = len(raw_packet)
                packet_count += 1
                total_bytes += packet_size
                min_size = min(min_size, packet_size)
                max_size = max(max_size, packet_size)
                packet_sizes.append(packet_size)

                # Set start_time when the first packet is received.
                if start_time is None:
                    start_time = time.time()
                    print("[*] Traffic detected! Starting capture...")

                # Update last_packet_time on each received packet.
                last_packet_time = time.time()
                print(f"[Packet {packet_count}] Captured {packet_size} bytes")

                # Process the packet (Ethernet frame)
                if len(raw_packet) < 14:
                    continue  # Too short for an Ethernet header

                eth_header = raw_packet[:14]
                eth = struct.unpack("!6s6sH", eth_header)
                eth_protocol = eth[2]

                # Only process IPv4 packets
                if eth_protocol == 0x0800:
                    ip_packet = raw_packet[14:]
                    if len(ip_packet) < 20:
                        continue  # Not a valid IP header
                    ip_header = struct.unpack("!BBHHHBBH4s4s", ip_packet[:20])
                    protocol = ip_header[6]
                    src_ip = socket.inet_ntoa(ip_header[8])
                    dst_ip = socket.inet_ntoa(ip_header[9])

                    # Process TCP (protocol 6) or UDP (protocol 17) packets.
                    if protocol in (6, 17) and len(ip_packet) >= 24:
                        # Get ports from the next 4 bytes after the IP header.
                        src_port, dst_port = struct.unpack("!HH", ip_packet[20:24])
                        flow = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                        unique_flows.add(flow)
                        src_ip_flows[src_ip] += 1
                        dst_ip_flows[dst_ip] += 1
                        data_transfers[flow] += packet_size
            else:
                # No data was available within the inactivity_timeout period.
                if start_time is not None and last_packet_time is not None:
                    print("[*] No packets received for 100 seconds. Stopping capture...")
                    break
                # If start_time is still None, we haven't seen any traffic yet.
                # In that case, just continue waiting.
                
    except KeyboardInterrupt:
        print("[*] Interrupted by user!")
    finally:
        # Compute capture statistics.
        duration = (time.time() - start_time) if start_time else 0
        avg_size = total_bytes / packet_count if packet_count > 0 else 0
        pps = packet_count / duration if duration > 0 else 0
        mbps = (total_bytes * 8) / (duration * 1e6) if duration > 0 else 0

        print("\n--- Sniffing Summary ---")
        print(f"Total Packets Captured: {packet_count}")
        print(f"Total Data Transferred: {total_bytes} bytes")
        print(f"Minimum Packet Size: {min_size} bytes")
        print(f"Maximum Packet Size: {max_size} bytes")
        print(f"Average Packet Size: {avg_size:.2f} bytes")
        print(f"Capture Duration: {duration:.2f} seconds")
        print(f"Packets per Second: {pps:.2f} pps")
        print(f"Traffic Rate: {mbps:.2f} Mbps")

        if data_transfers:
            max_transfer_flow = max(data_transfers, key=data_transfers.get)
            print(f"Top Data Transfer: {max_transfer_flow} with {data_transfers[max_transfer_flow]} bytes")

        # Show unique flows and IP flow statistics
        # print("\n--- Unique Source-Destination Flows ---")
        # for flow in unique_flows:
        #     print(flow)

        # print("\n--- Total Flows Per Source IP ---")
        # for ip, count in src_ip_flows.items():
        #     print(f"{ip}: {count} flows")

        # print("\n--- Total Flows Per Destination IP ---")
        # for ip, count in dst_ip_flows.items():
        #     print(f"{ip}: {count} flows")

        # Save flows information to a text file
        with open("flows.txt", "w") as f:
            f.write("--- Total Flows Per Source IP ---\n")
            for ip, count in src_ip_flows.items():
                f.write(f"{ip}: {count} flows\n")
            f.write("\n--- Total Flows Per Destination IP ---\n")
            for ip, count in dst_ip_flows.items():
                f.write(f"{ip}: {count} flows\n")
            f.write("\n--- Unique Source-Destination Flows ---\n")
            for flow in unique_flows:
                f.write(f"{flow}\n")
        print("[*] Flow information saved to flows.txt")

        # Plot histogram of packet sizes.
        plt.figure(figsize=(10, 5))
        plt.hist(packet_sizes, bins=50, color="blue", edgecolor="black")
        plt.xlabel("Packet Size (bytes)")
        plt.ylabel("Frequency")
        plt.title("Packet Size Distribution")
        plt.grid(True)
        plt.savefig("packet_size_distribution.png")  # Saves the plot to a file
        print("[*] Histogram saved as packet_size_distribution.png")

        sock.close()
        print("[*] Sniffing stopped.")

raw_packet_sniffer(interface="eth0")

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


pcap_file = "capture.pcap"  
hidden_message, total_packets, checksum = extract_hidden_message(pcap_file)

if hidden_message:
    print(f"Extracted Hidden Message: {hidden_message[0]}")
    print(f"TCP Checksum: {checksum}")
print(f"Total packets containing the hidden message: {total_packets}")



import threading
import time
from scapy.all import sniff, PcapWriter
import matplotlib.pyplot as plt

stop_sniffing = False  

def packet_callback(packet):
    global packet_count, total_bytes, min_size, max_size, packet_sizes
    if stop_sniffing:  
        return False

    packet_size = len(packet)
    packet_count += 1
    total_bytes += packet_size
    min_size = min(min_size, packet_size)
    max_size = max(max_size, packet_size)
    packet_sizes.append(packet_size)
    pcap_writer.write(packet)
    print(f"[Packet {packet_count}] Captured {packet_size} bytes")


def sniff_packets(interface):
    sniff(iface=interface, prn=packet_callback, stop_filter=lambda p: stop_sniffing)


def raw_packet_sniffer(interface="Ethernet 4", capture_file="capture.pcap"):
    global packet_count, total_bytes, min_size, max_size, packet_sizes, pcap_writer, stop_sniffing

    packet_count = 0
    total_bytes = 0
    min_size = float("inf")
    max_size = 0
    packet_sizes = []

    pcap_writer = PcapWriter(capture_file, append=True, sync=True)

    print(f"[*] Waiting for traffic on {interface}... Press Ctrl + C to stop.")

    sniff_thread = threading.Thread(target=sniff_packets, args=(interface,), daemon=True)
    sniff_thread.start()

    try:
        while sniff_thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping sniffing...")
        stop_sniffing = True
        sniff_thread.join()  

    avg_size = total_bytes / packet_count if packet_count > 0 else 0
    print("\n--- Sniffing Summary ---")
    print(f"Total Packets Captured: {packet_count}")
    print(f"Total Data Transferred: {total_bytes} bytes")
    print(f"Minimum Packet Size: {min_size} bytes")
    print(f"Maximum Packet Size: {max_size} bytes")
    print(f"Average Packet Size: {avg_size:.2f} bytes")

    plt.figure(figsize=(10, 5))
    plt.hist(packet_sizes, bins=50, color="blue", edgecolor="black")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.grid(True)
    plt.savefig("packet_size_distribution.png")
    print("[*] Histogram saved as packet_size_distribution.png")


raw_packet_sniffer(interface="Ethernet 4")

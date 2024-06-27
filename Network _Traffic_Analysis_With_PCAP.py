from scapy.all import sniff, wrpcap, Ether, IP
import pandas as pd

packet_list = []

def packet_callback(packet):
    if Ether in packet and IP in packet:
        packet_list.append(packet)

# Capture Ethernet packets
def start_sniffing(interface=None):
    print(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, timeout=30)

if __name__ == "__main__":
    network_interface = "Ethernet 2"  # Replace with your network interface
    try:
        start_sniffing(network_interface)
    except Exception as e:
        print(f"Error starting packet capture: {e}")

    # Save captured packets to a PCAP file
    pcap_file = "captured_packets.pcap"
    wrpcap(pcap_file, packet_list)
    print(f"\nCaptured {len(packet_list)} Ethernet packets")
    print(f"Packets saved to {pcap_file}")

    # Convert packet details to DataFrame
    df_packets = pd.DataFrame(columns=["src_ip", "dst_ip", "protocol"])

    for packet in packet_list:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            df_packets = pd.concat([df_packets, pd.DataFrame({"src_ip": [src_ip], "dst_ip": [dst_ip], "protocol": [protocol]})], ignore_index=True)

    # Save DataFrame to CSV
    csv_file = "packet_details.csv"
    df_packets.to_csv(csv_file, index=False)
    print(f"\nPacket details saved to {csv_file}")

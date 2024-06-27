from scapy.all import sniff, wrpcap, Ether, IP, TCP
import pandas as pd

packet_list = []

def packet_callback(packet):
    if IP in packet and TCP in packet:
        if packet[TCP].dport == 80:  # Filter for HTTP traffic
            if packet.haslayer('Raw'):
                raw_data = packet.getlayer('Raw').load.decode(errors='ignore')
                if 'POST' in raw_data and 'HTTP/1.1' in raw_data:
                    if 'Authorization: Basic' in raw_data and '401 Unauthorized' in raw_data:
                        packet_list.append(packet)
                        print(f"Detected failed HTTP POST login attempt: {packet.summary()}")

# Capture Ethernet packets
def start_sniffing(interface=None):
    print(f"Starting packet capture on interface: {interface} for 30 seconds")
    sniff(iface=interface, prn=packet_callback, filter="tcp", timeout=30, store=0)

if __name__ == "__main__":
    network_interface = "Ethernet 2"  # Replace with your network interface
    try:
        start_sniffing(network_interface)
    except Exception as e:
        print(f"Error starting packet capture: {e}")

    # Save captured packets to a PCAP file
    pcap_file = "failed_login_attempts.pcap"
    wrpcap(pcap_file, packet_list)
    print(f"\nCaptured {len(packet_list)} failed login attempt packets")
    print(f"Packets saved to {pcap_file}")

    # Convert packet details to DataFrame
    df_packets = pd.DataFrame(columns=["src_ip", "dst_ip", "protocol", "details"])

    for packet in packet_list:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        details = packet.summary()
        df_packets = pd.concat([df_packets, pd.DataFrame({"src_ip": [src_ip], "dst_ip": [dst_ip], "protocol": [protocol], "details": [details]})], ignore_index=True)

    # Save DataFrame to CSV for ease of parsing
    csv_file = "failed_login_attempts.csv"
    df_packets.to_csv(csv_file, index=False)
    print(f"\nFailed login attempt details saved to {csv_file}")

from scapy.all import sniff, Ether, IP
import pandas as pd

def handle_packet(packet):
    if Ether in packet and IP in packet:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            return {"src_ip": src_ip, "dst_ip": dst_ip, "protocol": protocol}

# Capture Ethernet packets and handle them
def start_sniffing(interface=None, timeout=10):
    print(f"Starting packet capture on interface: {interface} for {timeout} seconds")
    packet_list = sniff(iface=interface, filter="ether and ip", timeout=timeout, prn=handle_packet)
    return packet_list

if __name__ == "__main__":
    network_interface = "Ethernet 2"  # Replace with your network interface
    try:
        packet_list = start_sniffing(network_interface)
    except Exception as e:
        print(f"Error starting packet capture: {e}")
        packet_list = []

    # Convert packet details to DataFrame
    packet_details_df = pd.DataFrame(packet_list)

    # Save DataFrame to CSV
    csv_file = "packet_details.csv"
    packet_details_df.to_csv(csv_file, index=False)
    print(f"\nPacket details saved to {csv_file}")

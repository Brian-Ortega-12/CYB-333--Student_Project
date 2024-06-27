from scapy.all import *
from datetime import datetime
import csv

# Step 1: Filename to save packet results
csv_file = 'packet_results.csv'

# Step 2: CSV header that creates colunms in CSV file
csv_header = ['Time Stamp', 'Type', 'Direction', 'Source MAC', 'Destination MAC', 'Source IP', 'Destination IP']

# Step 3: Initialize the CSV file; Opens CSV in write mode
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(csv_header)
# %Y-%m-%d %H:%M:%S formats the time
# Step 5: calls the fucntion each time packet is captured
def packet_callback(packet):
    packet_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    src_mac = packet.src
    dst_mac = packet.dst
    src_ip = packet[IP].src if IP in packet else 'N/A'
    dst_ip = packet[IP].dst if IP in packet else 'N/A'
# Step 6: Packet type and direction
    if packet.haslayer(TCP):
        packet_type = 'TCP'
        direction = 'Incoming' if packet[IP].dst == my_ip else 'Outgoing'
    elif packet.haslayer(UDP):
        packet_type = 'UDP'
        direction = 'Incoming' if packet[IP].dst == my_ip else 'Outgoing'
    elif packet.haslayer(ICMP):
        packet_type = 'ICMP'
        direction = 'Incoming' if packet[IP].dst == my_ip else 'Outgoing'
    else:
        return  # If the packet is not TCP, UDP, or ICMP, we ignore it.
# step 7: Prints the packet details
    print(f'Time: {packet_time}, Type: {packet_type}, Direction: {direction}')
    print(f'Source MAC: {src_mac}, Destination MAC: {dst_mac}')
    print(f'Source IP: {src_ip}, Destination IP: {dst_ip}')
    print('-' * 80)

    # Step 8: Save packet details to CSV
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([packet_time, packet_type, direction, src_mac, dst_mac, src_ip, dst_ip])
# Step 9: Calls Function to get local IP
def local_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        # Doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
# Step 10: Main Execution
if __name__ == '__main__':
    my_ip = local_ip()
    print(f'Local IP: {my_ip}')
    print('Starting packet capture for 30 seconds...')
    sniff(prn=packet_callback, filter='ip', store=0, timeout=30)
    print('Packet capture finished.')

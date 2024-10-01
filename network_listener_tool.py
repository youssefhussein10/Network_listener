from scapy.all import sniff, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_analyzer(packet):
    # General packet summary
    print(packet.summary())
    
    # Detailed analysis of IP packets
    if packet.haslayer(IP):
        print("IP Packet:")
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
        print(f"TTL: {packet[IP].ttl}")
    
    # Detailed analysis of TCP packets
    if packet.haslayer(TCP):
        print("TCP Packet:")
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Flags: {packet[TCP].flags}")
    
    # Detailed analysis of UDP packets
    if packet.haslayer(UDP):
        print("UDP Packet:")
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    
    # Detailed analysis of ICMP packets
    if packet.haslayer(ICMP):
        print("ICMP Packet:")
        print(f"Type: {packet[ICMP].type}")
        print(f"Code: {packet[ICMP].code}")

def start_sniffing(interface, packet_count, filter_rule=None):
    # Start sniffing on the specified interface with optional filter
    sniff(iface=interface, filter=filter_rule, prn=packet_analyzer, count=packet_count)

# Identify available network interfaces
print("Available network interfaces:")
for iface in get_if_list():
    print(iface)

# Configuration
interface = "Wireless LAN adapter Wi-Fi:"  # Replace with your network interface name
packet_count = 10                       # Number of packets to capture
filter_rule = None                      # Optional: BPF filter

# Start capturing and analyzing packets
start_sniffing(interface, packet_count, filter_rule)

from scapy.all import *
import logging
import subprocess

# Set up logging
logging.basicConfig(filename='intrusion_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to analyze network traffic and detect SYN flood attacks
def analyze_traffic(packet):
    print(f"Captured packet: {packet.summary()}")
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Count the number of SYN packets for each source IP
        if packet[TCP].flags & 2:  # Check if the packet is a SYN packet
            logging.info(f"SYN packet detected - Source IP: {src_ip}, Source Port: {src_port}, Destination IP: {dst_ip}, Destination Port: {dst_port}")

            # Log additional details (you can customize this based on your needs)
            logging.debug(f"Packet details: {packet.summary()}")
            logging.debug(f"TCP Flags: {packet[TCP].flags}")
            logging.debug(f"IP TTL: {packet[IP].ttl}")
            logging.debug(f"IP Length: {packet[IP].len}")
            
            ip_count[src_ip] = ip_count.get(src_ip, 0) + 1

            # If the connection count exceeds a threshold, take action
            if ip_count[src_ip] > 10:
                logging.info(f"Potential SYN flood attack detected from {src_ip}. Blocking connections...")
                take_action(src_ip)

# Function to simulate blocking connections
def take_action(ip_address):
    # Simulate blocking the IP address using iptables
    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        logging.info(f"Blocked connections from {ip_address}")
    except Exception as e:
        logging.error(f"Error blocking connections from {ip_address}: {e}")

# Main function to capture and analyze network traffic
def capture_traffic():
    try:
        # Sniff network traffic and call analyze_traffic for each packet
        sniff(prn=analyze_traffic, store=0)

    except KeyboardInterrupt:
        logging.info("Traffic capture stopped.")

if __name__ == "__main__":
    # Inform users about the tool and its purpose
    print("Open-Source Intrusion Detection and Suspension Tool")

    # Run the main function to capture and analyze network traffic
    capture_traffic()


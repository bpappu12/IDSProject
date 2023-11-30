# Import necessary modules
from scapy.all import *

# Craft a SYN packet
fake_syn_packet = IP(src="192.168.1.1", dst="192.168.1.2") / TCP(dport=80, flags="S")

# Send the SYN packet
send(fake_syn_packet)


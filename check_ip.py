"""
Network Scanner for Raspberry Pi

This script checks if a device with a specified IP address is connected to the network. 
It is designed to run on a Raspberry Pi. The script includes functions to get the default 
gateway, the Raspberry Pi's IP address and netmask, and to perform an ARP scan on the 
network to identify if the target device is connected.

Usage: python scan_network.py <target_ip>
"""

import sys
import time
from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Address, IPv4Network

def get_default_gateway():
    """
    Get the default gateway of the system.

    Returns:
        str: Default gateway interface name.
    """
    with open('/proc/net/route') as f:
        for line in f.readlines():
            fields = line.strip().split()
            # Check if the route is the default route (destination is 0.0.0.0)
            if fields[1] == '00000000':
                return fields[0]

def get_pi_ip_and_netmask(iface):
    """
    Get the IP address and netmask of the specified network interface.

    Args:
        iface (str): Network interface name.

    Returns:
        tuple: IP address and netmask as strings.
    """
    import socket
    import fcntl
    import struct

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Use ioctl to get the IP address of the interface
    ip_addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])

    # Use ioctl to get the netmask of the interface
    netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])

    return ip_addr, netmask

def scan_network(target_ip):
    """
    Scan the network to check if a device with a specified IP address is connected.

    Args:
        target_ip (str): IP address of the target device.

    Returns:
        bool: True if the device is connected, False otherwise.
    """
    # Get the default gateway interface and the Raspberry Pi's IP address and netmask
    iface = get_default_gateway()
    pi_ip, pi_netmask = get_pi_ip_and_netmask(iface)

    # Calculate the network range based on the IP address and netmask
    pi_network = IPv4Network((pi_ip, pi_netmask), strict=False)

    # Create an ARP request packet to get the MAC addresses of devices on the network
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send the ARP request packet and capture the response
    result, _ = srp(packet, timeout=3, iface=iface, verbose=False)

    # Check if the target IP address is in the response
    for sent, received in result:
        if received.psrc == target_ip:
            return True

    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scan_network.py <target_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]

    try:
        # Validate the target IP address
        IPv4Address(target_ip)
    except ValueError:
        print("Invalid IP address.")
        sys.exit(1)

    is_connected = scan_network(target_ip)
    print(f"{target_ip} is {'connected' if is_connected else 'not connected'} to the network.")

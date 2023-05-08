import sys
import time
from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Address, IPv4Network

def get_default_gateway():
    with open('/proc/net/route') as f:
        for line in f.readlines():
            fields = line.strip().split()
            if fields[1] == '00000000':
                return fields[0]

def get_pi_ip_and_netmask(iface):
    import socket
    import fcntl
    import struct

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_addr = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])
    netmask = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x891b, struct.pack('256s', iface[:15].encode('utf-8')))[20:24])

    return ip_addr, netmask

def scan_network(target_ip):
    iface = get_default_gateway()
    pi_ip, pi_netmask = get_pi_ip_and_netmask(iface)

    # Calculate the network range
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
            print(f"{target_ip} is connected to the network.")
            return True

    print(f"{target_ip} is not connected to the network.")
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

    scan_network(target_ip)

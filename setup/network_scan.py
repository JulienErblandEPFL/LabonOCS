from scapy.all import ARP, Ether, srp


#Not sure yet if it works
def scan_network(ip_range, iface=None):
    print(f"Scanning {ip_range}...")

    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, iface=iface, verbose=False)

    hosts = []
    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc
        print(f"{ip} --> {mac}")
        hosts.append((ip, mac))

    return hosts
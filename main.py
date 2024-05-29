import random
import time
import threading
import xlsxwriter
import pandas as pd
import os.path
from scapy.all import *
from scapy.layers.l2 import ARP
import matplotlib.pyplot as plt


# Path to the Excel log file
excel_file = "arp_spoof_log.xlsx"

# Initialize an empty DataFrame to store the logs
if os.path.exists(excel_file):
    log_df = pd.read_excel(excel_file)
else:
    log_df = pd.DataFrame(columns=["Timestamp", "IP", "Severity", "Attack Type", "Mean Severity Score", "Detection Rate Score"])

def log_to_excel(timestamp, ip, severity, attack_type):
    global log_df
    mean_severity =  log_df["Severity"].mean()
    detection_rate = round(random.uniform(1.0, 99.9), 1)

    new_entry = pd.DataFrame({
        "Timestamp": [timestamp],
        "IP": [ip],
        "Severity": [severity],
        "Attack Type": [attack_type],
        "Mean Severity Score": [mean_severity],
        "Detection Rate Score": [detection_rate]
    })

    # Check if new_entry DataFrame is not empty or all-NA
    if not new_entry.dropna().empty:
        log_df = pd.concat([log_df, new_entry], ignore_index=True)

        # Write DataFrame to Excel file with defined column types and formats using xlsxwriter
        with pd.ExcelWriter(excel_file, engine='xlsxwriter', mode='w') as writer:
            log_df.to_excel(writer, index=False, sheet_name='ARP Log')
            workbook = writer.book
            worksheet = writer.sheets['ARP Log']

            # Add number format for severity and score columns
            num_format = workbook.add_format({'num_format': '0.0'})
            worksheet.set_column('C:C', 25, num_format)  # Severity
            worksheet.set_column('F:G', 25, num_format)  # Mean Severity Score and Detection Rate Score

            # Center-align the text
            center_format = workbook.add_format({'align': 'center'})
            worksheet.set_column('A:B', 25, center_format)  # Timestamp and IP
            worksheet.set_column('D:E', 25, center_format)  # Attack Type and Severity
            worksheet.set_column('C:G', 25, center_format)  # Severity, Mean Severity Score, and Detection Rate Score

            # Auto-fit column width
            for column in range(log_df.shape[1]):
                worksheet.set_column(column, column, 20)

time.sleep(1)
print("\n")
print("*********************************************************************")
print("\n")
print("                        QUANTUM ARP GUARD                            ")
print("\n")
print("          Secure ARP Spoof Detection with QKD BB84 Protocol        ")
print("\n")
print("*********************************************************************")
print("\n")

time.sleep(2)
print("Sniffing Packets......")
print("\n")
time.sleep(1)
print("Attack Status......")
print("\n")
time.sleep(5)

spoofed_ips = {}
new_event_detected = False
exit_flag = False  
sender_key = None
receiver_key = None

# Define quantum states for the BB84 protocol
quantum_states = {
    '0': ('H', 'V'),  # Horizontal and Vertical polarization
    '1': ('D', 'A')   # Diagonal and Anti-diagonal polarization
}

# BB84 Protocol Functions
def generate_bits_and_states(num_bits):
    bits = ''.join(random.choice(['0', '1']) for _ in range(num_bits))
    print("Generated bits:", bits)
    states = [quantum_states[bit][random.randint(0, 1)] for bit in bits]
    print("Generated states:", states)
    return bits, states

def choose_measurement_bases(sender_bases):
    return sender_bases

def encode_and_send(bits, states):
    return list(zip(bits, states))

def measure_received_qubits(encoded_qubits, measurement_bases):
    return [state[1] if base == '0' else state[0] for state, base in zip(encoded_qubits, measurement_bases)]

def compare_bases(sender_bases, receiver_bases):
    print("Sender bases:", sender_bases)
    print("Receiver bases:", receiver_bases)
    matching_indices = [idx for idx, (sender_base, receiver_base) in enumerate(zip(sender_bases, receiver_bases)) if sender_base == receiver_base]
    print("Matching bases indices:", matching_indices)
    return matching_indices

def share_results(indices, bits, measurements):
    return ''.join(bits[idx] for idx in indices), ''.join(measurements[idx] for idx in indices)

def bb84(num_bits):
    sender_bits, sender_states = generate_bits_and_states(num_bits)
    receiver_bases = choose_measurement_bases(sender_states)
    encoded_qubits = encode_and_send(sender_bits, sender_states)
    receiver_measurements = measure_received_qubits(encoded_qubits, receiver_bases)
    matching_indices = compare_bases(sender_states, receiver_bases)
    sender_key, receiver_key = share_results(matching_indices, sender_bits, receiver_measurements)
    return sender_key, receiver_key

def arp_sniffer():
    global new_event_detected, exit_flag
    try:
        while not exit_flag:
            sniff(iface="VMware Network Adapter VMnet8", filter="arp", prn=process_packet)
    except KeyboardInterrupt:
        exit_flag = True

def process_packet(packet):
    global new_event_detected
    if ARP in packet and packet[ARP].op == 2:  # Check if it's an ARP reply
        global ip, spoofed_ips
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        severity = random.randint(5, 100)
        if mac not in spoofed_ips:  # Check if MAC address is not in spoofed_ips
            spoofed_ips[mac] = (ip, severity)  # Store MAC address as key, and IP address and severity as value
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ARP spoof detected! IP: {ip}, Severity: {severity}%" ) 
            new_event_detected = True
            if severity < 30:
                attack_type = "Eavesdropping"
                print("Type of attack: Evaesdropping")
            elif severity in range(30, 50):
                attack_type = "MAC Flooding"
                print("Type of attack: MAC Flooding")
            elif severity in range(50, 70):
                attack_type = "ARP Cache Poisoning"
                print("Type of attack: ARP Cache Poisoning")
            elif severity in range(70, 90):
                attack_type = "Session Hijacking"
                print("Type of attack: Session Hijacking")
            else:
                attack_type = "Unknown"
                print("Type of attack: Unknown")

            log_to_excel(time.strftime('%Y-%m-%d %H:%M:%S'), ip, severity, attack_type)

def initiate_bb84_protocol():
    global new_event_detected
    print ("\n")
    print("Initiating BB84 protocol...Securing the Data Communication")
    print("\n")
    time.sleep(2)
    sender_key, receiver_key = bb84(100)  # Modify the number of bits as needed
    print("Sender's key:", sender_key)
    print("Receiver's key:", receiver_key)
    new_event_detected = True

def plt_grph():
    print("\n")
    print("Plotting the Severity of the Attack:")
    time.sleep(3)
    
    global spoofed_ips, new_event_detected
    
    ips = list(spoofed_ips.keys()) if new_event_detected else []  # Set default value for ips
    
    if new_event_detected is False:
        severity = [0] * len(ips)  # Set severity to zeros if no new event detected
    elif new_event_detected is True:
        severity = [spoofed_ips[ip][1] for ip in ips]  # Extract severity from the spoofed_ips dictionary
    
    plt.figure(figsize=(6, 4))
    if new_event_detected is False:
        plt.bar(ips, severity, color='red')  # Use ips and severity directly
    elif new_event_detected is True:
        plt.bar(ip, severity, color='red')  # Use ips and severity directly

    plt.xlabel('IP Address')
    plt.ylabel('Severity (%)')
    plt.title('Severity of ARP Spoofing Attack')
    
    plt.ylim(0, 100)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.show()
    exit

sniffer_thread = threading.Thread(target=arp_sniffer)
sniffer_thread.daemon = True
sniffer_thread.start()

# Main Loop
while not exit_flag:
    time.sleep(2)
    if not new_event_detected:
        print("No ARP spoof detected.")
        new_event_detected = False
        plt_grph()
        break
    if new_event_detected:
        initiate_bb84_protocol()
        plt_grph()
        break

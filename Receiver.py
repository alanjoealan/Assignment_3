from scapy.all import *

#Convert text to binary
def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(char, 2)) for char in chars if len(char) == 8)

#Capturing ICMP packets
def receive_message():
    captured_bits = []

#Packet processing callback
    def packet_callback(packet):
        if IP in packet and ICMP in packet and packet[ICMP].type == 8:  # Echo Request
            captured_bits.append(format(packet[IP].id, '016b'))

#Sniffing for ICMP packets
    print("Listening for incoming ICMP packets:")
    sniff(filter="icmp", prn=packet_callback, timeout=10)

#Rebuilding the hidden message
    full_bits = ''.join(captured_bits)
    hidden_message = bits_to_text(full_bits)
    print(f"Extracted Message: {hidden_message}")

#Main command-line execution
if __name__ == "__main__":
    print("Starting receiver...")
    receive_message()

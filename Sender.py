from scapy.all import *
import sys

#Function to convert text to binary (text to 8 bit binary)
def text_to_bits(text):
    return ''.join(format(ord(char), '08b') for char in text)

#Function to send the message via ICMP packets
def send_message(message, destination):
    bits = text_to_bits(message)
    print(f"Sending: {message} as bits: {bits}")

    for i in range(0, len(bits), 16):
        chunk = bits[i:i+16].ljust(16, '0') #zero-padding, in case last chuck is shorter than 16 bit
        ip_id = int(chunk, 2)
        packet = IP(dst=destination, id=ip_id)/ICMP() #create ICMP Packet
        send(packet, verbose=False)

#Main command-line handling
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python sender.py 'your message' target_ip")
    else:
        send_message(sys.argv[1], sys.argv[2])

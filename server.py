from scapy.all import *

# Constants
FILTER = "udp"
packet = IP(dst="127.0.0.1")/UDP(dport=103)

def receive_secret_message(packet):
    if packet.haslayer(UDP) and len(packet[UDP].payload) == 0:
        try:
            ascii_value = chr(packet[UDP].dport)   # Ensure value is within range(0, 256)
            print(ascii_value, end='')
        except Exception as e:
            print("[ERROR]", end='')  # Placeholder for unexpected errors


def main():
    print("Starting packet sniffing")
    sniff(filter=FILTER, prn=receive_secret_message)
    #receive_secret_message(packet)


if __name__ == "__main__":
    main()

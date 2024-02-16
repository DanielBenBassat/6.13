from scapy.all import *

# Constants
FILTER = "udp"

def receive_secret_message(packet):
    """
    receive packet and if its an empty udp packet turn the destention port to his asci value and print i
    :param packet: packet the client send that represent a asci value
    :return: none
    """
    if packet.haslayer(UDP) and len(packet[UDP].payload) == 0:
        try:
            ascii_value = chr(packet[UDP].dport)
            print(ascii_value, end='')
        except Exception as e:
            print("[ERROR]", end='')


def main():
    print("Starting packet sniffing")
    sniff(filter=FILTER, prn=receive_secret_message)


if __name__ == "__main__":
    main()

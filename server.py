from scapy.all import *

# Constants
FILTER = "udp"


def receive_secret_message(packet):
    """
    receive packet and if it is an empty udp packet turn the destination port to his ascii value and print it
    :param packet: packet the client send that represent an ascii value
    :return: none
    """
    if packet.haslayer(UDP) and len(packet[UDP].payload) == 0:
        try:
            port = packet[UDP].dport
            if 0 <= port <= 256:
                ascii_value = chr(port)
                print(ascii_value, end='')
        except Exception as error:
            print("[ERROR]", end='')



def main():
    print("Starting packet sniffing")
    sniff(prn=receive_secret_message, filter=FILTER, store=0)


if __name__ == "__main__":
    main()

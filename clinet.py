from scapy.all import *

IP_ADDRESS = "192.168.68.1"


def send_secret_message(message):
    """
    send a packet for every letter in messgae, the packet is sent to the port of the asci value of the letter
    :param message: the message that the client entered
    :return: none
    """
    for char in message:
        ascii_value = ord(char)
        packet = IP(dst=IP_ADDRESS) / UDP(dport=ascii_value)
        send(packet)


def main():
    message = input("Enter message to send: ")
    send_secret_message(message)


if __name__ == "__main__":
    main()

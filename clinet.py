from scapy.all import *

IP_ADDRESS = "127.0.0.1"


def send_secret_message(message):
    for char in message:
        ascii_value = ord(char)
        packet = IP(dst=IP_ADDRESS) / UDP(dport=ascii_value)
        send(packet)


def main():
    message = input("Enter message to send: ")
    send_secret_message(message)


if __name__ == "__main__":
    main()

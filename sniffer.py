from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_analyzer(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print("\n==============================")
        print("Source IP      :", src_ip)
        print("Destination IP :", dst_ip)

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        else:
            print("Protocol       : Other")

        if packet.haslayer(TCP) and packet[TCP].payload:
            print("Payload Data   :", bytes(packet[TCP].payload))

print("Starting packet capture... Press CTRL+C to stop")
sniff(prn=packet_analyzer, store=False)

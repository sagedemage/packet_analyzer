from scapy.all import ARP, PcapNgWriter, PcapNgReader
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ipv6nh
from scapy.packet import Packet
from typing import Any
from datetime import datetime

protocol_map = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    88: "EIGRP",
    89: "OSPF",
    112: "VRRP",
    115: "L2TP"
}

class PacketAnalyzer:
    def __init__(self, writer: PcapNgWriter=None):
        self.writer = writer
        self.num = 0
    
    @staticmethod
    def get_wire_length(packet: Packet):
        wire_length = len(bytes(packet))
        return wire_length
    
    def get_packet_infomation(self, packet: Packet) -> dict[str, Any]:
        self.num += 1
        src = "N/A"
        dst = "N/A"
        proto = "N/A"
        wire_length = self.get_wire_length(packet)
        window_size = "N/A"
        packet_time = float(packet.time)
        dt = datetime.fromtimestamp(packet_time)
        timestamp = dt.strftime("%H:%M:%S.%f")
        tcp_flags = "N/A"
        seq_num = "N/A"
        ack_num = "N/A"
        src_port = ""
        dst_port = ""
        if packet.haslayer(IP):
            proto_num = packet[IP].proto
            proto = protocol_map.get(proto_num, "Unknown")
            src = packet[IP].src
            dst = packet[IP].dst
        if packet.haslayer(TCP):
            window_size = packet[TCP].window
            tcp_flags = packet[TCP].flags
            seq_num = packet[TCP].seq
            ack_num = packet[TCP].ack
            src_port = f":{packet[TCP].sport}"
            dst_port = f":{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            src_port = f":{packet[UDP].sport}"
            dst_port = f":{packet[UDP].dport}"
        if packet.haslayer(ARP):
            proto = "ARP"
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
        if packet.haslayer(IPv6):
            src = f"[{packet[IPv6].src[:15]}...]"
            dst = f"[{packet[IPv6].dst[:15]}...]"
            proto_num = packet[IPv6].nh

            # Get the protocol name from the dictionary
            proto = ipv6nh.get(proto_num, "Unknown")

        # Num, Timestamp, Protocol, Source, Destination, TCP Flags, Sequence Number, Ack Number, Window Size, Length
        packet_info = f"{self.num}, {timestamp}, {proto}, {src}{src_port}, {dst}{dst_port}, {tcp_flags}, {seq_num}, {ack_num}, {window_size}, {wire_length}"
        
        return packet_info

    def callback(self, packet: Packet):
        packet_info = self.get_packet_infomation(packet)

        print(packet_info)

        # Write the packet to the file
        self.writer.write(packet)

    def get_data_of_pcapng_file(self, pcapng_file_path: str):
        with PcapNgReader(pcapng_file_path) as pcap_reader:
            for packet in pcap_reader:
                packet_info = self.get_packet_infomation(packet)
                print(packet_info)
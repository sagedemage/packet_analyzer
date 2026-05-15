from scapy.all import ARP, load_contrib, PcapNgWriter, PcapNgReader
from scapy.layers.tls.record import TLS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

load_contrib("igmpv3")

from scapy.contrib.igmpv3 import IGMPv3
from typing import Any

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

tls_verions = {
    0x0303: "TLSv1.2",
    0x0302: "TLSv1.1",
    0x0301: "TLSv1.0",
    0x0300: "SSLv3",
    0x0200: "SSLv2"
}

class PacketAnalyzer:
    def __init__(self, writer: PcapNgWriter=None):
        self.writer = writer
        self.count = 0
        self.packet_infos = []
    
    @staticmethod
    def get_wire_length(packet: Packet):
        wire_length = len(bytes(packet))
        return wire_length
    
    def get_packet_infomation(self, packet: Packet) -> dict[str, Any]:
        self.count += 1
        src = ""
        dst = ""
        proto = ""
        wire_length = self.get_wire_length(packet)
        window_size = ""
        timestamp = packet.time
        tcp_flags = ""
        seq_num = ""
        ack_num = ""
        if packet.haslayer(IP):
            proto = protocol_map.get(packet[IP].proto)
            src = packet[IP].src
            dst = packet[IP].dst

            if packet.haslayer(TCP):
                proto = "TCP"
                window_size = packet[TCP].window
                tcp_flags = packet[TCP].flags
                seq_num = packet[TCP].seq
                ack_num = packet[TCP].ack
            elif packet.haslayer(UDP):
                proto = "UDP"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
            if packet.haslayer(TLS):
                tls = packet[TLS]
                raw_version = tls.version
                version = tls_verions.get(raw_version)
                proto = version
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            proto = "ARP"
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src[:15] + "..."
            dst = packet[IPv6].dst[:15] + "..."
            proto = "IPv6"
        if packet.haslayer(IGMPv3):
            proto = "IGMPv3"

        # Num, Timestamp, Protocol, Source, Destination, TCP Flags, Seq Number, Ack Number, Window Size, Length
        packet_info = [
            str(self.count),
            str(timestamp),
            proto, src, dst,
            str(tcp_flags),
            str(seq_num),
            str(ack_num),
            str(window_size),
            str(wire_length)
            ]
        
        return packet_info

    def callback(self, packet: Packet):
        packet_info = self.get_packet_infomation(packet)
        self.packet_infos.append(packet_info)

        # Write the packet to the file
        self.writer.write(packet)

    def get_data_of_pcapng_file(self, pcapng_file_path: str) -> list:
        packet_data = []

        with PcapNgReader(pcapng_file_path) as pcap_reader:
            for packet in pcap_reader:
                packet_info = self.get_packet_infomation(packet)
                
                # Num, Timestamp, Protocol, Source, Destination, TCP Flags, Seq Number, Ack Number, Window Size, Length
                row = [
                    packet_info[0],
                    packet_info[1],
                    packet_info[2],
                    packet_info[3],
                    packet_info[4],
                    packet_info[5],
                    packet_info[6],
                    packet_info[7],
                    packet_info[8],
                    packet_info[9],
                    ]

                packet_data.append(row)
    
        return packet_data
    
    def get_packet_infos(self) -> list:
        return self.packet_infos 
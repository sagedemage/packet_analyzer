from scapy.all import ARP, load_contrib, PcapNgWriter, PcapNgReader
from scapy.layers.tls.record import TLS
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

load_contrib("igmp")
load_contrib("igmpv3")

from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3gr
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
        info = ""
        if packet.haslayer(IP):
            proto = protocol_map.get(packet[IP].proto)
            src = packet[IP].src
            dst = packet[IP].dst

            info = ""

            if packet.haslayer(TCP):
                proto = "TCP"
                info = f"{packet[TCP].sport} -> {packet[TCP].dport}"
                if packet[TCP].flags & 0x02:
                    info += " [SYN]"
                if packet[TCP].flags & 0x10:
                    info += " [ACK]"
                if packet[TCP].flags & 0x01:
                    info += " [FIN]"
            elif packet.haslayer(UDP):
                proto = "UDP"
                info = f"{packet[UDP].sport} -> {packet[UDP].dport}"
            elif packet.haslayer(ICMP):
                proto = "ICMP"
                if packet[ICMP].type == 8:
                    info = "Echo Request"
                else:
                    info = "Echo Reply"
            if packet.haslayer(TLS):
                tls = packet[TLS]
                raw_version = tls.version
                version = tls_verions.get(raw_version)
                proto = version
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            proto = "ARP"
            if packet[ARP].op == 1:
                info = f"Who has {dst}? Tell {src}"
            else:
                info = f"{src} is at {packet[ARP].hwsrc}"
        elif packet.haslayer(IPv6):
            src = packet[IPv6].src[:15] + "..."
            dst = packet[IPv6].dst[:15] + "..."
            proto = "IPv6"
        if packet.haslayer(IGMPv3):
            proto = "IGMPv3"
            igmpv3 = packet[IGMPv3]
            if igmpv3.type == 0x11:
                info = "Membership Query, general"
            elif igmpv3.type == 0x22 and igmpv3.haslayer(IGMPv3mr):
                mr = igmpv3[IGMPv3mr]
                info_parts = []

                for record in mr.records:
                    rtype = record.rtype
                    maddr = record.maddr
                    if hasattr(record, "srcaddrs"):
                        srcaddrs = record.srcaddrs
                    else:
                        srcaddrs = []

                    if rtype == 1: # MODE_IS_INCLUDE
                        if srcaddrs:
                             info_parts.append(f"Include group {maddr} sources {', '.join(srcaddrs)}")
                        else:
                            info_parts.append(f"Include group {maddr}")
                    elif rtype == 2: # MODE_IS_EXCLUDE
                        info_parts.append(f"Exclude group {maddr}")
                    elif rtype == 3: # CHANGE_TO_INCLUDE_MODE
                        if srcaddrs:
                            info_parts.append(f"Change to include group {maddr} sources {', '.join(srcaddrs)}")
                        else:
                            info_parts.append(f"Change to include group {maddr}")
                    elif rtype == 4:  # CHANGE_TO_EXCLUDE_MODE
                        info_parts.append(f"Change to exclude group {maddr}")
                    elif rtype == 5:  # ALLOW_NEW_SOURCES
                        info_parts.append(f"Allow new sources {', '.join(srcaddrs)} for group {maddr}")
                    elif rtype == 6:  # BLOCK_OLD_SOURCES
                        info_parts.append(f"Block old sources {', '.join(srcaddrs)} for group {maddr}")
                if info_parts:
                    info = "Membership Report / " + " / ".join(info_parts)
                else:
                    info = "Membership Report, IGMPv3"
        
        #packet_info = f"Num: {self.count}, Source: {src}, Destination: {dst}, Protocol: {proto}, Length: {wire_length}, Info: {info}"
        packet_info = {"Num": self.count, "Source": src, "Destination": dst, "Protocol": proto, "Length": wire_length, "Info": info}
        return packet_info

    def callback(self, packet: Packet):
        packet_info = self.get_packet_infomation(packet)
        print(packet_info)

        # Write the packet to the file
        self.writer.write(packet)
    
    @staticmethod
    def _get_igmpv3_type_name(type_val):
        types = {
            0x11: "Membership Query",
            0x22: "Version 3 Membership Report"
        }
        return types.get(type_val, "Unknown")

    def get_data_of_pcapng_file(self, pcapng_file_path: str) -> dict[str, Any]:
        packet_data: dict[str, Any] = {}
        packet_data["Num"] = []
        packet_data["Source"] = []
        packet_data["Destination"] = []
        packet_data["Protocol"] = []
        packet_data["Length"] = []
        packet_data["Info"] = []

        with PcapNgReader(pcapng_file_path) as pcap_reader:
            for packet in pcap_reader:
                packet_info = self.get_packet_infomation(packet)

                packet_data["Num"].append(packet_info["Num"])
                packet_data["Source"].append(packet_info["Source"])
                packet_data["Destination"].append(packet_info["Destination"])
                packet_data["Protocol"].append(packet_info["Protocol"])
                packet_data["Length"].append(packet_info["Length"])
                packet_data["Info"].append(packet_info["Info"])
    
        return packet_data
from scapy.all import sniff, load_layer, conf, PcapNgWriter
from packet_analyzer import PacketAnalyzer
import sys

def packet_sniffer():
    load_layer("tls")
    conf.tls_session_enable = True

    # Create a writer object for the file
    writer = PcapNgWriter("data/output.pcapng")

    packet_analyzer = PacketAnalyzer(writer)
    columns = "Num, Timestamp, Protocol, Source, Destination, TCP Flags, Sequence Number, Ack Number, Window Size, Length"
    print(columns)
    sniff(filter="host 10.0.0.1", iface="Ethernet", timeout=120, count=120, prn=packet_analyzer.callback)

    # Don't forget to close the writer when you're done
    writer.close()

def open_pcapng_file():
    packet_analyzer = PacketAnalyzer()
    pcapng_file_path = "data/output.pcapng"
    packet_analyzer.get_data_of_pcapng_file(pcapng_file_path)

def main():
    if len(sys.argv) > 0:
        flag = sys.argv[1]
        print(flag)

        match flag:
            case "sniff":
                packet_sniffer()
            case "read":
                open_pcapng_file()
            case _:
                print(f"Flag {flag} not supported\n")
                print("Usage:")
                print("sniff -> sniff packets")
                print("read -> read packet data from a file")
    else:
        print("Usage:")
        print("sniff -> sniff packets")
        print("read -> read packet data from a file")

if __name__ == "__main__":
    main()
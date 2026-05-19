from scapy.all import sniff, load_layer, conf, PcapNgWriter, get_if_hwaddr
from packet_analyzer import PacketAnalyzer
import sys

def check_interface_exists(iface_name: str):
    try:
        # Try to get hardware address
        get_if_hwaddr(iface_name)
        return True
    except ValueError:
        return False

def packet_sniffer(iface_name: str):
    load_layer("tls")
    conf.tls_session_enable = True

    if check_interface_exists(iface_name):
        # Create a writer object for the file
        writer = PcapNgWriter("data/output.pcapng")

        packet_analyzer = PacketAnalyzer(writer)
        columns = "Num, Timestamp, Protocol, Source, Destination, TCP Flags, Sequence Number, Ack Number, Window Size, Length"
        print(columns)
        sniff(filter="host 10.0.0.1", iface=iface_name, timeout=100, count=20, prn=packet_analyzer.callback)

        # Don't forget to close the writer when you're done
        writer.close()
    else:
        print(f"Interface: {iface_name} does not exist on the system!")

def open_pcapng_file():
    packet_analyzer = PacketAnalyzer()
    pcapng_file_path = "data/output.pcapng"
    packet_analyzer.get_data_of_pcapng_file(pcapng_file_path)

def help_usage():
    print("Usage:")
    print("sniff i <interface_name> -> sniff packets on a specified interface")
    print("read -> read packet data from a file")

def main():
    if len(sys.argv) > 1:
        flag = sys.argv[1]

        match flag:
            case "sniff":
                if len(sys.argv) > 3:
                    interface_flag = sys.argv[2]
                    if interface_flag == "i":
                        iface_name = sys.argv[3]
                        packet_sniffer(iface_name)
                else:
                    help_usage()
            case "read":
                open_pcapng_file()
            case _:
                print(f"Flag {flag} not supported\n")
                help_usage()
    else:
        help_usage()

if __name__ == "__main__":
    main()
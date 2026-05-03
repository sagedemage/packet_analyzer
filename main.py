from scapy.all import sniff, load_layer, conf, PcapNgWriter
from packet_analyzer import PacketAnalyzer

def main():
    load_layer("tls")
    conf.tls_session_enable = True

    # Create a writer object for the file
    writer = PcapNgWriter("data/output.pcapng")

    packet_analyzer = PacketAnalyzer(writer)
    sniff(timeout=120, count=120, prn=packet_analyzer.callback)

    # Don't forget to close the writer when you're done
    writer.close()

if __name__ == "__main__":
    main()
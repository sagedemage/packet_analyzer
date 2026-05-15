from scapy.all import sniff, load_layer, conf, PcapNgWriter
from packet_analyzer import PacketAnalyzer
from PySide6 import QtCore
from PySide6.QtWidgets import QHeaderView, QPushButton, QLabel, QTableView, QMainWindow, QWidget, QVBoxLayout, QApplication
from PySide6.QtGui import QStandardItemModel, QStandardItem
import sys

def packet_sniffer():
    load_layer("tls")
    conf.tls_session_enable = True

    # Create a writer object for the file
    writer = PcapNgWriter("data/output.pcapng")

    packet_analyzer = PacketAnalyzer(writer)
    sniff(timeout=120, count=120, prn=packet_analyzer.callback)

    packet_infos = packet_analyzer.get_packet_infos()

    # Don't forget to close the writer when you're done
    writer.close()

    return packet_infos

def open_pcapng_file() -> list:
    packet_analyzer = PacketAnalyzer()
    pcapng_file_path = "data/output.pcapng"
    packet_data = packet_analyzer.get_data_of_pcapng_file(pcapng_file_path)
    return packet_data

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.run_button = QPushButton("Run Packet Analyzer")
        self.read_pcapng_file_button = QPushButton("Read pcapng file")
        self.text = QLabel("Packet Analyzer",
                                     alignment=QtCore.Qt.AlignCenter)
        self.table_view = QTableView()
        self.model = QStandardItemModel()

        # Hide row numbers
        self.table_view.verticalHeader().setVisible(False)

        # Set headers
        self.model.setHorizontalHeaderLabels([
            "Num",
            "Timestamp",
            "Protocol",
            "Source",
            "Destination",
            "TCP Flags",
            "Seq Number",
            "Ack Number",
            "Window Size",
            "Length"
            ])
        
        # Adjust column widths
        self.table_view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.table_view.setModel(self.model)
        
        widget = QWidget()

        layout = QVBoxLayout()
        layout.addWidget(self.text)
        layout.addWidget(self.table_view)
        layout.addWidget(self.run_button)
        layout.addWidget(self.read_pcapng_file_button)

        widget.setLayout(layout)

        self.setCentralWidget(widget)

        self.run_button.clicked.connect(self.run_packet_analyzer)
        self.read_pcapng_file_button.clicked.connect(self.read_pcapng_file)
    
    def clear_table_data(self):
        self.model.removeRows(1, self.model.rowCount())

    @QtCore.Slot()
    def run_packet_analyzer(self):
        self.clear_table_data()
        
        packet_infos = packet_sniffer()
        
        for row, row_data in enumerate(packet_infos):
            items = [QStandardItem(value) for value in row_data]
            self.model.appendRow(items)
    
    @QtCore.Slot()
    def read_pcapng_file(self):
        self.clear_table_data()

        packat_data = open_pcapng_file()

        for row, row_data in enumerate(packat_data):
            items = [QStandardItem(value) for value in row_data]
            self.model.appendRow(items)

if __name__ == "__main__":
    app = QApplication([])

    main_window = MainWindow()
    main_window.resize(800, 600)
    main_window.show()

    sys.exit(app.exec())
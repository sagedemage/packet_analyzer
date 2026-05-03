from flask import Flask
from packet_analyzer import PacketAnalyzer
from flask.json import jsonify

app = Flask(__name__)

def read_data_of_pcapng_file(packet_data: dict):
    for i in range(len(packet_data["Num"])):
        num = packet_data["Num"][i]
        source = packet_data["Source"][i]
        dst = packet_data["Destination"][i]
        proto = packet_data["Protocol"][i]
        length = packet_data["Length"][i]
        info = packet_data["Info"][i]
        print(f"Num: {num}, Source: {source}, Destination: {dst}, Protocol: {proto}, Length: {length}, Info: {info}")

@app.route("/")
def home_page():
    return "<p>Click <a href='/get-data-of-pcapng-file'>here</a> to go to the route to get the packet data from pcapng file.</p>"

@app.route("/get-data-of-pcapng-file")
def get_data_of_pcapng_file():
    packet_analyzer = PacketAnalyzer()
    pcapng_file_path = "data/output.pcapng"
    packet_data = packet_analyzer.get_data_of_pcapng_file(pcapng_file_path)
    
    return jsonify(packet_data)

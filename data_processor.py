
import pandas as pd
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

def extract_features(packet):
    """Extrai features relevantes de um único pacote."""
    features = {}
    
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto
        features['length'] = len(packet)
        
        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = int(packet[TCP].flags)
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['tcp_flags'] = 0
        else:
            features['src_port'] = 0
            features['dst_port'] = 0
            features['tcp_flags'] = 0
            
        return features
    return None

def packets_to_df(packets):
    """Converte uma lista de pacotes Scapy em um DataFrame do Pandas."""
    data = []
    for packet in packets:
        features = extract_features(packet)
        if features:
            data.append(features)
    
    df = pd.DataFrame(data)
    return df

def preprocess_data(df):
    """Realiza o pré-processamento dos dados (ex: encoding, normalização)."""
    # Exemplo simples: preencher valores ausentes e converter IPs para categorias numéricas se necessário
    # Para este exemplo, vamos focar nas features numéricas
    features_to_use = ['protocol', 'length', 'src_port', 'dst_port', 'tcp_flags']
    X = df[features_to_use]
    return X

if __name__ == "__main__":
    from packet_capture import load_packets
    
    # Carregar pacotes do teste anterior
    pcap_filename = "captured_packets.pcap"
    try:
        packets = load_packets(pcap_filename)
        df = packets_to_df(packets)
        print("\n--- DataFrame de Pacotes ---")
        print(df.head())
        
        X = preprocess_data(df)
        print("\n--- Features Pré-processadas ---")
        print(X.head())
    except FileNotFoundError:
        print(f"Arquivo {pcap_filename} não encontrado. Execute packet_capture.py primeiro.")

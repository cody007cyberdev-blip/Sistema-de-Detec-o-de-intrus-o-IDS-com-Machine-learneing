
import scapy.all as scapy

def sniff_packets(interface, count):
    print(f"Iniciando a captura de {count} pacotes na interface {interface}...")
    packets = scapy.sniff(iface=interface, count=count, store=True)
    print(f"Captura concluída. {len(packets)} pacotes capturados.")
    return packets

def save_packets(packets, filename):
    scapy.wrpcap(filename, packets)
    print(f"Pacotes salvos em {filename}")

def load_packets(filename):
    packets = scapy.rdpcap(filename)
    print(f"Pacotes carregados de {filename}")
    return packets

if __name__ == "__main__":
    # Exemplo de uso:
    # Certifique-se de ter as permissões necessárias para capturar pacotes (ex: sudo python3 packet_capture.py)
    # Você pode precisar alterar 'eth0' para a interface de rede correta (ex: 'wlan0', 'en0', 'Wi-Fi')
    interface = "eth0"  # Altere para a sua interface de rede
    num_packets = 10

    # Capturar pacotes
    captured_packets = sniff_packets(interface, num_packets)

    # Salvar pacotes em um arquivo
    pcap_filename = "captured_packets.pcap"
    save_packets(captured_packets, pcap_filename)

    # Carregar pacotes de um arquivo
    loaded_packets = load_packets(pcap_filename)

    # Exibir um resumo dos pacotes carregados
    for i, packet in enumerate(loaded_packets):
        print(f"\n--- Pacote {i+1} ---")
        packet.show()

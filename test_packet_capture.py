
import unittest
import os
from scapy.all import Ether, IP, TCP, wrpcap, rdpcap
from packet_capture import sniff_packets, save_packets, load_packets

class TestPacketCapture(unittest.TestCase):

    def setUp(self):
        self.test_pcap_file = "test_packets.pcap"
        # Criar alguns pacotes de teste
        self.test_packets = [
            Ether()/IP(dst="192.168.1.1")/TCP(dport=80),
            Ether()/IP(dst="192.168.1.2")/TCP(dport=443)
        ]
        wrpcap(self.test_pcap_file, self.test_packets)

    def tearDown(self):
        if os.path.exists(self.test_pcap_file):
            os.remove(self.test_pcap_file)

    def test_save_and_load_packets(self):
        # Testar se os pacotes são salvos e carregados corretamente
        loaded = load_packets(self.test_pcap_file)
        self.assertEqual(len(loaded), len(self.test_packets))
        # Mais verificações poderiam ser feitas para comparar o conteúdo dos pacotes

    # Não é possível testar sniff_packets diretamente sem uma interface de rede real e permissões de root
    # e sem mockar a função sniff do scapy, o que é mais complexo para um teste unitário simples.
    # Este teste é mais para garantir que as funções de salvar/carregar funcionam.

if __name__ == '__main__':
    unittest.main()


import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
import time
import random

def simulate_activity(interface='lo'):
    """Simula atividades de rede, incluindo normais e suspeitas."""
    print(f"Iniciando simulação de atividades na interface {interface}...")
    
    # Destinos comuns
    targets = ["127.0.0.1"]
    
    try:
        while True:
            activity_type = random.choice(['normal', 'large_packet', 'sensitive_port', 'null_scan'])
            
            if activity_type == 'normal':
                print("Simulando tráfego normal (HTTP/HTTPS)...")
                packet = IP(dst=random.choice(targets))/TCP(dport=443, flags="PA")
                scapy.send(packet, iface=interface, verbose=False)
                
            elif activity_type == 'large_packet':
                print("Simulando pacote suspeito (Tamanho excessivo)...")
                # Pacote com payload grande (> 1400 bytes)
                payload = "X" * 1450
                packet = IP(dst=random.choice(targets))/TCP(dport=80)/payload
                scapy.send(packet, iface=interface, verbose=False)
                
            elif activity_type == 'sensitive_port':
                print("Simulando acesso a porta sensível (SSH - 22)...")
                packet = IP(dst=random.choice(targets))/TCP(dport=22, flags="S")
                scapy.send(packet, iface=interface, verbose=False)
                
            elif activity_type == 'null_scan':
                print("Simulando varredura suspeita (TCP NULL Scan - flags=0)...")
                packet = IP(dst=random.choice(targets))/TCP(dport=random.randint(1024, 65535), flags=0)
                scapy.send(packet, iface=interface, verbose=False)
            
            time.sleep(2) # Espera entre as atividades
            
    except KeyboardInterrupt:
        print("\nSimulação interrompida pelo usuário.")

if __name__ == "__main__":
    # Nota: Requer permissões de superusuário
    # Usando a interface de loopback 'lo' para simulação local
    simulate_activity(interface='lo')

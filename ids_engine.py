
import scapy.all as scapy
from data_processor import extract_features
from ml_model import IDSModel
import pandas as pd
import datetime

class IDSEngine:
    def __init__(self, interface='eth0', model_path='ids_model.joblib'):
        self.interface = interface
        self.ids_model = IDSModel(model_path)
        if not self.ids_model.load_model():
            print("Erro: Modelo não encontrado. Treine o modelo primeiro.")
            exit(1)
        self.alert_count = 0

    def packet_callback(self, packet):
        """Callback chamada para cada pacote capturado."""
        features = extract_features(packet)
        if features:
            # Converter features para DataFrame para predição
            df_features = pd.DataFrame([features])
            # Selecionar apenas as colunas usadas no treinamento
            X = df_features[['protocol', 'length', 'src_port', 'dst_port', 'tcp_flags']]
            
            prediction = self.ids_model.predict(X)[0]
            
            if prediction == 1:
                self.alert_count += 1
                self.generate_alert(features)

    def generate_alert(self, features):
        """Gera um alerta para atividade suspeita."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[ALERTA {self.alert_count}] Atividade Suspeita Detectada!")
        print(f"Horário: {timestamp}")
        print(f"Origem: {features['src_ip']}:{features['src_port']}")
        print(f"Destino: {features['dst_ip']}:{features['dst_port']}")
        print(f"Protocolo: {features['protocol']} | Tamanho: {features['length']} | Flags: {features['tcp_flags']}")
        print("-" * 40)

    def start_monitoring(self):
        """Inicia o monitoramento em tempo real."""
        print(f"Iniciando monitoramento na interface {self.interface}...")
        print("Pressione Ctrl+C para parar.")
        try:
            scapy.sniff(iface=self.interface, prn=self.packet_callback, store=False)
        except KeyboardInterrupt:
            print("\nMonitoramento interrompido pelo usuário.")
            print(f"Total de alertas gerados: {self.alert_count}")

if __name__ == "__main__":
    # Nota: Requer permissões de superusuário
    engine = IDSEngine(interface='eth0')
    engine.start_monitoring()

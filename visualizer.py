
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from data_processor import packets_to_df
from packet_capture import load_packets
from ml_model import IDSModel
import os

def generate_visualizations(pcap_file, model_path='ids_model.joblib', output_dir='plots'):
    """Gera gráficos baseados nos dados de um arquivo PCAP e no modelo IDS."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print(f"Carregando dados de {pcap_file}...")
    packets = load_packets(pcap_file)
    df = packets_to_df(packets)
    
    if df.empty:
        print("Erro: Nenhum dado encontrado no arquivo PCAP.")
        return

    # Realizar predições para identificar o que é suspeito
    ids_model = IDSModel(model_path)
    if ids_model.load_model():
        X = df[['protocol', 'length', 'src_port', 'dst_port', 'tcp_flags']]
        df['prediction'] = ids_model.predict(X)
        df['status'] = df['prediction'].map({0: 'Normal', 1: 'Suspeito'})
    else:
        print("Aviso: Modelo não encontrado. Gerando apenas estatísticas básicas.")
        df['status'] = 'Desconhecido'

    # Configuração de estilo
    sns.set_theme(style="darkgrid")
    plt.rcParams['figure.figsize'] = (12, 8)

    # 1. Distribuição do Tamanho dos Pacotes por Status
    plt.figure()
    sns.histplot(data=df, x='length', hue='status', multiple="stack", bins=30)
    plt.title('Distribuição do Tamanho dos Pacotes')
    plt.xlabel('Tamanho (bytes)')
    plt.ylabel('Frequência')
    plt.savefig(f'{output_dir}/packet_length_dist.png')
    print(f"Gráfico salvo: {output_dir}/packet_length_dist.png")

    # 2. Contagem de Protocolos
    plt.figure()
    sns.countplot(data=df, x='protocol', hue='status')
    plt.title('Contagem de Pacotes por Protocolo')
    plt.xlabel('Protocolo (6=TCP, 17=UDP, 1=ICMP)')
    plt.ylabel('Quantidade')
    plt.savefig(f'{output_dir}/protocol_count.png')
    print(f"Gráfico salvo: {output_dir}/protocol_count.png")

    # 3. Portas de Destino mais comuns
    plt.figure()
    top_ports = df['dst_port'].value_counts().nlargest(10).index
    sns.countplot(data=df[df['dst_port'].isin(top_ports)], y='dst_port', hue='status', orient='h')
    plt.title('Top 10 Portas de Destino')
    plt.xlabel('Quantidade')
    plt.ylabel('Porta')
    plt.savefig(f'{output_dir}/top_dst_ports.png')
    print(f"Gráfico salvo: {output_dir}/top_dst_ports.png")

    # 4. Resumo de Detecção (Pizza)
    if 'prediction' in df.columns:
        plt.figure()
        df['status'].value_counts().plot.pie(autopct='%1.1f%%', colors=['#2ecc71', '#e74c3c'])
        plt.title('Resumo de Detecção do IDS')
        plt.ylabel('')
        plt.savefig(f'{output_dir}/detection_summary.png')
        print(f"Gráfico salvo: {output_dir}/detection_summary.png")

if __name__ == "__main__":
    # Exemplo de uso
    pcap_test = "captured_packets.pcap"
    if os.path.exists(pcap_test):
        generate_visualizations(pcap_test)
    else:
        print(f"Arquivo {pcap_test} não encontrado para gerar visualizações.")

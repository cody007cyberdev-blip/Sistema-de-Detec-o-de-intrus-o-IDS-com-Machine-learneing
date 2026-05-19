
import argparse
import sys
from packet_capture import sniff_packets, save_packets, load_packets
from data_processor import packets_to_df, preprocess_data
from ml_model import IDSModel
from ids_engine import IDSEngine

def main():
    parser = argparse.ArgumentParser(description="Sistema de Detecção de Intrusão (IDS) com Machine Learning")
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponíveis')

    # Comando: capture
    capture_parser = subparsers.add_parser('capture', help='Capturar pacotes de rede')
    capture_parser.add_argument('-i', '--interface', default='eth0', help='Interface de rede (padrão: eth0)')
    capture_parser.add_argument('-c', '--count', type=int, default=100, help='Número de pacotes a capturar (padrão: 100)')
    capture_parser.add_argument('-o', '--output', default='captured_packets.pcap', help='Arquivo de saída (padrão: captured_packets.pcap)')

    # Comando: train
    train_parser = subparsers.add_parser('train', help='Treinar o modelo de ML')
    train_parser.add_argument('-d', '--data', default='captured_packets.pcap', help='Arquivo PCAP com dados de treinamento')
    train_parser.add_argument('-m', '--model', default='ids_model.joblib', help='Arquivo de saída do modelo')

    # Comando: monitor
    monitor_parser = subparsers.add_parser('monitor', help='Iniciar monitoramento em tempo real')
    monitor_parser.add_argument('-i', '--interface', default='eth0', help='Interface de rede (padrão: eth0)')
    monitor_parser.add_argument('-m', '--model', default='ids_model.joblib', help='Arquivo do modelo treinado')

    # Comando: analyze
    analyze_parser = subparsers.add_parser('analyze', help='Analisar arquivo PCAP')
    analyze_parser.add_argument('-f', '--file', required=True, help='Arquivo PCAP a analisar')

    args = parser.parse_args()

    if args.command == 'capture':
        print(f"Capturando {args.count} pacotes da interface {args.interface}...")
        packets = sniff_packets(args.interface, args.count)
        save_packets(packets, args.output)
        print(f"Pacotes salvos em {args.output}")

    elif args.command == 'train':
        print(f"Carregando dados de {args.data}...")
        packets = load_packets(args.data)
        df = packets_to_df(packets)
        X = preprocess_data(df)
        
        # Gerar labels simples para demonstração
        import numpy as np
        y = ((df['length'] > 1400) | (df['dst_port'] == 22) | (df['tcp_flags'] == 0)).astype(int)
        
        ids = IDSModel(args.model)
        ids.train(X, y)

    elif args.command == 'monitor':
        print(f"Iniciando monitoramento na interface {args.interface}...")
        engine = IDSEngine(interface=args.interface, model_path=args.model)
        engine.start_monitoring()

    elif args.command == 'analyze':
        print(f"Analisando {args.file}...")
        packets = load_packets(args.file)
        df = packets_to_df(packets)
        print("\nResumo dos Pacotes:")
        print(df.describe())
        print("\nPrimeiros 10 pacotes:")
        print(df.head(10))

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

# Sistema de Detecção de Intrusão (IDS) com Machine Learning

Este projeto visa desenvolver um Sistema de Detecção de Intrusão (IDS) completo utilizando Python, Scapy, Scikit-learn e Pandas. O sistema será capaz de monitorar pacotes de rede em tempo real, processar os dados, aplicar modelos de Machine Learning para detectar atividades suspeitas e gerar alertas.

## Estrutura do Projeto

```
ids_project/
├── packet_capture.py
├── data_processor.py
├── ml_model.py
├── ids_engine.py
├── cli.py
├── requirements.txt
├── .gitignore
├── README.md
└── test_packet_capture.py
```

## Módulos

### `packet_capture.py`

Este módulo é responsável por capturar pacotes de rede usando a biblioteca Scapy, salvá-los em arquivos `.pcap` e carregá-los para análise posterior.

### `data_processor.py`

Este módulo contém funções para extrair características (features) relevantes de pacotes de rede e pré-processar esses dados para uso em modelos de Machine Learning. Ele converte pacotes Scapy em DataFrames do Pandas.

### `ml_model.py`

Este módulo implementa a lógica para treinar, salvar, carregar e usar modelos de Machine Learning (atualmente `RandomForestClassifier`) para detecção de intrusões. Ele utiliza `scikit-learn` e `joblib`.

### `ids_engine.py`

O motor do IDS, responsável por monitorar o tráfego de rede em tempo real, processar cada pacote, aplicar o modelo de ML treinado e gerar alertas quando atividades suspeitas são detectadas.

### `cli.py`

Uma interface de linha de comando para interagir com o sistema IDS, permitindo capturar pacotes, treinar o modelo, monitorar o tráfego em tempo real e analisar arquivos PCAP existentes.

## Pré-requisitos

Certifique-se de ter as seguintes bibliotecas instaladas. Você pode instalá-las usando o `pip`:

```bash
sudo pip3 install -r requirements.txt
```

## Como Usar (CLI)

Navegue até o diretório `ids_project` e use o script `cli.py` com os seguintes comandos:

### 1. Capturar Pacotes

Captura um número especificado de pacotes de uma interface de rede e os salva em um arquivo `.pcap`.

```bash
sudo python3 cli.py capture -i eth0 -c 100 -o captured_packets.pcap
```

-   `-i`, `--interface`: Interface de rede (padrão: `eth0`)
-   `-c`, `--count`: Número de pacotes a capturar (padrão: `100`)
-   `-o`, `--output`: Arquivo de saída (padrão: `captured_packets.pcap`)

### 2. Treinar o Modelo de ML

Treina o modelo de Machine Learning usando um arquivo `.pcap` como dados de treinamento. (Nota: Para um uso real, você precisaria de um dataset rotulado).

```bash
python3 cli.py train -d captured_packets.pcap -m ids_model.joblib
```

-   `-d`, `--data`: Arquivo PCAP com dados de treinamento (padrão: `captured_packets.pcap`)
-   `-m`, `--model`: Arquivo de saída para o modelo treinado (padrão: `ids_model.joblib`)

### 3. Monitorar em Tempo Real

Inicia o monitoramento do tráfego de rede em tempo real, usando o modelo treinado para detectar atividades suspeitas.

```bash
sudo python3 cli.py monitor -i eth0 -m ids_model.joblib
```

-   `-i`, `--interface`: Interface de rede (padrão: `eth0`)
-   `-m`, `--model`: Arquivo do modelo treinado (padrão: `ids_model.joblib`)

### 4. Analisar Arquivo PCAP

Carrega e exibe um resumo estatístico e os primeiros pacotes de um arquivo `.pcap`.

```bash
python3 cli.py analyze -f captured_packets.pcap
```

-   `-f`, `--file`: Arquivo PCAP a analisar (obrigatório)

## Testes

Para executar os testes unitários, navegue até o diretório `ids_project` e execute:

```bash
python3 -m unittest test_packet_capture.py
```

## Contribuição

Sinta-se à vontade para contribuir com este projeto. Por favor, abra uma issue ou envie um pull request.

## Licença

Este projeto está licenciado sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.

## Scripts de Demonstração

Foram adicionados scripts para simular ataques e demonstrar o funcionamento do IDS em tempo real.

### `simulate_attack.py`

Simula diferentes tipos de tráfego na rede, incluindo:
-   **Tráfego Normal**: Pacotes TCP comuns na porta 443.
-   **Pacote Suspeito (Tamanho)**: Pacotes com payload superior a 1400 bytes.
-   **Acesso a Porta Sensível**: Tentativas de conexão na porta SSH (22).
-   **Varredura Suspeita (NULL Scan)**: Pacotes TCP com todas as flags zeradas.

### `demo_ids.py`

Um script que automatiza a demonstração, iniciando o IDS e a simulação de ataques simultaneamente na interface de loopback (`lo`).

#### Como executar a demonstração:

```bash
sudo python3 demo_ids.py
```

**Nota:** O script treinará o modelo automaticamente se ele não existir e iniciará o monitoramento. Os alertas aparecerão no terminal conforme os ataques simulados forem detectados.

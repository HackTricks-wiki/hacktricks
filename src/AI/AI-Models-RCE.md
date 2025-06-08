# Modeller RCE

{{#include ../banners/hacktricks-training.md}}

## Modellerin RCE'ye Yüklenmesi

Makine Öğrenimi modelleri genellikle ONNX, TensorFlow, PyTorch gibi farklı formatlarda paylaşılır. Bu modeller, geliştiricilerin makinelerine veya üretim sistemlerine yüklenerek kullanılabilir. Genellikle modeller kötü niyetli kod içermemelidir, ancak bazı durumlarda model, sistemde rastgele kod çalıştırmak için kullanılabilir; bu, ya beklenen bir özellik ya da model yükleme kütüphanesindeki bir güvenlik açığı nedeniyle olabilir.

Yazım zamanı itibarıyla bu tür güvenlik açıklarına bazı örnekler şunlardır:

| **Framework / Araç**       | **Güvenlik Açığı (CVE mevcutsa)**                                                                                          | **RCE Vektörü**                                                                                                                         | **Referanslar**                             |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|
| **PyTorch** (Python)        | *Güvensiz serileştirme* `torch.load` **(CVE-2025-32434)**                                                                  | Model kontrol noktasındaki kötü niyetli pickle, kod çalıştırmaya yol açar ( `weights_only` korumasını atlar)                            | |
| PyTorch **TorchServe**      | *ShellTorch* – **CVE-2023-43654**, **CVE-2022-1471**                                                                       | SSRF + kötü niyetli model indirme, kod çalıştırmaya neden olur; yönetim API'sinde Java serileştirme RCE                                    | |
| **TensorFlow/Keras**        | **CVE-2021-37678** (güvensiz YAML) <br> **CVE-2024-3660** (Keras Lambda)                                                  | YAML'den model yüklemek `yaml.unsafe_load` kullanır (kod çalıştırma) <br> **Lambda** katmanı ile model yüklemek rastgele Python kodu çalıştırır | |
| TensorFlow (TFLite)         | **CVE-2022-23559** (TFLite ayrıştırma)                                                                                      | Özel olarak hazırlanmış `.tflite` modeli, tam sayı taşması tetikler → bellek bozulması (potansiyel RCE)                                  | |
| **Scikit-learn** (Python)   | **CVE-2020-13092** (joblib/pickle)                                                                                         | `joblib.load` ile bir model yüklemek, saldırganın `__reduce__` yükünü çalıştırır                                                          | |
| **NumPy** (Python)          | **CVE-2019-6446** (güvensiz `np.load`) *tartışmalı*                                                                         | `numpy.load` varsayılan olarak pickle nesne dizilerine izin veriyordu – kötü niyetli `.npy/.npz` kod çalıştırmayı tetikler               | |
| **ONNX / ONNX Runtime**     | **CVE-2022-25882** (dizin geçişi) <br> **CVE-2024-5187** (tar geçişi)                                                      | ONNX modelinin dış-ağırlık yolu dizinden çıkabilir (rastgele dosyaları okuyabilir) <br> Kötü niyetli ONNX model tar, rastgele dosyaları yazabilir (RCE'ye yol açar) | |
| ONNX Runtime (tasarım riski) | *(CVE yok)* ONNX özel ops / kontrol akışı                                                                                   | Özel operatör içeren model, saldırganın yerel kodunu yüklemeyi gerektirir; karmaşık model grafikleri, istenmeyen hesaplamaları çalıştırmak için mantığı kötüye kullanır | |
| **NVIDIA Triton Server**    | **CVE-2023-31036** (yol geçişi)                                                                                            | `--model-control` etkinleştirildiğinde model yükleme API'sinin kullanılması, dosyaları yazmak için göreli yol geçişine izin verir (örneğin, RCE için `.bashrc`'yi geçersiz kılma) | |
| **GGML (GGUF formatı)**     | **CVE-2024-25664 … 25668** (birden fazla bellek taşması)                                                                    | Bozuk GGUF model dosyası, ayrıştırıcıda bellek tamponu taşmalarına neden olarak kurban sistemde rastgele kod çalıştırılmasını sağlar      | |
| **Keras (eski formatlar)**  | *(Yeni CVE yok)* Eski Keras H5 modeli                                                                                       | Kötü niyetli HDF5 (`.h5`) modeli, Lambda katmanı kodu yüklenirken hala çalışır (Keras güvenli_modu eski formatı kapsamaz – “gerileme saldırısı”) | |
| **Diğerleri** (genel)       | *Tasarım hatası* – Pickle serileştirme                                                                                      | Birçok ML aracı (örneğin, pickle tabanlı model formatları, Python `pickle.load`) model dosyalarına gömülü rastgele kodu çalıştıracaktır, önlem alınmadıkça | |

Ayrıca, [PyTorch](https://github.com/pytorch/pytorch/security) tarafından kullanılanlar gibi bazı python pickle tabanlı modeller, `weights_only=True` ile yüklenmediklerinde sistemde rastgele kod çalıştırmak için kullanılabilir. Bu nedenle, tabloda listelenmemiş olsalar bile, herhangi bir pickle tabanlı model bu tür saldırılara özellikle duyarlı olabilir.

{{#include ../banners/hacktricks-training.md}}

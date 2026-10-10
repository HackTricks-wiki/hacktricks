# Konteynerler ve Ad Alanları

{{#include ../../banners/hacktricks-training.md}}

Bir konteyner, izolasyon ve ayrıcalık yapılandırmasıyla çalışan bir Linux sürecidir. Çalışma zamanını, bağlanan ana makine kaynaklarını, verilen yetenekleri ve ad alanı ayarlarını birlikte değerlendirin. [Konteyner güvenliğine genel bakış](container-security/README.md), bu katmanları açıklar ve her bir denetime bağlantı verir.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md), containerd'nin yönetim arayüzüne erişime odaklanır.
- [RunC privilege escalation](runc-privilege-escalation.md), çalışma zamanına özgü privilege escalation materyallerini ele alır.
- [Konteyner güvenliği](container-security/README.md); çalışma zamanlarını, açığa çıkarılan API'leri, imaj risklerini, hassas bağlamaları, ayrıcalıklı konteynerleri, değerlendirmeyi ve ad alanları, seccomp ve zorunlu erişim denetimi gibi korumaları açıklar.
{{#include ../../banners/hacktricks-training.md}}

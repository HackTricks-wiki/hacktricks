# Container'lar ve Namespace'ler

{{#include ../../banners/hacktricks-training.md}}

Bir container, izolasyon ve ayrıcalık yapılandırmasıyla çalışan bir Linux sürecidir. Runtime'ı, bağlanmış ana makine kaynaklarını, verilen capabilities değerlerini ve namespace ayarlarını birlikte değerlendirin. [Container security overview](container-security/README.md), bu katmanları açıklar ve her denetimle ilgili bağlantılar sunar.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md), containerd'nin yönetim arayüzüne erişime odaklanır.
- [RunC privilege escalation](runc-privilege-escalation.md), runtime'a özgü privilege escalation konularını ele alır.
- [Container security](container-security/README.md), runtime'ları, açığa çıkarılmış API'leri, image risklerini, hassas mount'ları, ayrıcalıklı container'ları, değerlendirmeyi ve namespace'ler, seccomp ve zorunlu erişim denetimi gibi korumaları açıklar.
{{#include ../../banners/hacktricks-training.md}}

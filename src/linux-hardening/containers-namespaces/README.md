# Konteynerler ve Namespace'ler

{{#include ../../banners/hacktricks-training.md}}

Bir container, izolasyon ve yetki yapılandırmasıyla çalışan bir Linux sürecidir. Runtime'ı, bağlanan host kaynaklarını, verilen capability'leri ve namespace ayarlarını birlikte değerlendirin. [Container security overview](container-security/README.md), bu katmanları açıklar ve her denetime bağlantı verir.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md), containerd'nin yönetim arayüzüne erişime odaklanır.
- [RunC privilege escalation](runc-privilege-escalation.md), runtime'a özgü privilege escalation konularını ele alır.
- [Container security](container-security/README.md); runtime'ları, açığa çıkan API'leri, image risklerini, hassas mount'ları, privileged container'ları, değerlendirme yöntemlerini ve namespace, seccomp ve zorunlu erişim denetimi gibi korumaları açıklar.
{{#include ../../banners/hacktricks-training.md}}

# Değerlendirme ve Sertleştirme

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

İyi bir container değerlendirmesi iki paralel soruyu yanıtlamalıdır. Birincisi, mevcut workload'tan bir attacker neler yapabilir? İkincisi, hangi operator seçimleri bunu mümkün kıldı? Enumeration araçları ilk soruya yardımcı olurken, sertleştirme rehberi ikinci soruya yardımcı olur. Her ikisini de tek bir sayfada tutmak, bölümü sadece bir escape tricks kataloğu olmaktan ziyade saha başvuru kaynağı olarak daha kullanışlı kılar.

## Enumeration Tools

Bir dizi araç, bir container ortamını hızlıca tanımlamak için hâlâ faydalıdır:

- `linpeas` birçok container göstergesini, mounted sockets'i, capability set'lerini, tehlikeli dosya sistemlerini ve breakout hints'i tespit edebilir.
- `CDK` özellikle container ortamlarına odaklanır ve enumeration ile bazı otomatikleştirilmiş escape kontrolleri içerir.
- `amicontained` hafif bir araçtır ve container kısıtlamalarını, capabilities'i, namespace maruziyetini ve olası breakout sınıflarını belirlemede kullanışlıdır.
- `deepce` breakout-oriented kontroller içeren başka bir container-odaklı enumeratördür.
- `grype` değerlendirmeye image-package zafiyet incelemesi de dahil olduğunda, sadece runtime escape analizine bağlı kalınmadığında faydalıdır.

Bu araçların değeri kesinlik değil hız ve kapsamdadır. Kabaca duruşu hızlıca ortaya koymaya yardımcı olurlar, ancak ilginç bulgular hâlâ gerçek runtime, namespace, capability ve mount modeline karşı elle yorumlanmalıdır.

## Sertleştirme Öncelikleri

En önemli sertleştirme ilkeleri kavramsal olarak basittir, fakat uygulanmaları platforma göre değişir. Privileged container'lardan kaçının. Mounted runtime sockets'lerden kaçının. Çok özel bir neden olmadıkça container'lara yazılabilir host path'leri vermeyin. Mümkünse user namespaces veya rootless execution kullanın. Tüm capabilities'i kaldırın ve yalnızca workload'un gerçekten ihtiyaç duyduğu olanları geri ekleyin. Uygulama uyumluluk problemlerini gidermek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Kaynakları sınırlandırın ki ele geçirilmiş bir container host'a hizmeti kolayca engelleyemesin.

Image ve build hijyeni, runtime duruşu kadar önemlidir. Minimal image'ler kullanın, sık sık yeniden inşa edin, tarayın, mümkün olduğunda provenance isteyin ve secret'ları layer'ların dışında tutun. Non-root olarak çalışan, küçük bir image ve dar bir syscall ile capability yüzeyine sahip bir container, host-equivalent root olarak çalışan ve önceden yüklenmiş debugging araçları içeren büyük bir convenience image'e göre savunması çok daha kolaydır.

## Kaynak Tüketimi Örnekleri

Kaynak kontrolleri gösterişli olmayabilir, ancak compromise'ın blast radius'unu sınırladıkları için container güvenliğinin bir parçasıdır. Bellek, CPU veya PID limitleri yoksa, basit bir shell host'u veya komşu workload'ları bozmak için yeterli olabilir.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Bu örnekler faydalıdır çünkü her tehlikeli container çıktısının temiz bir "escape" olmadığını gösterir. Zayıf cgroup limitleri kod yürütmeyi gerçek operasyonel etkiye dönüştürebilir.

## Sertleştirme Araçları

Docker-odaklı ortamlarda, `docker-bench-security` host tarafı denetim temeli olarak hâlâ faydalıdır çünkü yaygın yapılandırma sorunlarını geniş çapta kabul görmüş benchmark yönergelerine karşı kontrol eder:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Bu araç threat modeling'in yerine geçmez, ancak zaman içinde biriken dikkatsiz daemon, mount, network ve runtime varsayılanlarını bulmak için yine de değerlidir.

## Kontroller

Değerlendirme sırasında hızlı ilk tarama komutları olarak bunları kullanın:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Geniş yetkilere sahip bir root process ve `Seccomp: 0` hemen dikkat gerektirir.
- Şüpheli mounts ve runtime sockets genellikle herhangi bir kernel exploit'ten daha hızlı bir etki yolunu sağlar.
- Zayıf runtime posture ile zayıf resource limits kombinasyonu genellikle tek bir izole hatadan ziyade genel olarak permissive container environment gösterir.

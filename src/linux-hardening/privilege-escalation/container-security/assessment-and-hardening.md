# Değerlendirme ve Sertleştirme

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

İyi bir container değerlendirmesi iki paralel soruyu yanıtlamalı. Birincisi, mevcut workload'tan bir attacker neler yapabilir? İkincisi, hangi operator tercihleri bunun gerçekleşmesini sağladı? Enumeration araçları ilk soruda yardımcı olur, sertleştirme rehberi ise ikinci soruyu açıklar. Her ikisini aynı sayfada tutmak, bölümü yalnızca escape taktikleri kataloğu olmaktan çıkarıp saha referansı olarak daha kullanışlı kılar.

## Keşif Araçları

Aşağıdaki araçlar container ortamını hızlıca karakterize etmek için faydalıdır:

- `linpeas` birçok container göstergesi, mounted sockets, capability sets, tehlikeli dosya sistemleri ve breakout ipuçlarını tespit edebilir.
- `CDK` özellikle container ortamlarına odaklanır ve keşfin yanında bazı otomatik escape kontrolleri içerir.
- `amicontained` hafiftir ve container kısıtlamalarını, capability'leri, namespace maruziyetini ve olası breakout sınıflarını belirlemede faydalıdır.
- `deepce` yine container odaklı bir enumeratör olup breakout yönelimli kontrolleri vardır.
- `grype` değerlendirme image-package zafiyet incelemesini de içeriyorsa, sadece runtime escape analizinden ziyade paket taraması için kullanışlıdır.

Bu araçların değeri hız ve kapsama yatkınlıktadır; kesinlik değil. Rough posture'u hızlıca ortaya koymaya yardımcı olurlar, fakat ilginç bulgular hâlâ gerçek runtime, namespace, capability ve mount modeline karşı manuel olarak yorumlanmalıdır.

## Sertleştirme Öncelikleri

En önemli sertleştirme ilkeleri kavramsal olarak basittir, uygulamaları platforma göre değişir. Privileged containers'dan kaçının. Mounted runtime sockets'ten kaçının. Eğer çok spesifik bir gerekçe yoksa containerlara writable host path'ler vermeyin. Mümkünse user namespaces veya rootless execution kullanın. Tüm capability'leri drop edin ve yalnızca workload'un gerçekten ihtiyaç duyduğu olanları geri ekleyin. Uygulama uyumluluk sorunlarını gidermek için seccomp, AppArmor ve SELinux'u devre dışı bırakmak yerine etkin tutun. Kompromize bir container'ın host'a trivially hizmeti engellemesini önlemek için kaynakları sınırlayın.

Image ve build hijyeni runtime duruşu kadar önemlidir. Minimal image'lar kullanın, sık sık rebuild edin, tarayın, mümkün olduğunda provenance isteyin ve secrets'i katmanların dışında tutun. Non-root olarak çalışan, küçük bir image'a sahip ve dar bir syscall ve capability yüzeyine sahip bir container, debugging araçları önyüklü host-eşdeğeri root olarak çalışan büyük bir convenience image'a göre savunması çok daha kolaydır.

## Kaynak-Tükenmesi Örnekleri

Kaynak kontrolleri göz alıcı değildir, ancak compromise'in blast radius'unu sınırladıkları için container güvenliğinin bir parçasıdır. Bellek, CPU veya PID limitleri olmadan, basit bir shell bile host'u veya komşu workload'ları bozmak için yeterli olabilir.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Bu örnekler yararlıdır çünkü her tehlikeli container sonucunun temiz bir "escape" olmadığını gösterir. Zayıf cgroup sınırlamaları kod yürütmeyi hâlâ gerçek operasyonel etkiye dönüştürebilir.

## Sertleştirme Araçları

Docker-odaklı ortamlarda, `docker-bench-security` host tarafı denetimi için hâlâ yararlı bir temel sağlar çünkü yaygın yapılandırma sorunlarını geniş kabul görmüş benchmark yönergelerine karşı kontrol eder:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Araç threat modeling'in yerine geçmez, ancak zaman içinde biriken dikkatsiz daemon, mount, network ve runtime varsayılanlarını bulmak için hâlâ değerlidir.

## Checks

Değerlendirme sırasında ilk hızlı kontrol için bu komutları kullanın:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Burada ilginç olanlar:

- Geniş capabilities'e sahip bir root process ve `Seccomp: 0` hemen dikkat gerektirir.
- Şüpheli mounts ve runtime sockets genellikle herhangi bir kernel exploit'ten daha hızlı etkiye ulaşma yolu sağlar.
- Zayıf runtime posture ile zayıf resource limits'in birleşimi genellikle tek bir izole hatadan ziyade genel olarak izin verici bir container ortamına işaret eder.
{{#include ../../../banners/hacktricks-training.md}}

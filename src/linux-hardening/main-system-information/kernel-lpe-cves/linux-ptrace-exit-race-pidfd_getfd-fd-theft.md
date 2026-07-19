# Linux ptrace exit-race `pidfd_getfd()` FD çalma

{{#include ../../../banners/hacktricks-training.md}}

Yararlı bir **Linux kernel privesc pattern**, **ptrace authorization bug** durumunu ayrıcalıklı bir process içinden **file descriptor theft** gerçekleştirmek için kullanmaktır.

Qualys `__ptrace_may_access()` case study'sinde (CVE-2026-46333), attacker **exiting veya credentials düşüren ayrıcalıklı bir process** ile race eder ve `pidfd_getfd()` kullanarak bir FD'yi attacker process'ine kopyalar.

## Temel fikir

`pidfd_getfd()`, başka bir process'ten bir file descriptor'ı duplicate eder; ancak önce target'a karşı ptrace-style permissions kontrolü gerçekleştirir. Bu authorization, bir **teardown window** sırasında hatalı şekilde verilirse, unprivileged bir attacker şunları kopyalayabilir:

- Ayrıcalıklı bir helper tarafından önceden açılmış **sensitive files** için FD'ler
- Zaten root olarak authorize edilmiş **authenticated IPC channels** için FD'ler

Bu, kernel-side authorization bug durumunu oldukça pratik bir userspace primitive'e dönüştürür.

## Primitive neden tehlikelidir?

Attack'in privileged helper'ın kendisinde bir bug'a ihtiyacı yoktur. Helper'ın yalnızca geçici olarak değerli bir şeyi elinde tutması yeterlidir:

- `/etc/shadow`
- `/etc/ssh/*_key`
- Ayrıcalıklı bir D-Bus / systemd connection
- Önceden açılmış başka herhangi bir secret veya authorized channel

Attacker process'ine duplicate edildikten sonra kernel, işlemleri original pathname veya yeni bir authentication flow üzerinden değil, **stolen FD** üzerinden uygular.

## Exploitation pattern

1. Sensitive files açan veya kullanışlı IPC connections bulunduran bir **setuid / setgid / file-capability binary** ya da **root daemon** belirleyin.
2. Target path için ilgili ptrace policy checks'i karşılayan bir ilişki elde edin (örneğin permissive YAMA settings altında oluşturulan privileged child process'in **parent**'ı olmak).
3. Process **exiting**, **credentials düşürüyor** veya ptrace access'in kullanılamaz hale gelmesi gereken başka bir state'e girerken race gerçekleştirin.
4. Dar authorization window sırasında target FD'yi duplicate etmek için `pidfd_open()` + `pidfd_getfd()` kullanın.
5. Stolen FD'yi unprivileged context içinden yeniden kullanın:
- Privileged file descriptor'lardan secret'ları `read()` ile okuyun
- **root-side actions** elde etmek için stolen authenticated IPC channel üzerinden requests gönderin

Minimal primitive şekli:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Denetlenecek pratik hedefler

Kısa süreliğine bile olsa aşağıdakilerden birini yapan binary ve daemon'lara öncelik verin:

- yetki geçişlerini tamamlamadan önce yalnızca root tarafından erişilebilen dosyaları açmak
- **system bus**'a bağlanmak ve önceden yetkilendirilmiş bir kanalı açık tutmak
- yetkili FD'leri helper sınırları üzerinden geçirmek
- `do_exit()`-yakın sonlandırma sırasında security-sensitive işler gerçekleştirmek

İyi araştırma adayları:

- password / account management helper'ları
- SSH helper'ları
- PolicyKit / D-Bus aracılı helper'lar
- D-Bus method'ları sunan root desktop daemon'ları

## Bir exploit gate olarak YAMA

`kernel.yama.ptrace_scope`, ptrace-family abuse için önemli bir pratik geçittir:

- `0`: klasik same-UID ptrace davranışı
- `1`: genellikle parent -> child tracing'e izin verir; bu da bazı public exploit path'lerini erişilebilir tutabilir
- `2`: attach-style erişim için `CAP_SYS_PTRACE` gerektirir ve bu path'teki unprivileged `pidfd_getfd()` abuse'unu engeller
- `3`: reboot'e kadar ptrace attach'i tamamen devre dışı bırakır

Bu technique için `ptrace_scope=2`, unprivileged kullanıcılar için public `pidfd_getfd()` exploitation path'ini `-EPERM` ile kırdığı için güçlü bir **geçici mitigation**'dır.

## Detection / review fikirleri

Privileged Linux software'ını denetlerken şu kombinasyonları arayın:

- **privileged child process** + **attacker-controlled parent**
- **değerli açık dosyalara** geçici erişim
- **authenticated D-Bus/systemd channel'larına** geçici erişim
- klasik `ptrace(2)` dışında **ptrace-style authorization**'ı yeniden kullanan security kararları
- mevcut privileged FD'leri **duplicate, inherit veya re-export** edebilen kernel API'leri

Kernel'i denetlerken, özellikle başarının doğrudan `task->files` veya önceden yetkilendirilmiş diğer process kaynaklarına erişim sağlaması durumunda, **task teardown** sırasında **ptrace-equivalent authorization** gerçekleştiren tüm path'leri yüksek riskli kabul edin.

## Referanslar

- [Qualys blog: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}

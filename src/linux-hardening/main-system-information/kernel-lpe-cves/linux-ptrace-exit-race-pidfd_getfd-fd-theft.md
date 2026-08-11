# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Kullanışlı bir **Linux kernel privesc pattern**, bir **ptrace authorization bug** durumunu ayrıcalıklı bir process'ten **file descriptor theft** elde etmek için kullanmaktır.

Qualys `__ptrace_may_access()` case study'sinde (CVE-2026-46333), attacker **exiting veya credentials düşüren ayrıcalıklı bir process'i** race eder ve attacker process'ine bir FD duplicate etmek için `pidfd_getfd()` kullanır.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()`, başka bir process'ten file descriptor duplicate eder; ancak önce target'a karşı ptrace-style permissions kontrolü yapar.<sup>[[3]](#references)</sup> Bu authorization bir **teardown window** sırasında hatalı şekilde veriliyorsa, unprivileged attacker şunları kopyalayabilir:

- Ayrıcalıklı bir helper tarafından önceden açılmış **sensitive files** için FD'ler
- Zaten root olarak authorize edilmiş **authenticated IPC channels** için FD'ler

Bu durum, kernel-side authorization bug'ını oldukça pratik bir userspace primitive'ine dönüştürür.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

Bu attack'in privileged helper'ın kendisinde bir bug bulunmasına ihtiyacı yoktur. Helper'ın yalnızca geçici olarak değerli bir şeyi elinde tutması yeterlidir:

- `/etc/shadow`
- `/etc/ssh/*_key`
- Ayrıcalıklı bir D-Bus / systemd connection
- Önceden açılmış herhangi bir secret veya authorized channel

Attacker process'ine duplicate edildikten sonra duplicate, aynı open file description'ı gösterir. Bu nedenle sonraki read veya IPC request'leri, original pathname'i yeniden açmak ya da yeni bir authentication flow başlatmak yerine zaten açılmış FD'yi kullanır.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Sensitive files açan veya kullanışlı IPC connections tutan bir **setuid / setgid / file-capability binary** ya da **root daemon** belirleyin.<sup>[[2]](#references)</sup>
2. Target path için ilgili ptrace policy checks'i karşılayan bir ilişki elde edin (örneğin permissive YAMA settings altında spawn edilmiş privileged child'ın **parent**'ı olmak).<sup>[[2]](#references)[[4]](#references)</sup>
3. Process'i **exiting**, **credentials düşürüyor** veya ptrace access'in kullanılamaz hale gelmiş olması gereken başka bir state'e giriyor olduğu sırada race edin.<sup>[[2]](#references)</sup>
4. Dar authorization window sırasında target FD'yi duplicate etmek için `pidfd_open()` + `pidfd_getfd()` kullanın.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Stolen FD'yi unprivileged context'ten yeniden kullanın.<sup>[[2]](#references)</sup>
- Privileged file descriptor'dan `read()` ile secret'ları okuyun
- **root-side actions** elde etmek için stolen authenticated IPC channel üzerinden request'ler gönderin

Minimal primitive biçimi.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Denetlenecek pratik hedefler

Kısa süreliğine bile olsa aşağıdakilerden birini yapan binary ve daemon'lara öncelik verin:<sup>[[1]](#references)[[2]](#references)</sup>

- privilege geçişlerini tamamlamadan önce yalnızca root tarafından erişilebilen dosyaları açmak
- **system bus**'a bağlanmak ve önceden yetkilendirilmiş bir channel'ı açık tutmak
- helper sınırları üzerinden privileged FD'ler geçirmek
- `do_exit()`'e yakın teardown sırasında security-sensitive işlemler gerçekleştirmek

İyi hunting adayları:<sup>[[1]](#references)</sup>

- password / account management helper'ları
- SSH helper'ları
- PolicyKit / D-Bus aracılı helper'lar
- D-Bus method'ları sunan root desktop daemon'ları

## Exploit gate olarak YAMA

`kernel.yama.ptrace_scope`, ptrace-family abuse için önemli bir pratik engeldir:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasik same-UID ptrace davranışı
- `1`: genellikle parent -> child tracing'e izin verir; bu da bazı public exploit path'lerini erişilebilir tutabilir
- `2`: attach-style erişim için `CAP_SYS_PTRACE` gerektirir ve bu path'te unprivileged `pidfd_getfd()` abuse'unu engeller
- `3`: reboot gerçekleşene kadar ptrace attach'i tamamen devre dışı bırakır

Bu technique için `ptrace_scope=2`, unprivileged user'lar için public `pidfd_getfd()` exploitation path'ini `-EPERM` ile kırdığı için güçlü bir **geçici mitigation**'dır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review fikirleri

Privileged Linux software'ını audit ederken şu kombinasyonları arayın:

- **privileged child process** + **attacker-controlled parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- **değerli open file'lara** geçici erişim
- **authenticated D-Bus/systemd channel'larına** geçici erişim.<sup>[[2]](#references)</sup>
- klasik `ptrace(2)` dışında **ptrace-style authorization**'ı yeniden kullanan security decision'lar
- mevcut privileged FD'leri **duplicate, inherit veya re-export** edebilen kernel API'leri

Kernel'i audit ederken, özellikle başarının doğrudan `task->files`'a veya önceden yetkilendirilmiş diğer process resource'larına erişim sağladığı durumlarda, **task teardown** sırasında **ptrace-equivalent authorization** gerçekleştiren her path'i yüksek riskli kabul edin.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux Kernel ptrace Path'inde Local Root Privilege Escalation ve Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}

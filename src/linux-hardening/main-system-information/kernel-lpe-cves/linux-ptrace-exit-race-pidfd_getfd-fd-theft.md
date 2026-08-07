# Linux ptrace çıkış-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Kullanışlı bir **Linux kernel privesc pattern**, bir **ptrace authorization bug** durumunu ayrıcalıklı bir process'ten **file descriptor theft** elde etmek için kullanmaktır.

Qualys `__ptrace_may_access()` case study'sinde (CVE-2026-46333), attacker **exiting veya credentials düşüren ayrıcalıklı bir process'i** race eder ve attacker process'ine bir FD duplicate etmek için `pidfd_getfd()` kullanır.<sup>[[1]](#references)[[2]](#references)</sup>

## Temel fikir

`pidfd_getfd()`, başka bir process'ten bir file descriptor duplicate eder; ancak önce target'a karşı ptrace-style permissions kontrolü yapar. Bu authorization bir **teardown window** sırasında hatalı şekilde verilirse, unprivileged bir attacker şunları kopyalayabilir:

- Ayrıcalıklı bir helper tarafından önceden açılmış **sensitive files** için FDs
- Root olarak zaten authorized edilmiş **authenticated IPC channels** için FDs

Bu, kernel-side authorization bug durumunu oldukça pratik bir userspace primitive'e dönüştürür.<sup>[[1]](#references)</sup>

## Primitive neden tehlikelidir

Attack'in privileged helper'ın kendisinde bir bug bulunmasına **gerek yoktur**. Helper'ın yalnızca geçici olarak değerli bir şeyi elinde tutması yeterlidir:

- `/etc/shadow`
- `/etc/ssh/*_key`
- Ayrıcalıklı bir D-Bus / systemd connection
- Önceden açılmış herhangi bir secret veya authorized channel

Attacker process'ine duplicate edildikten sonra kernel, işlemleri original pathname veya yeni bir authentication flow üzerinde değil, **stolen FD** üzerinde uygular.<sup>[[1]](#references)</sup>

## Exploitation pattern

1. Sensitive files açan veya kullanışlı IPC connections tutan bir **setuid / setgid / file-capability binary** ya da **root daemon** belirleyin.
2. Target path için ilgili ptrace policy checks'i karşılayan bir relationship elde edin (örneğin permissive YAMA settings altında spawn edilmiş privileged child'ın **parent**'ı olmak).
3. Process'i **exiting**, **credentials düşürüyor** veya ptrace access'in kullanılamaz hale gelmesi gereken başka bir state'e giriyor olduğu sırada race edin.
4. Dar authorization window sırasında target FD'yi duplicate etmek için `pidfd_open()` + `pidfd_getfd()` kullanın.
5. Stolen FD'yi unprivileged context'ten yeniden kullanın:
- Privileged file descriptor'lardan secret'ları `read()` edin
- **Root-side actions** elde etmek için stolen authenticated IPC channel üzerinden requests gönderin<sup>[[1]](#references)</sup>

Minimal primitive shape:<sup>[[1]](#references)[[3]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Audit için pratik hedefler

Kısa süreliğine bile olsa aşağıdakilerden birini yapan binary ve daemon'lara öncelik verin:<sup>[[1]](#references)</sup>

- privilege geçişlerini tamamlamadan önce yalnızca root erişimine açık dosyaları açanlar
- **system bus**'a bağlanan ve önceden yetkilendirilmiş bir channel'ı açık tutanlar
- privileged FD'leri helper sınırları üzerinden aktaranlar
- `do_exit()`'e yakın teardown sırasında security-sensitive işlemler gerçekleştirenler

İyi hunting adayları:<sup>[[1]](#references)</sup>

- password / account management helper'ları
- SSH helper'ları
- PolicyKit / D-Bus aracılı helper'lar
- D-Bus method'ları sunan root desktop daemon'ları

## YAMA bir exploit gate olarak

`kernel.yama.ptrace_scope`, ptrace-family abuse için önemli bir pratik gate'tir:<sup>[[4]](#references)</sup>

- `0`: klasik aynı-UID ptrace davranışı
- `1`: genellikle parent -> child tracing'e izin verir; bu da bazı public exploit path'lerini erişilebilir tutabilir
- `2`: attach-style access için `CAP_SYS_PTRACE` gerektirir ve bu path'te unprivileged `pidfd_getfd()` abuse'unu engeller
- `3`: reboot gerçekleşene kadar ptrace attach'i tamamen devre dışı bırakır

Bu technique için `ptrace_scope=2`, unprivileged user'lar için public `pidfd_getfd()` exploitation path'ini `-EPERM` ile kırdığı için güçlü bir **geçici mitigation**'dır.<sup>[[1]](#references)</sup>

## Detection / review fikirleri

Privileged Linux software'ını audit ederken şu kombinasyonları arayın:

- **privileged child process** + **attacker-controlled parent**
- **değerli açık dosyalara** geçici erişim
- **authenticated D-Bus/systemd channel'larına** geçici erişim
- klasik `ptrace(2)` dışında **ptrace-style authorization** kullanan security kararları
- mevcut privileged FD'leri **duplicate, inherit veya re-export** edebilen kernel API'leri

Kernel'ı audit ederken, **task teardown** sırasında **ptrace-equivalent authorization** gerçekleştiren her path'i yüksek riskli kabul edin; özellikle de başarı, `task->files`'a veya zaten yetkilendirilmiş diğer process kaynaklarına doğrudan erişim sağlıyorsa.

## References

- [1] [CVE-2026-46333: Local Root Privilege Escalation and Credential Disclosure in the Linux Kernel ptrace Path (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}

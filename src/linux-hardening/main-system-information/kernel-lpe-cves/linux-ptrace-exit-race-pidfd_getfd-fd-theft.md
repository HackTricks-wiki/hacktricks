# Linux ptrace exit-race `pidfd_getfd()` FD theft

Kullanışlı bir **Linux kernel privesc pattern**, bir **ptrace authorization bug**'ını ayrıcalıklı bir process'ten **file descriptor theft** gerçekleştirmek için kullanmaktır.

Qualys `__ptrace_may_access()` case study'sinde (CVE-2026-46333), saldırgan **ayrıcalıklı bir process'in çıkış yaptığı veya credentials bıraktığı** sırada race gerçekleştirir ve saldırgan process'ine bir FD kopyalamak için `pidfd_getfd()` kullanır.<sup>[[1]](#references)[[2]](#references)</sup>

## Core idea

`pidfd_getfd()`, başka bir process'ten bir file descriptor kopyalar, ancak önce hedefe karşı ptrace-style permissions kontrolleri gerçekleştirir.<sup>[[3]](#references)</sup> Bu authorization bir **teardown window** sırasında hatalı şekilde verilirse, ayrıcalıksız bir saldırgan şunları kopyalayabilir:

- Ayrıcalıklı bir helper tarafından önceden açılmış **sensitive files** için FD'ler
- Halihazırda root olarak authorize edilmiş **authenticated IPC channels** için FD'ler

Bu, kernel-side authorization bug'ını oldukça pratik bir userspace primitive'e dönüştürür.<sup>[[1]](#references)</sup>

## Why the primitive is dangerous

Attack'in ayrıcalıklı helper'ın kendisinde bir bug bulunmasına gerek yoktur. Helper'ın yalnızca geçici olarak değerli bir şeyi elinde tutması yeterlidir:

- `/etc/shadow`
- `/etc/ssh/*_key`
- Ayrıcalıklı bir D-Bus / systemd connection
- Önceden açılmış başka herhangi bir secret veya authorized channel

Attacker process'ine kopyalandıktan sonra duplicate, aynı open file description'ı gösterir. Böylece sonraki read veya IPC request'leri, original pathname'i yeniden açmak ya da yeni bir authentication flow başlatmak yerine önceden açılmış FD'yi kullanır.<sup>[[2]](#references)[[3]](#references)</sup>

## Exploitation pattern

1. Sensitive files açan veya kullanışlı IPC connections tutan bir **setuid / setgid / file-capability binary** ya da **root daemon** belirleyin.<sup>[[2]](#references)</sup>
2. Target path için ilgili ptrace policy checks'i karşılayan bir relationship elde edin (örneğin permissive YAMA settings altında oluşturulmuş ayrıcalıklı bir child'ın **parent**'ı olmak).<sup>[[2]](#references)[[4]](#references)</sup>
3. Process **exiting**, **dropping credentials** veya ptrace access'in artık kullanılamaz olması gereken başka bir state'e girdiği sırada race gerçekleştirin.<sup>[[2]](#references)</sup>
4. Dar authorization window sırasında target FD'sini duplicate etmek için `pidfd_open()` + `pidfd_getfd()` kullanın.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Stolen FD'yi ayrıcalıksız context'ten yeniden kullanın.<sup>[[2]](#references)</sup>
- Ayrıcalıklı bir file descriptor'dan secret'ları `read()` ile okuyun
- **root-side actions** gerçekleştirmek için stolen authenticated IPC channel üzerinden requests gönderin

Minimal primitive shape.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Denetlenecek pratik hedefler

Kısa bir süreliğine bile olsa aşağıdakilerden birini yapan binary ve daemon'lara öncelik verin:<sup>[[1]](#references)[[2]](#references)</sup>

- yetki geçişlerini tamamlamadan önce yalnızca root tarafından erişilebilen dosyaları açmak
- **system bus**'a bağlanmak ve zaten yetkilendirilmiş bir kanalı açık tutmak
- ayrıcalıklı FD'leri helper sınırları üzerinden geçirmek
- `do_exit()` ile ilişkili teardown sırasında güvenlik açısından hassas işlemler gerçekleştirmek

İyi hunting adayları:<sup>[[1]](#references)</sup>

- parola / hesap yönetimi helper'ları
- SSH helper'ları
- PolicyKit / D-Bus aracılı helper'lar
- D-Bus metotlarını dışa açan root desktop daemon'ları

## Exploit kapısı olarak YAMA

`kernel.yama.ptrace_scope`, ptrace-family abuse için önemli bir pratik kapıdır:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: klasik aynı UID ptrace davranışı
- `1`: genellikle parent -> child tracing'e izin verir; bu da bazı public exploit path'lerini erişilebilir tutabilir
- `2`: attach-style erişim için `CAP_SYS_PTRACE` gerektirir ve bu path'te ayrıcalıksız `pidfd_getfd()` abuse'ını engeller
- `3`: reboot edilene kadar ptrace attach'i tamamen devre dışı bırakır

Bu teknik için `ptrace_scope=2`, ayrıcalıksız kullanıcılar açısından public `pidfd_getfd()` exploitation path'ini `-EPERM` ile kırdığı için güçlü bir **geçici mitigation**'dır.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Detection / review fikirleri

Ayrıcalıklı Linux yazılımlarını denetlerken şu kombinasyonları arayın:

- **ayrıcalıklı child process** + **saldırganın kontrolündeki parent**.<sup>[[2]](#references)[[4]](#references)</sup>
- **değerli açık dosyalara** geçici erişim
- **authenticated D-Bus/systemd kanallarına** geçici erişim.<sup>[[2]](#references)</sup>
- klasik `ptrace(2)` dışında **ptrace-style authorization** kullanan güvenlik kararları
- mevcut ayrıcalıklı FD'leri **duplicate, inherit veya re-export** edebilen kernel API'leri

Kernel'i denetlerken, **task teardown** sırasında **ptrace-equivalent authorization** gerçekleştiren tüm path'leri yüksek riskli kabul edin; özellikle de başarı, `task->files` veya önceden yetkilendirilmiş diğer process kaynaklarına doğrudan erişim sağlıyorsa.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Linux Kernel ptrace Path'inde Local Root Privilege Escalation ve Credential Disclosure (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [Qualys advisory TXT](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [pidfd_getfd(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Linux kernel Yama documentation](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [pidfd_open(2) manual page](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}

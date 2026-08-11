# Linux ptrace exit-race `pidfd_getfd()` крадіжка FD

{{#include ../../../banners/hacktricks-training.md}}

Корисний **патерн privesc у ядрі Linux** полягає в перетворенні **помилки авторизації ptrace** на **крадіжку дескриптора файлу** з привілейованого процесу.

У case study Qualys щодо `__ptrace_may_access()` (CVE-2026-46333) attacker створює race з **привілейованим процесом, який завершується або скидає credentials**, і використовує `pidfd_getfd()` для дублювання FD у процес attacker-а.<sup>[[1]](#references)[[2]](#references)</sup>

## Основна ідея

`pidfd_getfd()` дублює дескриптор файлу з іншого процесу, але спочатку перевіряє дозволи у стилі ptrace щодо target-а.<sup>[[3]](#references)</sup> Якщо ця авторизація помилково надається протягом **вікна teardown**, unprivileged attacker може скопіювати:

- FD для **sensitive files**, уже відкритих привілейованим helper-ом
- FD для **authenticated IPC channels**, уже авторизованих як root

Це перетворює помилку авторизації на рівні kernel на дуже практичний primitive у userspace.<sup>[[1]](#references)</sup>

## Чому цей primitive небезпечний

Для атаки **не потрібна помилка в самому привілейованому helper-і**. Helper лише має тимчасово утримувати щось цінне:

- `/etc/shadow`
- `/etc/ssh/*_key`
- привілейоване D-Bus / systemd connection
- будь-який інший уже відкритий secret або authorized channel

Після дублювання у процес attacker-а дублікат посилається на той самий open file description, тому наступні операції читання або IPC використовують уже відкритий FD, а не повторно відкривають оригінальний pathname і не запускають новий authentication flow.<sup>[[2]](#references)[[3]](#references)</sup>

## Патерн exploitation

1. Визначити **setuid / setgid / file-capability binary** або **root daemon**, який відкриває sensitive files чи підтримує корисні IPC connections.<sup>[[2]](#references)</sup>
2. Отримати relationship, який задовольняє відповідні policy checks ptrace для target path (наприклад, бути **parent** створеного привілейованого child за permissive налаштувань YAMA).<sup>[[2]](#references)[[4]](#references)</sup>
3. Створити race з процесом, поки він **завершується**, **скидає credentials** або іншим чином переходить у стан, у якому доступ ptrace уже мав би стати недоступним.<sup>[[2]](#references)</sup>
4. Використати `pidfd_open()` + `pidfd_getfd()` для дублювання target FD протягом вузького вікна авторизації.<sup>[[2]](#references)[[3]](#references)[[5]](#references)</sup>
5. Повторно використати stolen FD з unprivileged context.<sup>[[2]](#references)</sup>
- `read()` secrets із привілейованого file descriptor
- надсилати requests через stolen authenticated IPC channel для отримання **root-side actions**

Мінімальна форма primitive.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Практичні цілі для аудиту

Пріоритезуйте бінарні файли та демони, які навіть протягом короткого часу роблять одне з наведеного:<sup>[[1]](#references)[[2]](#references)</sup>

- відкривають файли, доступні лише `root`, до завершення переходів привілеїв
- підключаються до **системної шини** та зберігають уже авторизований канал
- передають привілейовані FDs через межі helper-процесів
- виконують чутливі до безпеки операції під час teardown, суміжного з `do_exit()`

Хороші кандидати для пошуку:<sup>[[1]](#references)</sup>

- helper-програми для керування паролями / обліковими записами
- SSH helpers
- helper-програми, опосередковані PolicyKit / D-Bus
- root desktop daemons, які надають методи D-Bus

## YAMA як exploit gate

`kernel.yama.ptrace_scope` є важливим практичним gate для зловживань сімейством ptrace:<sup>[[3]](#references)[[4]](#references)</sup>

- `0`: класична поведінка ptrace для одного UID
- `1`: зазвичай дозволяє трасування parent -> child, що може зберігати доступність деяких public exploit paths
- `2`: вимагає `CAP_SYS_PTRACE` для доступу attach-style і блокує непривілейоване зловживання `pidfd_getfd()` у цьому path
- `3`: повністю вимикає ptrace attach до перезавантаження

Для цієї техніки `ptrace_scope=2` є надійним **тимчасовим заходом пом’якшення**, оскільки він ламає public `pidfd_getfd()` exploitation path, повертаючи `-EPERM` для непривілейованих користувачів.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Ідеї для виявлення / review

Під час аудиту привілейованого Linux software шукайте такі комбінації:

- **привілейований child process** + **parent, контрольований attacker’ом**.<sup>[[2]](#references)[[4]](#references)</sup>
- тимчасовий доступ до **цінних відкритих файлів**
- тимчасовий доступ до **автентифікованих каналів D-Bus/systemd**.<sup>[[2]](#references)</sup>
- security-рішення, які повторно використовують **авторизацію у стилі ptrace** поза межами класичного `ptrace(2)`
- kernel APIs, здатні **дублювати, успадковувати або повторно експортувати** наявні привілейовані FDs

Під час аудиту kernel вважайте високоризиковим будь-який path, який виконує **ptrace-equivalent authorization** під час **task teardown**, особливо якщо успішне виконання надає прямий доступ до `task->files` або інших уже авторизованих process resources.<sup>[[2]](#references)</sup>

## References

- [1] [CVE-2026-46333: Локальне підвищення привілеїв до root і розкриття облікових даних у ptrace path Linux kernel (Qualys)](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [2] [TXT-консультація Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [3] [Сторінка довідки pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [4] [Документація Linux kernel щодо Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [5] [Сторінка довідки pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html)
{{#include ../../../banners/hacktricks-training.md}}

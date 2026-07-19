# Linux ptrace exit-race `pidfd_getfd()` FD theft

{{#include ../../../banners/hacktricks-training.md}}

Корисний **Linux kernel privesc pattern** полягає в перетворенні **ptrace authorization bug** на **file descriptor theft** із привілейованого процесу.

У case study Qualys щодо `__ptrace_may_access()` (CVE-2026-46333) зловмисник створює race з **привілейованим процесом, який завершує роботу або скидає credentials**, і використовує `pidfd_getfd()`, щоб продублювати FD у процес зловмисника.

## Core idea

`pidfd_getfd()` дублює file descriptor з іншого процесу, але спочатку перевіряє ptrace-style permissions щодо цільового процесу. Якщо цей дозвіл помилково надається під час **teardown window**, unprivileged attacker може скопіювати:

- FD для **sensitive files**, уже відкритих привілейованим helper
- FD для **authenticated IPC channels**, уже авторизованих як root

Це перетворює authorization bug на рівні kernel на дуже практичний userspace primitive.

## Why the primitive is dangerous

Для атаки **не потрібен bug у самому привілейованому helper**. Helper має лише тимчасово утримувати щось цінне:

- `/etc/shadow`
- `/etc/ssh/*_key`
- привілейоване D-Bus / systemd connection
- будь-який інший уже відкритий secret або authorized channel

Після дублювання у процес зловмисника kernel застосовує операції до **stolen FD**, а не до оригінального pathname чи нового authentication flow.

## Exploitation pattern

1. Identify **setuid / setgid / file-capability binary** або **root daemon**, який відкриває sensitive files чи підтримує корисні IPC connections.
2. Establish relationship, що відповідає relevant ptrace policy checks для target path (наприклад, бути **parent** породженого privileged child за permissive налаштувань YAMA).
3. Створити race з процесом, поки він **завершує роботу**, **скидає credentials** або іншим чином переходить у стан, у якому ptrace access уже мав би стати недоступним.
4. Використати `pidfd_open()` + `pidfd_getfd()`, щоб продублювати target FD протягом вузького authorization window.
5. Повторно використати stolen FD з unprivileged context:
- `read()` secrets із privileged file descriptor
- надсилати requests через stolen authenticated IPC channel, щоб отримувати **root-side actions**

Minimal primitive shape:
```c
int p = pidfd_open(victim_pid, 0);
int stolen = pidfd_getfd(p, victim_fd, 0);
/* use stolen with read()/write()/sendmsg()/ioctl() depending on target */
```
## Практичні цілі для аудиту

Надавайте пріоритет бінарним файлам і daemon, які, навіть ненадовго, роблять одну з таких дій:

- відкривають файли, доступні лише root, до завершення переходів привілеїв
- підключаються до **system bus** і зберігають уже авторизований канал
- передають привілейовані FD через межі helper-процесів
- виконують чутливі до безпеки операції під час teardown, суміжного з `do_exit()`

Добрі кандидати для hunting:

- helper-процеси для керування паролями / обліковими записами
- SSH helper-процеси
- helper-процеси, опосередковані PolicyKit / D-Bus
- root desktop daemon, які відкривають методи D-Bus

## YAMA як exploit gate

`kernel.yama.ptrace_scope` є важливим практичним обмежувачем для зловживань сімейством ptrace:

- `0`: класична поведінка ptrace для одного UID
- `1`: зазвичай дозволяє трасування parent -> child, що може зберігати доступність деяких public exploit paths
- `2`: вимагає `CAP_SYS_PTRACE` для доступу в режимі attach і блокує зловживання `pidfd_getfd()` непривілейованими користувачами в цьому path
- `3`: повністю вимикає ptrace attach до перезавантаження

Для цієї техніки `ptrace_scope=2` є сильним **тимчасовим mitigation**, оскільки він ламає public `pidfd_getfd()` exploitation path, повертаючи `-EPERM` для непривілейованих користувачів.

## Ідеї для detection / review

Під час аудиту привілейованого Linux software шукайте такі комбінації:

- **privileged child process** + **attacker-controlled parent**
- тимчасовий доступ до **цінних відкритих файлів**
- тимчасовий доступ до **автентифікованих D-Bus/systemd каналів**
- рішення щодо безпеки, які повторно використовують **ptrace-style authorization** поза межами класичного `ptrace(2)`
- kernel API, здатні **дублювати, успадковувати або повторно експортувати** наявні привілейовані FD

Під час аудиту kernel вважайте high risk будь-який path, який виконує **ptrace-equivalent authorization** під час **task teardown**, особливо якщо успіх надає прямий доступ до `task->files` або інших уже авторизованих process resources.

## Посилання

- [Блог Qualys: CVE-2026-46333](https://blog.qualys.com/vulnerabilities-threat-research/2026/05/20/cve-2026-46333-local-root-privilege-escalation-and-credential-disclosure-in-the-linux-kernel-ptrace-path)
- [Текст рекомендацій Qualys](https://cdn2.qualys.com/advisory/2026/05/20/cve-2026-46333-ptrace.txt)
- [Сторінка посібника pidfd_getfd(2)](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html)
- [Документація Linux kernel щодо Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

{{#include ../../../banners/hacktricks-training.md}}

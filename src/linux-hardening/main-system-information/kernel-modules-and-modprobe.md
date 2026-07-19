# Missbrauch von Kernelmodulen und modprobe

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen von Kernelmodulen und dem Laden von Modulen

Die Unterstützung für Kernelmodule ist ein wichtiger Bereich bei der Überprüfung auf Linux privilege escalation. Behandle nicht jede Meldung zu unsignierten Modulen automatisch als ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten:

- Kann der aktuelle Benutzer Module über `sudo`, Capabilities oder einen beschreibbaren Helper-Pfad laden?
- Ist das Laden von Modulen weiterhin aktiviert?
- Ist die Durchsetzung von Modulsignaturen deaktiviert?
- Sind Modulverzeichnisse oder Moduldateien beschreibbar?
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Schnellprüfung:
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
- `dmesg_restrict=0` ermöglicht es nicht privilegierten Benutzern auf vielen Systemen, Kernel-Logs zu lesen.
- Schreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da die Modulsuche und das automatische Laden diesem Verzeichnisbaum vertrauen können.

### Laden eines Moduls und Lesen der Kernel-Ausgabe

Wenn du die entsprechende Berechtigung zum Laden eines lokalen Moduls hast, fügt `insmod` die von dir angegebene `.ko`-Datei exakt ein. Die Init-Funktion des Moduls wird sofort ausgeführt, und mit `printk()` geschriebene Nachrichten erscheinen in den Kernel-Logs.

Minimaler Ablauf für Review- oder Laborumgebungen:
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
### Sudo-allowed `insmod`

Eine sudo-Regel, die einem Benutzer die Ausführung von `insmod` erlaubt, ist nicht mit der Erlaubnis zur Ausführung eines gewöhnlichen administrativen Hilfsprogramms vergleichbar. Der Initialisierungscode des Moduls wird sofort im Kernel-Kontext ausgeführt, sobald die `.ko`-Datei eingefügt wurde. Die entscheidende Frage bei der praktischen Überprüfung lautet daher: „Kann dieser Benutzer das zu ladende Modul auswählen oder verändern?“

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
Wenn der Benutzer ein beliebiges `.ko` bereitstellen kann, sollte dies bei einer autorisierten Prüfung als vollständige Kompromittierung des Systems eingestuft werden. Ein sichereres Vorgehensmuster besteht darin, das Laden von Modulen nicht über sudo zu delegieren. Falls dies unvermeidbar ist, sollten der genaue Pfad, Eigentümer, Berechtigungen, die Signaturrichtlinie und der Ablauf zur Entfernung eingeschränkt beziehungsweise festgelegt werden.

Für ein harmloses Muster zum Erstellen eines Moduls in einer kontrollierten Laborumgebung sehen eine minimale Quelldatei und ein Makefile wie folgt aus:
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

`kernel.modprobe` steuert den Userspace-Helfer, den der Kernel aufruft, wenn er Unterstützung beim Laden von Modulen benötigt. Wenn ein Angreifer den Wert in einen Pfad zu einer beschreibbaren ausführbaren Datei ändern und ein unbekanntes Binärformat oder einen anderen Pfad für Modulanforderungen auslösen kann, kann dies zu Root-Codeausführung führen.

Überprüfe den aktuellen Helfer:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Prüfe, ob du es beeinflussen kannst:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Generisches, nur für Labore bestimmtes Muster:
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

### Überprüfung beschreibbarer `/lib/modules`-Verzeichnisse

Beschreibbare Modulverzeichnisse können je nach späterem Aufruf von `modprobe` den Austausch von Modulen, das Platzieren schädlicher Module oder den Missbrauch des Auto-Loads ermöglichen.

Überprüfe beschreibbare Speicherorte:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Wenn du beschreibbare Modulinhalte findest, überprüfe, wie Module entdeckt werden:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive Hinweise:

- `/lib/modules` im Besitz von `root:root` belassen und für Benutzer nicht beschreibbar machen.
- `kernel.modules_disabled=1` nach dem Booten setzen, sofern dies betrieblich möglich ist.
- Auf Systemen, die ladbare Module benötigen, das Signieren von Modulen erzwingen.
- Schreibzugriffe auf `/proc/sys/kernel/modprobe` und `/lib/modules` sowie unerwartete Ausführungen von `insmod`/`modprobe` überwachen.
{{#include ../../banners/hacktricks-training.md}}

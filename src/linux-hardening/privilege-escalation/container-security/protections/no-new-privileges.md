# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist eine Kernel-Härtungsfunktion, die verhindert, dass ein Prozess durch `execve()` zusätzliche Privilegien erlangt. Praktisch bedeutet das: Sobald das Flag gesetzt ist, gewährt das Ausführen eines setuid binary, eines setgid binary oder einer Datei mit Linux file capabilities keine zusätzlichen Privilegien über das hinaus, was der Prozess bereits hatte. In containerisierten Umgebungen ist das wichtig, weil viele privilege-escalation chains darauf angewiesen sind, ein ausführbares Programm innerhalb des image zu finden, das beim Start Privilegien ändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für namespaces, seccomp oder capability dropping. Es ist eine zusätzliche Verstärkungsschicht. Es blockiert eine bestimmte Klasse nachfolgender Eskalationen, nachdem bereits Codeausführung erreicht wurde. Deshalb ist es besonders wertvoll in Umgebungen, in denen images helper binaries, package-manager artifacts oder legacy tools enthalten, die in Kombination mit einer teilweisen Kompromittierung gefährlich wären.

## Funktionsweise

Das Kernel-Flag hinter diesem Verhalten ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt ist, können spätere `execve()`-Aufrufe die Privilegien nicht erhöhen. Wichtig ist, dass der Prozess weiterhin binaries ausführen kann; er kann diese binaries lediglich nicht verwenden, um eine Privilegiengrenze zu überschreiten, die der Kernel sonst anerkennen würde.

In Kubernetes-orientierten Umgebungen entspricht `allowPrivilegeEscalation: false` diesem Verhalten für den Containerprozess. In Docker- und Podman-ähnlichen Runtimes wird das Äquivalent üblicherweise explizit über eine Sicherheitsoption aktiviert.

## Labor

Untersuche den aktuellen Prozesszustand:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleichen Sie das mit einem container, in dem die runtime das flag aktiviert:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Bei einem gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

## Sicherheitsauswirkung

Wenn `no_new_privs` fehlt, kann ein Zugang im Container weiterhin durch setuid-Helfer oder Binaries mit file capabilities hochgestuft werden. Ist es gesetzt, werden diese Privilegänderungen nach der Ausführung unterbunden. Der Effekt ist besonders relevant bei umfangreichen Basis-Images, die viele Utilities mitliefern, die die Anwendung nie benötigt hat.

## Fehlkonfigurationen

Das häufigste Problem ist, die Kontrolle in Umgebungen nicht zu aktivieren, in denen sie kompatibel wäre. In Kubernetes ist es ein häufiger Betriebsfehler, `allowPrivilegeEscalation` aktiviert zu lassen. In Docker und Podman hat das Weglassen der relevanten Sicherheitsoption denselben Effekt. Ein weiterer wiederkehrender Fehler ist die Annahme, dass Exec-zeitliche Privilegübergänge automatisch irrelevant sind, weil ein Container als "not privileged" gilt.

## Missbrauch

Falls `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image Binaries enthält, die noch Privilegien erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid-Hilfsprogramme wie `su`, `mount`, `passwd` oder distributionsspezifische Admin-Tools
- Binaries mit file capabilities, die Netzwerk- oder Dateisystem-Privilegien gewähren

### Vollständiges Beispiel: In-Container Privilege Escalation durch setuid

Diese Kontrolle verhindert normalerweise **in-container privilege escalation**, anstatt direktes host escape. Wenn `NoNewPrivs` `0` ist und ein setuid helper vorhanden ist, teste ihn explizit:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn ein bekanntes setuid binary vorhanden und funktionsfähig ist, versuche, es so zu starten, dass die Privilegienübergabe erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Das führt nicht automatisch zu einem Container-Escape, kann aber eine niedrig-privilegierte Fußfeste im Container in root-Rechte im Container umwandeln, was oft die Voraussetzung für ein späteres Host-Escape über Mounts, Runtime-Sockets oder kernel-nahe Schnittstellen wird.

## Prüfungen

Das Ziel dieser Prüfungen ist festzustellen, ob eine Erhöhung der Privilegien zur Laufzeit blockiert wird und ob das Image noch Helfer enthält, die relevant wären, falls dem nicht so ist.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Was hier interessant ist:

- `NoNewPrivs: 1` ist in der Regel das sicherere Ergebnis.
- `NoNewPrivs: 0` bedeutet, dass setuid- und file-cap-basierte Eskalationspfade weiterhin relevant sind.
- Ein minimales Image mit wenigen oder keinen setuid/file-cap-Binärdateien bietet einem Angreifer weniger post-exploitation-Optionen, selbst wenn `no_new_privs` fehlt.

## Standardwerte zur Laufzeit

| Laufzeit / Plattform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Wird explizit mit `--security-opt no-new-privileges=true` aktiviert | Weglassen des Flags, `--privileged` |
| Podman | Standardmäßig nicht aktiviert | Wird explizit mit `--security-opt no-new-privileges` oder einer äquivalenten Sicherheitskonfiguration aktiviert | Auslassen der Option, `--privileged` |
| Kubernetes | Gesteuert durch Workload-Richtlinien | `allowPrivilegeEscalation: false` aktiviert die Wirkung; viele Workloads lassen es dennoch aktiviert | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Folgt den Kubernetes-Workload-Einstellungen | Normalerweise vom Pod-Sicherheitskontext vererbt | gleich wie in der Kubernetes-Zeile |

Dieser Schutz ist oft einfach dadurch nicht vorhanden, dass niemand ihn eingeschaltet hat, nicht weil die Laufzeit keine Unterstützung dafür bietet.
{{#include ../../../../banners/hacktricks-training.md}}

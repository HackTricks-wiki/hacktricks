# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist ein Kernel-Hardening-Feature, das verhindert, dass ein Prozess über `execve()` zusätzliche Privilegien erhält. Praktisch bedeutet das: Sobald das Flag gesetzt ist, gewährt das Ausführen einer setuid-Binary, einer setgid-Binary oder einer Datei mit Linux file capabilities keine zusätzlichen Privilegien über das hinaus, was der Prozess bereits hatte. In containerisierten Umgebungen ist das wichtig, weil viele privilege-escalation-Ketten darauf angewiesen sind, eine ausführbare Datei im Image zu finden, die beim Start Privilegien verändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für namespaces, seccomp oder capability dropping. Es ist eine Verstärkungsebene. Es blockiert eine spezifische Klasse von Folgeeskalationen, nachdem bereits Codeausführung erlangt wurde. Das macht es besonders wertvoll in Umgebungen, in denen Images Hilfsbinaries, package-manager-Artefakte oder Legacy-Tools enthalten, die in Kombination mit einer Teilkompromittierung gefährlich wären.

## Operation

Das Kernel-Flag hinter diesem Verhalten ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt ist, können spätere `execve()`-Aufrufe Privilegien nicht erhöhen. Wichtiger Punkt: Der Prozess kann weiterhin Binaries ausführen; er kann diese Binaries nur nicht dazu verwenden, eine Privilegiengrenze zu überschreiten, die der Kernel sonst anerkennen würde.

In Kubernetes-orientierten Umgebungen entspricht `allowPrivilegeEscalation: false` diesem Verhalten für den Containerprozess. In Docker und Podman style runtimes wird das Äquivalent üblicherweise explizit über eine Security-Option aktiviert.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleichen Sie das mit einem Container, bei dem die runtime das flag aktiviert:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Bei einem gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

## Sicherheitsauswirkung

Wenn `no_new_privs` fehlt, kann ein foothold innerhalb des Containers weiterhin über setuid helpers oder Binärdateien mit file capabilities aufgewertet werden. Wenn es gesetzt ist, werden diese post-exec privilege changes unterbunden. Der Effekt ist besonders relevant in umfangreichen base images, die viele utilities mitliefern, die die Anwendung von vornherein nie benötigt hat.

## Fehlkonfigurationen

Das häufigste Problem ist einfach, die Kontrolle nicht zu aktivieren in Umgebungen, in denen sie kompatibel wäre. In Kubernetes ist es oft der betriebliche Standardfehler, `allowPrivilegeEscalation` aktiviert zu lassen. In Docker und Podman hat das Weglassen der entsprechenden Sicherheitsoption die gleiche Wirkung. Ein weiterer wiederkehrender Fehler ist die Annahme, dass, weil ein Container "not privileged" ist, exec-time privilege transitions automatisch irrelevant sind.

## Missbrauch

Wenn `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image Binärdateien enthält, die weiterhin Privilegien erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid helpers wie `su`, `mount`, `passwd` oder distribution-spezifische Admin-Tools
- Binaries mit file capabilities, die Netzwerk- oder Dateisystem-Privilegien gewähren

In einer realen Bewertung beweisen diese Befunde für sich genommen keine funktionierende Escalation, identifizieren jedoch genau die Binaries, die als Nächstes getestet werden sollten.

### Vollständiges Beispiel: In-Container Privilege Escalation Through setuid

Diese Kontrolle verhindert in der Regel **in-container privilege escalation** eher als ein direktes host escape. Wenn `NoNewPrivs` `0` ist und ein setuid helper vorhanden ist, teste ihn explizit:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn ein bekanntes setuid binary vorhanden und funktionsfähig ist, versuchen Sie, es so zu starten, dass der Privilegübergang erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Das entkommt dem container nicht von selbst, kann aber einen low-privilege foothold im container in container-root verwandeln, was oft die Voraussetzung für einen späteren host escape über mounts, runtime sockets oder kernel-facing interfaces ist.

## Checks

Das Ziel dieser Checks ist festzustellen, ob exec-time privilege gain blockiert ist und ob das image noch helpers enthält, die relevant wären, falls dies nicht der Fall ist.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Was hier interessant ist:

- `NoNewPrivs: 1` ist normalerweise das sicherere Ergebnis.
- `NoNewPrivs: 0` bedeutet, dass setuid- und file-cap-basierte Escalation-Pfade weiterhin relevant sind.
- Ein minimales Image mit wenigen oder keinen setuid-/file-cap-Binaries bietet einem Angreifer weniger Post-Exploitation-Optionen, selbst wenn `no_new_privs` fehlt.

## Runtime-Standardeinstellungen

| Runtime / platform | Standardzustand | Standardverhalten | Häufige manuelle Abschwächung |
| --- | --- | --- | --- |
| Docker Engine | Nicht standardmäßig aktiviert | Explizit aktiviert mit `--security-opt no-new-privileges=true` | Weglassen des Flags, `--privileged` |
| Podman | Nicht standardmäßig aktiviert | Explizit aktiviert mit `--security-opt no-new-privileges` oder entsprechender Sicherheitskonfiguration | Weglassen der Option, `--privileged` |
| Kubernetes | Durch Workload-Policy gesteuert | `allowPrivilegeEscalation: false` erzeugt den Effekt; viele Workloads lassen es weiterhin aktiviert | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Folgt den Kubernetes-Workload-Einstellungen | Üblicherweise vom Pod-Sicherheitskontext vererbt | wie in der Kubernetes-Zeile |

Dieser Schutz fehlt häufig einfach, weil niemand ihn aktiviert hat, nicht weil die Runtime keine Unterstützung dafür bietet.

# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ist eine Kernel-Härtungsfunktion, die verhindert, dass ein Prozess über `execve()` zusätzliche Privilegien erlangt. Praktisch bedeutet das: Sobald das Flag gesetzt ist, gewährt das Ausführen einer setuid binary, einer setgid binary oder einer Datei mit Linux file capabilities keine zusätzlichen Privilegien über das hinaus, was der Prozess bereits besitzt. In containerisierten Umgebungen ist das wichtig, weil viele privilege-escalation chains darauf angewiesen sind, ein ausführbares Programm im Image zu finden, das beim Start Privilegien ändert.

Aus defensiver Sicht ist `no_new_privs` kein Ersatz für namespaces, seccomp oder capability dropping. Es ist eine Verstärkungsschicht. Es blockiert eine bestimmte Klasse von Folgeeskalationen, nachdem bereits Codeausführung erzielt wurde. Das macht es besonders wertvoll in Umgebungen, in denen Images Hilfsbinaries, package-manager artifacts oder Legacy-Tools enthalten, die bei teilweiser Kompromittierung gefährlich werden könnten.

## Operation

Das Kernel-Flag, das dieses Verhalten steuert, ist `PR_SET_NO_NEW_PRIVS`. Sobald es für einen Prozess gesetzt ist, können spätere `execve()`-Aufrufe die Privilegien nicht erhöhen. Wichtig ist, dass der Prozess weiterhin Binaries ausführen kann; er kann diese Binaries nur nicht dazu verwenden, eine Privilegiengrenze zu überschreiten, die der Kernel sonst anerkennen würde.

In Kubernetes-orientierten Umgebungen bildet `allowPrivilegeEscalation: false` dieses Verhalten für den Containerprozess ab. In Docker- und Podman-ähnlichen Runtimes wird das Äquivalent üblicherweise explizit über eine security option aktiviert.

## Labor

Untersuche den Zustand des aktuellen Prozesses:
```bash
grep NoNewPrivs /proc/self/status
```
Vergleiche das mit einem Container, bei dem die runtime das Flag aktiviert ist:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Auf einem gehärteten Workload sollte das Ergebnis `NoNewPrivs: 1` anzeigen.

## Sicherheitsauswirkungen

Wenn `no_new_privs` fehlt, kann eine im Container gewonnene Ausgangsposition weiterhin durch setuid-Helfer oder Binärdateien mit file capabilities zu höheren Rechten eskalieren. Wenn es gesetzt ist, werden diese nach dem Exec auftretenden Privilegienänderungen unterbunden. Dieser Effekt ist besonders relevant bei breit angelegten base images, die viele Utilities mitliefern, die die Anwendung eigentlich nie benötigt hat.

## Fehlkonfigurationen

Das häufigste Problem ist schlicht, die Kontrolle in Umgebungen nicht zu aktivieren, in denen sie kompatibel wäre. In Kubernetes ist es oft der betriebliche Standardfehler, `allowPrivilegeEscalation` aktiviert zu lassen. In Docker und Podman hat das Weglassen der entsprechenden Sicherheitsoption denselben Effekt. Ein weiterer wiederkehrender Fehler ist die Annahme, dass Privilegienübergänge zur Laufzeit automatisch irrelevant sind, nur weil ein Container "not privileged" ist.

## Missbrauch

Wenn `no_new_privs` nicht gesetzt ist, lautet die erste Frage, ob das Image Binärdateien enthält, die Privilegien noch erhöhen können:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interessante Ergebnisse umfassen:

- `NoNewPrivs: 0`
- setuid-Helfer wie `su`, `mount`, `passwd` oder distributionsspezifische Admin-Tools
- Binaries mit file capabilities, die Netzwerk- oder Dateisystem-Privilegien gewähren

In einer echten Bewertung beweisen diese Befunde für sich genommen keine funktionierende Eskalation, identifizieren jedoch genau die Binaries, die als Nächstes getestet werden sollten.

### Vollständiges Beispiel: In-Container Privilege Escalation Through setuid

Diese Kontrolle verhindert in der Regel **in-container privilege escalation** und nicht direkt einen host escape. Wenn `NoNewPrivs` `0` ist und ein setuid-Helfer existiert, teste ihn explizit:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Wenn ein bekanntes setuid binary vorhanden und funktionsfähig ist, versuche, es so zu starten, dass der Privilegienübergang erhalten bleibt:
```bash
/bin/su -c id 2>/dev/null
```
Das entkommt dadurch nicht automatisch dem Container, kann aber einen low-privilege foothold innerhalb des Containers in container-root umwandeln, was häufig zur Voraussetzung für späteres Host-Escape über mounts, runtime sockets oder kernel-facing interfaces wird.

## Checks

Das Ziel dieser Checks ist es festzustellen, ob exec-time privilege gain blockiert ist und ob das Image noch helpers enthält, die relevant wären, falls dies nicht der Fall ist.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Was hier interessant ist:

- `NoNewPrivs: 1` ist normalerweise das sicherere Ergebnis.
- `NoNewPrivs: 0` bedeutet, dass setuid- und file-cap-basierte Eskalationspfade relevant bleiben.
- Ein minimales Image mit wenigen oder keinen setuid-/file-cap-Binärdateien bietet einem Angreifer weniger Post-Exploitation-Optionen, selbst wenn `no_new_privs` fehlt.

## Laufzeit-Standardeinstellungen

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Standardmäßig nicht aktiviert | Wird explizit mit `--security-opt no-new-privileges=true` aktiviert | Auslassen des Flags, `--privileged` |
| Podman | Standardmäßig nicht aktiviert | Wird explizit mit `--security-opt no-new-privileges` oder entsprechender Sicherheitskonfiguration aktiviert | Auslassen der Option, `--privileged` |
| Kubernetes | Wird durch die Workload-Policy gesteuert | `allowPrivilegeEscalation: false` aktiviert die Schutzwirkung; viele Workloads lassen es trotzdem aktiviert | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O unter Kubernetes | Folgt den Kubernetes-Workload-Einstellungen | Üblicherweise vom Pod-Sicherheitskontext geerbt | wie in der Kubernetes-Zeile |

Dieser Schutz fehlt oft einfach, weil niemand ihn eingeschaltet hat, nicht weil die Runtime keine Unterstützung dafür bietet.
{{#include ../../../../banners/hacktricks-training.md}}

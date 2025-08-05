# Zeit-Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Der Zeit-Namespace in Linux ermöglicht offsets pro Namespace zu den systemeigenen monotonen und Boot-Zeituhren. Er wird häufig in Linux-Containern verwendet, um das Datum/die Uhrzeit innerhalb eines Containers zu ändern und Uhren nach der Wiederherstellung von einem Checkpoint oder Snapshot anzupassen.

## Labor:

### Verschiedene Namespaces erstellen

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Durch das Einhängen einer neuen Instanz des `/proc` Dateisystems, wenn Sie den Parameter `--mount-proc` verwenden, stellen Sie sicher, dass der neue Mount-Namespace eine **genaue und isolierte Sicht auf die Prozessinformationen hat, die spezifisch für diesen Namespace sind**.

<details>

<summary>Fehler: bash: fork: Kann Speicher nicht zuweisen</summary>

Wenn `unshare` ohne die Option `-f` ausgeführt wird, tritt ein Fehler auf, der auf die Art und Weise zurückzuführen ist, wie Linux neue PID (Process ID) Namespaces behandelt. Die wichtigsten Details und die Lösung sind unten aufgeführt:

1. **Problembeschreibung**:

- Der Linux-Kernel erlaubt es einem Prozess, neue Namespaces mit dem Systemaufruf `unshare` zu erstellen. Der Prozess, der die Erstellung eines neuen PID-Namespace initiiert (als "unshare" Prozess bezeichnet), tritt jedoch nicht in den neuen Namespace ein; nur seine Kindprozesse tun dies.
- Das Ausführen von `%unshare -p /bin/bash%` startet `/bin/bash` im selben Prozess wie `unshare`. Folglich befinden sich `/bin/bash` und seine Kindprozesse im ursprünglichen PID-Namespace.
- Der erste Kindprozess von `/bin/bash` im neuen Namespace wird PID 1. Wenn dieser Prozess beendet wird, wird die Bereinigung des Namespaces ausgelöst, wenn keine anderen Prozesse vorhanden sind, da PID 1 die besondere Rolle hat, verwaiste Prozesse zu übernehmen. Der Linux-Kernel deaktiviert dann die PID-Zuweisung in diesem Namespace.

2. **Folge**:

- Das Verlassen von PID 1 in einem neuen Namespace führt zur Bereinigung des `PIDNS_HASH_ADDING` Flags. Dies führt dazu, dass die Funktion `alloc_pid` fehlschlägt, um eine neue PID zuzuweisen, wenn ein neuer Prozess erstellt wird, was den Fehler "Kann Speicher nicht zuweisen" erzeugt.

3. **Lösung**:
- Das Problem kann gelöst werden, indem die Option `-f` mit `unshare` verwendet wird. Diese Option sorgt dafür, dass `unshare` einen neuen Prozess nach der Erstellung des neuen PID-Namespace forked.
- Das Ausführen von `%unshare -fp /bin/bash%` stellt sicher, dass der `unshare` Befehl selbst PID 1 im neuen Namespace wird. `/bin/bash` und seine Kindprozesse sind dann sicher in diesem neuen Namespace enthalten, wodurch der vorzeitige Austritt von PID 1 verhindert wird und eine normale PID-Zuweisung ermöglicht wird.

Durch die Sicherstellung, dass `unshare` mit dem `-f` Flag ausgeführt wird, wird der neue PID-Namespace korrekt aufrechterhalten, sodass `/bin/bash` und seine Unterprozesse ohne den Speicherzuweisungsfehler arbeiten können.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Überprüfen, in welchem Namespace sich Ihr Prozess befindet
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Finde alle Zeit-Namensräume
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Betritt einen Zeit-Namespace
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulating Time Offsets

Ab Linux 5.6 können zwei Uhren pro Zeit-Namespace virtualisiert werden:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Ihre per-Namespace-Deltas sind über die Datei `/proc/<PID>/timens_offsets` zugänglich (und können modifiziert werden):
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Die Datei enthält zwei Zeilen – eine pro Uhr – mit dem Offset in **Nanosekunden**. Prozesse, die **CAP_SYS_TIME** _im Zeit-Namespace_ besitzen, können den Wert ändern:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Wenn Sie möchten, dass die Wanduhr (`CLOCK_REALTIME`) sich ebenfalls ändert, müssen Sie weiterhin auf klassische Mechanismen (`date`, `hwclock`, `chronyd`, …) zurückgreifen; sie ist **nicht** namespaced.


### `unshare(1)` Hilfsflags (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
Die langen Optionen schreiben automatisch die gewählten Deltas in `timens_offsets`, direkt nachdem der Namespace erstellt wurde, wodurch ein manuelles `echo` entfällt.

---

## OCI & Runtime-Unterstützung

* Die **OCI Runtime Specification v1.1** (Nov 2023) fügte einen speziellen `time` Namespace-Typ und das Feld `linux.timeOffsets` hinzu, damit Container-Engines die Zeitvirtualisierung auf tragbare Weise anfordern können.
* **runc >= 1.2.0** implementiert diesen Teil der Spezifikation. Ein minimales Fragment von `config.json` sieht so aus:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Führen Sie dann den Container mit `runc run <id>` aus.

>  HINWEIS: runc **1.2.6** (Feb 2025) behob einen Fehler "exec in Container mit privatem timens", der zu einem Hängenbleiben und potenziellen DoS führen konnte. Stellen Sie sicher, dass Sie in der Produktion auf ≥ 1.2.6 sind.

---

## Sicherheitsüberlegungen

1. **Erforderliche Berechtigung** – Ein Prozess benötigt **CAP_SYS_TIME** innerhalb seines Benutzer-/Zeit-Namespace, um die Offsets zu ändern. Das Entfernen dieser Berechtigung im Container (Standard in Docker & Kubernetes) verhindert Manipulationen.
2. **Keine Änderungen der Echtzeituhr** – Da `CLOCK_REALTIME` mit dem Host geteilt wird, können Angreifer Zertifikatslaufzeiten, JWT-Ablauf usw. nicht nur über timens fälschen.
3. **Protokoll-/Erkennungsevasion** – Software, die auf `CLOCK_MONOTONIC` angewiesen ist (z. B. Ratenbegrenzer basierend auf Uptime), kann verwirrt werden, wenn der Namespace-Benutzer den Offset anpasst. Bevorzugen Sie `CLOCK_REALTIME` für sicherheitsrelevante Zeitstempel.
4. **Angriffsfläche des Kernels** – Selbst wenn `CAP_SYS_TIME` entfernt wird, bleibt der Kernel-Code zugänglich; halten Sie den Host gepatcht. Linux 5.6 → 5.12 erhielt mehrere Bugfixes für timens (NULL-deref, Vorzeichenprobleme).

### Härtungs-Checkliste

* Entfernen Sie `CAP_SYS_TIME` in Ihrem Standardprofil der Containerlaufzeit.
* Halten Sie die Laufzeiten aktuell (runc ≥ 1.2.6, crun ≥ 1.12).
* Fixieren Sie util-linux ≥ 2.38, wenn Sie auf die `--monotonic/--boottime`-Hilfsprogramme angewiesen sind.
* Überprüfen Sie die Software im Container, die **uptime** oder **CLOCK_MONOTONIC** für sicherheitskritische Logik liest.

## Referenzen

* man7.org – Handbuchseite für Zeitnamespaces: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI-Blog – "OCI v1.1: neue Zeit- und RDT-Namespace" (15. Nov 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}

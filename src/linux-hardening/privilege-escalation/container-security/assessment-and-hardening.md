# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

’n Goeie container-assessment moet twee parallelle vrae beantwoord. Eerstens, wat kan ’n aanvaller doen vanaf die huidige workload? Tweedens, watter operator-keuses het dit moontlik gemaak? Enumeration tools help met die eerste vraag, en hardening guidance help met die tweede. Om albei op een bladsy te hou maak die afdeling nuttiger as ’n veldverwysing eerder as net ’n katalogus van escape tricks.

Een praktiese opdatering vir moderne omgewings is dat baie ou container writeups stilweg ’n **rootful runtime**, **no user namespace isolation**, en dikwels **cgroup v1** veronderstel. Daardie aannames is nie meer veilig nie. Voordat jy tyd aan ou escape primitives bestee, bevestig eers of die workload rootless of userns-remapped is, of die host cgroup v2 gebruik, en of Kubernetes of die runtime nou verstek seccomp en AppArmor profiles toepas. Hierdie besonderhede bepaal dikwels of ’n beroemde breakout nog steeds van toepassing is.

## Enumeration Tools

’n Aantal tools bly nuttig om ’n container environment vinnig te karakteriseer:

- `linpeas` kan baie container indicators, gemounte sockets, capability sets, gevaarlike filesystems en breakout hints identifiseer.
- `CDK` fokus spesifiek op container environments en sluit enumeration plus sommige outomatiese escape checks in.
- `amicontained` is liggewig en nuttig om container restrictions, capabilities, namespace exposure en waarskynlike breakout classes te identifiseer.
- `deepce` is nog ’n container-gefokusde enumerator met breakout-gerigte checks.
- `grype` is nuttig wanneer die assessment image-package vulnerability review insluit in plaas van net runtime escape analysis.
- `Tracee` is nuttig wanneer jy **runtime evidence** nodig het eerder as slegs static posture, veral vir verdagte process execution, file access en container-aware event collection.
- `Inspektor Gadget` is nuttig in Kubernetes en Linux-host investigations wanneer jy eBPF-backed visibility nodig het wat teruggekoppel is aan pods, containers, namespaces en ander hoërvlak-konsepte.

Die waarde van hierdie tools is spoed en dekking, nie sekerheid nie. Hulle help om die ruwe posture vinnig bloot te lê, maar die interessante bevindings moet steeds handmatig geïnterpreteer word teen die werklike runtime, namespace, capability en mount model.

## Hardening Priorities

Die belangrikste hardening beginsels is konseptueel eenvoudig, al verskil die implementering per platform. Vermy privileged containers. Vermy gemounte runtime sockets. Moenie containers writable host paths gee nie, tensy daar ’n baie spesifieke rede is. Gebruik user namespaces of rootless execution waar moontlik. Drop alle capabilities en voeg net dié terug wat die workload werklik nodig het. Hou seccomp, AppArmor en SELinux geaktiveer eerder as om hulle te deaktiveer om application compatibility probleme reg te stel. Beperk resources sodat ’n gekompromitteerde container nie die host triviaal kan denial of service nie.

Image- en build hygiene is net so belangrik soos runtime posture. Gebruik minimale images, herbou gereeld, scan hulle, vereis provenance waar prakties, en hou secrets uit layers. ’n Container wat as non-root loop met ’n klein image en ’n nou syscall- en capability surface is baie makliker om te verdedig as ’n groot convenience image wat as host-equivalent root loop met debugging tools vooraf geïnstalleer.

Vir Kubernetes is huidige hardening baselines meer opinionated as wat baie operators nog aanvaar. Die ingeboude **Pod Security Standards** behandel `restricted` as die "current best practice" profile: `allowPrivilegeEscalation` moet `false` wees, workloads moet as non-root loop, seccomp moet eksplisiet gestel wees na `RuntimeDefault` of `Localhost`, en capability sets moet aggressief gedrop word. Tydens assessment maak dit saak omdat ’n cluster wat net `warn` of `audit` labels gebruik, op papier hardened kan lyk terwyl dit steeds riskante pods in die praktyk toelaat.

## Modern Triage Questions

Voordat jy na escape-spesifieke bladsye delf, beantwoord hierdie vinnige vrae:

1. Is die workload **rootful**, **rootless**, of **userns-remapped**?
2. Gebruik die node **cgroup v1** of **cgroup v2**?
3. Is **seccomp** en **AppArmor/SELinux** eksplisiet gekonfigureer, of net geërf wanneer beskikbaar?
4. In Kubernetes, enforce die namespace werklik **baseline** of **restricted**, of net warning/auditing?

Nuttige checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Wat hier interessant is:

- As `/proc/self/uid_map` wys dat container root na ’n **hoë host UID-reeks** gemap is, word baie ou host-root writeups minder relevant, omdat root in die container nie meer host-root-ekwivalent is nie.
- As `/sys/fs/cgroup` `cgroup2fs` is, behoort ou **cgroup v1**-spesifieke writeups soos `release_agent` abuse nie meer jou eerste raaiskoot te wees nie.
- As seccomp en AppArmor slegs implisiet geërf word, kan portability swakker wees as wat defenders verwag. In Kubernetes is om `RuntimeDefault` eksplisiet te stel dikwels sterker as om stilweg op node defaults te vertrou.
- As `supplementalGroupsPolicy` op `Strict` gestel is, behoort die pod te vermy om stilweg ekstra group memberships van `/etc/group` binne die image te erf, wat group-gebaseerde volume- en file access-gedrag meer voorspelbaar maak.
- Namespace labels soos `pod-security.kubernetes.io/enforce=restricted` is die moeite werd om direk na te gaan. `warn` en `audit` is nuttig, maar hulle stop nie ’n riskante pod om geskep te word nie.

## Resource-Exhaustion Examples

Resource controls is nie glansryk nie, maar hulle is deel van container security omdat hulle die blast radius van compromise beperk. Sonder memory-, CPU- of PID-limiete kan ’n eenvoudige shell genoeg wees om die host of buur-workloads te degradeer.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hierdie voorbeelde is nuttig omdat hulle wys dat nie elke gevaarlike container-uitkoms ’n skoon "escape" is nie. Swak cgroup-limiete kan steeds code execution in werklike operasionele impak omsit.

In Kubernetes-backed omgewings, kontroleer ook of resource controls enigsins bestaan voordat jy DoS as teoreties beskou:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Verhardingsnutsgoed

Vir Docker-gesentreerde omgewings bly `docker-bench-security` ’n nuttige gasheer-kant oudit-basislyn omdat dit algemene konfigurasieprobleme teen wyd erkende benchmark-riglyne nagaan:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Die tool is nie ’n plaasvervanger vir threat modeling nie, maar dit is steeds waardevol om sorgelose daemon-, mount-, network- en runtime-standaarde te vind wat oor tyd ophoop.

Vir Kubernetes en runtime-swaar omgewings, koppel statiese checks met runtime-sigbaarheid:

- `Tracee` is useful vir container-aware runtime detection en vinnige forensics wanneer jy moet bevestig wat ’n compromised workload eintlik geraak het.
- `Inspektor Gadget` is useful wanneer die assessment kernel-level telemetry nodig het wat terug na pods, containers, DNS-aktiwiteit, file execution, of network behavior gemap word.

## Checks

Gebruik hierdie as vinnige first-pass commands tydens assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Wat is interessant hier:

- ’n Root-proses met breë capabilities en `Seccomp: 0` verdien onmiddellike aandag.
- ’n Root-proses wat ook ’n **1:1 UID map** het, is baie interessanter as "root" binne ’n behoorlik geïsoleerde user namespace.
- `cgroup2fs` beteken gewoonlik dat baie ouer **cgroup v1** escape chains nie jou beste beginpunt is nie, terwyl ontbrekende `memory.max` of `pids.max` steeds op swak blast-radius controls dui.
- Verdagte mounts en runtime sockets bied dikwels ’n vinniger pad na impact as enige kernel exploit.
- Die kombinasie van swak runtime posture en swak resource limits dui gewoonlik op ’n oor die algemeen permissive container environment eerder as ’n enkele geïsoleerde fout.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}

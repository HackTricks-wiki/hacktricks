# Assessering En Verharding

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Goeie container-assessment behoort twee parallelle vrae te beantwoord. Eerstens, wat kan 'n aanvaller vanuit die huidige werklading doen? Tweedens, watter operateurkeuses het dit moontlik gemaak? Enumeration-tools help met die eerste vraag, en hardening guidance help met die tweede. Deur albei op een bladsy te hou, word die afdeling nuttiger as 'n veldverwysing eerder as net 'n katalogus van escape-truuks.

Een praktiese opdatering vir moderne omgewings is dat baie ouer container-writeups stilweg 'n **rootful runtime**, **geen user namespace-isolasie**, en dikwels **cgroup v1** aanvaar. Hierdie aannames is nie meer veilig nie. Voordat jy tyd aan ou escape-primitives bestee, bevestig eers of die werklading rootless of userns-remapped is, of die host cgroup v2 gebruik, en of Kubernetes of die runtime nou standaard seccomp- en AppArmor-profiele toepas. Hierdie besonderhede bepaal dikwels of 'n bekende breakout steeds van toepassing is.

## Enumeration Tools

'n Aantal tools bly nuttig om 'n container-omgewing vinnig te karakteriseer:

- `linpeas` kan baie container-indikators, gemounte sockets, capability-stelle, gevaarlike filesystems en breakout-hints identifiseer.
- `CDK` fokus spesifiek op container-omgewings en sluit enumeration plus sommige geoutomatiseerde escape-checks in.
- `amicontained` is liggewig en nuttig vir die identifisering van container-beperkings, capabilities, namespace-blootstelling en waarskynlike breakout-klasse.
- `deepce` is nog 'n container-gefokusde enumerator met breakout-georiënteerde checks.
- `grype` is nuttig wanneer die assessment image-package-vulnerability review insluit, eerder as slegs runtime escape analysis.
- `Tracee` is nuttig wanneer jy **runtime-bewyse** eerder as slegs statiese posture benodig, veral vir verdagte process execution, file access en container-bewuste event collection.
- `Inspektor Gadget` is nuttig in Kubernetes- en Linux-host-ondersoeke wanneer jy eBPF-gesteunde sigbaarheid benodig wat teruggekoppel is aan pods, containers, namespaces en ander hoërvlak-konsepte.

Die waarde van hierdie tools is spoed en dekking, nie sekerheid nie. Hulle help om die algemene posture vinnig bloot te lê, maar die interessante bevindings benodig steeds handmatige interpretasie teenoor die werklike runtime-, namespace-, capability- en mount-model.

## Hardening Priorities

Die belangrikste hardening-beginsels is konseptueel eenvoudig, al verskil die implementering per platform. Vermy privileged containers. Vermy gemounte runtime-sockets. Moenie containers writable host paths gee nie, tensy daar 'n baie spesifieke rede daarvoor is. Gebruik user namespaces of rootless execution waar dit haalbaar is. Drop alle capabilities en voeg slegs dié by wat die werklading werklik benodig. Hou seccomp, AppArmor en SELinux enabled eerder as om hulle te disable om application-compatibility-probleme op te los. Beperk resources sodat 'n gekompromitteerde container nie die host maklik van diens kan ontneem nie.

Image- en build-higiëne is net so belangrik soos runtime-posture. Gebruik minimale images, rebuild hulle gereeld, scan hulle, vereis provenance waar dit prakties is, en hou secrets uit layers. 'n Container wat as non-root loop, met 'n klein image en 'n beperkte syscall- en capability-surface, is baie makliker om te verdedig as 'n groot convenience-image wat as host-equivalent root loop met debugging-tools wat vooraf geïnstalleer is.

Vir Kubernetes is huidige hardening-baselines meer voorskriftelik as wat baie operateurs steeds aanvaar. Die ingeboude **Pod Security Standards** beskou `restricted` as die "current best practice"-profiel: `allowPrivilegeEscalation` behoort `false` te wees, workloads behoort as non-root te loop, seccomp behoort eksplisiet op `RuntimeDefault` of `Localhost` gestel te word, en capability-stelle behoort aggressief gedrop te word. Tydens assessment is dit belangrik omdat 'n cluster wat slegs `warn`- of `audit`-labels gebruik, op papier hardened kan lyk terwyl dit in die praktyk steeds riskante pods toelaat.<sup>[[1]](#references)</sup>

## Moderne Triage-vrae

Voordat jy escape-spesifieke bladsye ondersoek, beantwoord hierdie vinnige vrae:

1. Is die werklading **rootful**, **rootless** of **userns-remapped**?
2. Gebruik die node **cgroup v1** of **cgroup v2**?
3. Is **seccomp** en **AppArmor/SELinux** eksplisiet gekonfigureer, of word hulle bloot geërf wanneer dit beskikbaar is?
4. In Kubernetes, is die namespace werklik besig om `baseline` of `restricted` **af te dwing**, of waarsku/audit dit slegs?

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

- As `/proc/self/uid_map` wys dat container-root na ’n **hoë host-UID-reeks** gekarteer word, word baie ouer host-root writeups minder relevant, omdat root in die container nie meer gelykstaande aan host-root is nie.
- As `/sys/fs/cgroup` `cgroup2fs` is, behoort ou **cgroup v1**-spesifieke writeups, soos misbruik van `release_agent`, nie meer jou eerste raaiskoot te wees nie.
- As seccomp en AppArmor slegs implisiet geërf word, kan portability swakker wees as wat defenders verwag. In Kubernetes is dit dikwels sterker om `RuntimeDefault` eksplisiet te stel as om stilweg op node-defaults staat te maak.
- As `supplementalGroupsPolicy` op `Strict` gestel is, behoort die pod nie stilweg ekstra groep-lidmaatskappe vanaf `/etc/group` binne die image te erf nie, wat groepgebaseerde volume- en lêertoegangsgedrag meer voorspelbaar maak.
- Namespace-labels soos `pod-security.kubernetes.io/enforce=restricted` is die moeite werd om direk na te gaan. `warn` en `audit` is nuttig, maar hulle keer nie dat ’n riskante pod geskep word nie.

## Runtime-basislyntriage

’n Runtime-basislyn is die vinnige kontrole wat jou vertel of ’n container soos ’n gewone geïsoleerde workload lyk, of soos ’n foothold in ’n control plane wat die host kan beïnvloed. Dit behoort genoeg feite in te samel om te bepaal watter bladsy jy volgende moet lees: runtime-socket abuse, host mounts, namespaces, cgroups, capabilities, of image-secret review.

Nuttige kontroles vanuit ’n workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Interpretasie:

- Ontbrekende of onbeperkte `memory.max` / `pids.max` dui op swak beheer oor die blast radius, selfs sonder ’n skoon escape.
- ’n root shell met `NoNewPrivs: 0`, breë capabilities en permissiewe seccomp is baie interessanter as ’n beperkte non-root workload.
- Runtime sockets en skryfbare host mounts weeg gewoonlik swaarder as kernel exploits, omdat hulle reeds ’n beheerpad na die bestuur of lêerstelsel blootlê.
- Gedeelde PID-, network-, IPC- of cgroup namespaces is nie altyd op sigself volledige escapes nie, maar dit maak dit makliker om die volgende stap te vind.

## Voorbeelde van Resource-Exhaustion

Resource controls is nie glansryk nie, maar hulle is deel van container security omdat hulle die blast radius van ’n compromise beperk. Sonder memory-, CPU- of PID-limits kan ’n eenvoudige shell genoeg wees om die host of naburige workloads te degradeer.

Voorbeeldtoetse wat die host beïnvloed:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hierdie voorbeelde is nuttig omdat hulle wys dat nie elke gevaarlike container-uitkoms ’n netjiese "escape" is nie. Swak cgroup-limiete kan steeds code execution in werklike operasionele impak omskep.

In Kubernetes-gesteunde omgewings, kontroleer ook of resource controls enigsins bestaan voordat jy DoS as teoreties beskou:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening-gereedskap

Vir Docker-gesentreerde omgewings bly `docker-bench-security` ’n nuttige oudit-basislyn aan die host-kant, omdat dit algemene konfigurasieprobleme nagaan aan die hand van wyd erkende benchmark-riglyne:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Die tool is nie ’n plaasvervanger vir threat modeling nie, maar dit is steeds waardevol om onversigtige daemon-, mount-, network- en runtime-verstekwaardes te vind wat mettertyd ophoop.

Vir Kubernetes- en runtime-swaar omgewings, kombineer statiese checks met runtime-sigbaarheid:

- `Tracee` is nuttig vir container-bewuste runtime-detection en vinnige forensics wanneer jy moet bevestig waaraan ’n gekompromitteerde workload werklik geraak het.
- `Inspektor Gadget` is nuttig wanneer die assessment kernel-vlak-telemetrie benodig wat teruggekoppel is aan pods, containers, DNS-aktiwiteit, file execution of network-gedrag.

## Checks

Gebruik hierdie as vinnige eerste-pass-opdragte tydens assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Wat is hier interessant:

- 'n root-proses met breë vermoëns en `Seccomp: 0` verdien onmiddellike aandag.
- 'n root-proses wat ook 'n **1:1 UID map** het, is baie interessanter as "root" binne 'n behoorlik geïsoleerde user namespace.
- `cgroup2fs` beteken gewoonlik dat baie ouer **cgroup v1** escape-kettings nie jou beste beginpunt is nie, terwyl 'n ontbrekende `memory.max` of `pids.max` steeds op swak beheermaatreëls vir die impakradius dui.
- Verdagte mounts en runtime-sockets bied dikwels 'n vinniger pad na impak as enige kernel exploit.
- Die kombinasie van 'n swak runtime-postuur en swak resource limits dui gewoonlik op 'n algemeen permissiewe container-omgewing eerder as een enkele geïsoleerde fout.

## Verwysings

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}

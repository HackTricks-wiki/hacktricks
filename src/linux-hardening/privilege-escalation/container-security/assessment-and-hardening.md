# Procena i Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena containera treba da odgovori na dva paralelna pitanja. Prvo, šta napadač može da uradi iz trenutnog workload-a? Drugo, koji su operator izbori to omogućili? Enumeration alati pomažu sa prvim pitanjem, a hardening smernice pomažu sa drugim. Držanje oba na istoj stranici čini ovaj deo korisnijim kao terenski reference, a ne samo kao katalog escape trikova.

Jedno praktično ažuriranje za moderna okruženja je da mnogi stariji container writeup-ovi tiho pretpostavljaju **rootful runtime**, **bez user namespace izolacije**, i često **cgroup v1**. Te pretpostavke više nisu bezbedne. Pre nego što potrošiš vreme na stare escape primitive, prvo potvrdi da li je workload rootless ili userns-remapped, da li host koristi cgroup v2, i da li Kubernetes ili runtime sada primenjuju podrazumevane seccomp i AppArmor profile. Ovi detalji često odlučuju da li čuveni breakout i dalje važi.

## Enumeration Tools

Brojni alati ostaju korisni za brzo karakterisanje container okruženja:

- `linpeas` može da identifikuje mnoge container indikatore, mountovane sokete, capability skupove, opasne filesystems, i breakout tragove.
- `CDK` je fokusiran posebno na container okruženja i uključuje enumeration plus neke automatizovane escape provere.
- `amicontained` je lagan i koristan za identifikaciju container restrikcija, capabilities, namespace izloženosti, i verovatnih breakout klasa.
- `deepce` je još jedan enumerator fokusiran na containere sa breakout-orijentisanim proverama.
- `grype` je koristan kada procena uključuje pregled ranjivosti image-paketa umesto samo runtime escape analize.
- `Tracee` je koristan kada ti trebaju **runtime dokazi** umesto samo statičkog stanja, posebno za sumnjivo izvršavanje procesa, pristup fajlovima, i container-aware prikupljanje događaja.
- `Inspektor Gadget` je koristan u Kubernetes i Linux-host istragama kada ti treba eBPF-backed vidljivost poveziva nazad na pods, containere, namespace-ove, i druge viši nivo koncepte.

Vrednost ovih alata je brzina i pokrivenost, ne sigurnost. Oni pomažu da se brzo otkrije gruba pozicija, ali zanimljivi nalazi i dalje zahtevaju ručnu interpretaciju u odnosu na stvarni runtime, namespace, capability, i mount model.

## Hardening Priorities

Najvažniji hardening principi su konceptualno jednostavni iako se njihova implementacija razlikuje po platformi. Izbegavaj privileged containere. Izbegavaj mountovane runtime sokete. Ne daj containerima writable host putanje osim ako za to ne postoji veoma specifičan razlog. Koristi user namespaces ili rootless izvršavanje gde je moguće. Ukloni sve capabilities i dodaj nazad samo one koje workload zaista treba. Drži seccomp, AppArmor, i SELinux uključene umesto da ih isključuješ radi rešavanja problema kompatibilnosti aplikacija. Ograniči resurse tako da kompromitovani container ne može trivijalno da uskrati servis hostu.

Image i build higijena su jednako važni kao i runtime stanje. Koristi minimalne image-ove, često ih rebuild-uj, skeniraj ih, zahtevaj provenance gde je praktično, i drži secret-e van layer-ova. Container koji radi kao non-root sa malim image-om i uskom syscall i capability površinom mnogo je lakši za odbranu nego veliki convenience image koji radi kao host-ekvivalent root sa unapred instaliranim debugging alatima.

Za Kubernetes, trenutne hardening osnove su više opinionated nego što mnogi operatori i dalje pretpostavljaju. Ugrađeni **Pod Security Standards** tretiraju `restricted` kao profil "trenutne najbolje prakse": `allowPrivilegeEscalation` treba da bude `false`, workload-ovi treba da rade kao non-root, seccomp treba eksplicitno postaviti na `RuntimeDefault` ili `Localhost`, a capability skupove treba agresivno ukloniti. Tokom procene, ovo je važno jer cluster koji koristi samo `warn` ili `audit` labele može izgledati hardenovano na papiru dok i dalje u praksi prihvata rizične podove.

## Modern Triage Questions

Pre nego što pređeš na stranice specifične za escape, odgovori na ova kratka pitanja:

1. Da li je workload **rootful**, **rootless**, ili **userns-remapped**?
2. Da li node koristi **cgroup v1** ili **cgroup v2**?
3. Da li su **seccomp** i **AppArmor/SELinux** eksplicitno konfigurisani, ili su samo nasleđeni kada su dostupni?
4. U Kubernetes, da li namespace zaista **enforcing** `baseline` ili `restricted`, ili samo upozorava/revizira?

Korisne provere:
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
Šta je zanimljivo ovde:

- Ako `/proc/self/uid_map` pokazuje da je container root mapiran na **visok host UID opseg**, mnogi stariji host-root writeups postaju manje relevantni zato što root u containeru više nije ekvivalentan host-root.
- Ako je `/sys/fs/cgroup` `cgroup2fs`, stari **cgroup v1**-specifični writeups kao što je zloupotreba `release_agent` više ne bi trebalo da budu prvi izbor.
- Ako su seccomp i AppArmor samo implicitno nasleđeni, prenosivost može biti slabija nego što defanzivci očekuju. U Kubernetes, eksplicitno postavljanje `RuntimeDefault` je često jače nego tiho oslanjanje na podrazumevana podešavanja noda.
- Ako je `supplementalGroupsPolicy` postavljen na `Strict`, pod bi trebalo da izbegne tiho nasleđivanje dodatnih grupnih članstava iz `/etc/group` unutar image-a, što ponašanje pristupa fajlovima i volume-ima zasnovano na grupama čini predvidljivijim.
- Namespace oznake kao što je `pod-security.kubernetes.io/enforce=restricted` vredi proveriti direktno. `warn` i `audit` su korisni, ali ne sprečavaju kreiranje rizičnog poda.

## Resource-Exhaustion Examples

Kontrole resursa nisu glamurozne, ali su deo container security jer ograničavaju blast radius kompromitacije. Bez limita za memoriju, CPU ili PID, običan shell može biti dovoljan da degradira host ili susedne workloads.

Primeri testova koji utiču na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ovi primeri su korisni zato što pokazuju da nije svaki opasan ishod kontejnera čist "escape". Slabe cgroup granice i dalje mogu pretvoriti izvršavanje koda u stvarni operativni uticaj.

U okruženjima zasnovanim na Kubernetes-u, takođe proveri da li kontrole resursa uopšte postoje pre nego što tretiraš DoS kao teorijski:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Za Docker-centric okruženja, `docker-bench-security` ostaje koristan host-side audit baseline zato što proverava uobičajene probleme sa konfiguracijom prema široko priznatim benchmark smernicama:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Alat nije zamena za threat modeling, ali je i dalje koristan za pronalaženje nepažljivih daemon, mount, network i runtime podrazumevanih podešavanja koja se vremenom nagomilavaju.

Za Kubernetes i okruženja sa velikim oslanjanjem na runtime, upari statičke provere sa runtime vidljivošću:

- `Tracee` je koristan za container-aware runtime detection i brzu forenziku kada treba da potvrdiš čega je kompromitovani workload zapravo dotakao.
- `Inspektor Gadget` je koristan kada procena treba kernel-level telemetry mapiran nazad na pods, containers, DNS activity, file execution ili network ponašanje.

## Checks

Koristi ovo kao brze komande za prvi prolaz tokom procene:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Šta je zanimljivo ovde:

- Root proces sa širokim capabilities i `Seccomp: 0` zaslužuje trenutnu pažnju.
- Root proces koji takođe ima **1:1 UID map** je daleko zanimljiviji od "root" unutar pravilno izolovanog user namespace-a.
- `cgroup2fs` obično znači da mnogi stariji **cgroup v1** escape lanci nisu najbolja početna tačka, dok odsustvo `memory.max` ili `pids.max` i dalje ukazuje na slabe kontrole blast radius-a.
- Sumnjivi mounts i runtime sockets često pružaju brži put do impact-a nego bilo koji kernel exploit.
- Kombinacija slabe runtime posture i slabih resource limits obično ukazuje na generalno permissive container environment, a ne na jednu izolovanu grešku.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}

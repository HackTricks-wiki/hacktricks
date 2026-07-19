# Procena i ojačavanje

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena containera treba da odgovori na dva paralelna pitanja. Prvo, šta napadač može da uradi iz trenutnog workload-a? Drugo, koje odluke operatora su to omogućile? Alati za enumeraciju pomažu kod prvog pitanja, a smernice za ojačavanje kod drugog. Držanje oba aspekta na jednoj stranici čini ovaj odeljak korisnijim kao terensku referencu, a ne samo kao katalog escape trikova.

Jedna praktična dopuna za moderna okruženja jeste da mnogi stariji container tekstovi prećutno pretpostavljaju **rootful runtime**, **bez izolacije user namespace-a** i često **cgroup v1**. Te pretpostavke više nisu bezbedne. Pre nego što utrošite vreme na stare escape primitive, prvo proverite da li je workload rootless ili userns-remapped, da li host koristi cgroup v2 i da li Kubernetes ili runtime sada primenjuju podrazumevane seccomp i AppArmor profile. Ovi detalji često odlučuju da li je poznati breakout i dalje primenljiv.

## Alati za enumeraciju

Brojni alati su i dalje korisni za brzo karakterisanje container okruženja:

- `linpeas` može da otkrije mnoge indikatore containera, montirane sockete, skupove capability-ja, opasne filesystem-e i naznake breakout-a.
- `CDK` je posebno usmeren na container okruženja i obuhvata enumeraciju, kao i neke automatizovane provere escape-a.
- `amicontained` je lagan i koristan za identifikovanje ograničenja containera, capability-ja, izloženosti namespace-a i verovatnih klasa breakout-a.
- `deepce` je još jedan enumerator usmeren na containere, sa proverama usmerenim na breakout.
- `grype` je koristan kada procena obuhvata pregled ranjivosti paketa u image-ima, a ne samo analizu runtime escape-a.
- `Tracee` je koristan kada su vam potrebni **runtime dokazi**, a ne samo statička procena stanja, naročito za sumnjivo pokretanje procesa, pristup fajlovima i prikupljanje događaja svesno containera.
- `Inspektor Gadget` je koristan u Kubernetes i Linux-host istragama kada vam je potrebna eBPF vidljivost povezana sa podovima, containerima, namespace-ima i drugim konceptima višeg nivoa.

Vrednost ovih alata leži u brzini i obuhvatu, a ne u izvesnosti. Oni pomažu da se brzo otkrije približno stanje, ali zanimljivi nalazi i dalje zahtevaju ručno tumačenje u odnosu na stvarni runtime, namespace, capability i mount model.

## Prioriteti ojačavanja

Najvažniji principi ojačavanja su konceptualno jednostavni, iako se njihova implementacija razlikuje u zavisnosti od platforme. Izbegavajte privileged containere. Izbegavajte montirane runtime sockete. Nemojte containerima davati writable host putanje osim ako za to ne postoji veoma konkretan razlog. Koristite user namespace-e ili rootless izvršavanje gde je izvodljivo. Uklonite sve capability-je i vratite samo one koje su workload-u zaista potrebne. Ostavite seccomp, AppArmor i SELinux uključene umesto da ih isključujete radi rešavanja problema kompatibilnosti aplikacije. Ograničite resurse kako kompromitovani container ne bi mogao trivijalno da uskrati uslugu hostu.

Higijena image-a i build procesa jednako je važna kao i runtime stanje. Koristite minimalne image-e, često ih ponovo build-ujte, skenirajte ih, zahtevajte provenance gde je to praktično i držite secrets van layer-a. Container koji radi kao non-root, koristi mali image i ima ograničenu syscall i capability površinu mnogo je lakše braniti nego veliki convenience image koji radi kao root ekvivalentan hostu i unapred sadrži debugging alate.

Za Kubernetes su aktuelne osnove ojačavanja preciznije nego što mnogi operatori i dalje pretpostavljaju. Ugrađeni **Pod Security Standards** tretiraju `restricted` kao profil "trenutne najbolje prakse": `allowPrivilegeEscalation` treba da bude `false`, workload-i treba da rade kao non-root, seccomp treba eksplicitno postaviti na `RuntimeDefault` ili `Localhost`, a skupove capability-ja treba agresivno ukloniti. Tokom procene ovo je važno zato što cluster koji koristi samo `warn` ili `audit` labele može na papiru izgledati ojačano, dok u praksi i dalje prihvata rizične podove.

## Pitanja za moderni triage

Pre nego što pređete na stranice posvećene escape-u, odgovorite na sledeća kratka pitanja:

1. Da li je workload **rootful**, **rootless** ili **userns-remapped**?
2. Da li node koristi **cgroup v1** ili **cgroup v2**?
3. Da li su **seccomp** i **AppArmor/SELinux** eksplicitno konfigurisani ili se samo nasleđuju kada su dostupni?
4. U Kubernetes-u, da li namespace zaista **enforcing** primenjuje `baseline` ili `restricted`, ili samo izdaje upozorenja/vrši audit?

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
Šta je ovde zanimljivo:

- Ako `/proc/self/uid_map` prikazuje da je container root mapiran na **visok opseg UID-ova na hostu**, mnogi stariji writeup-i o upisivanju sa host-root privilegijama postaju manje relevantni, jer root u container-u više nije ekvivalentan host-root-u.
- Ako je `/sys/fs/cgroup` `cgroup2fs`, stari writeup-i specifični za **cgroup v1**, kao što je zloupotreba `release_agent` mehanizma, više ne bi trebalo da budu vaša prva pretpostavka.
- Ako se seccomp i AppArmor samo implicitno nasleđuju, portability može biti slabiji nego što defenders očekuju. U Kubernetes-u je eksplicitno podešavanje `RuntimeDefault` često bezbednije od neprimetnog oslanjanja na podrazumevana podešavanja node-a.
- Ako je `supplementalGroupsPolicy` podešen na `Strict`, pod bi trebalo da izbegne neprimetno nasleđivanje dodatnih članstava u grupama iz `/etc/group` unutar image-a, čime ponašanje pristupa volume-ima i fajlovima zasnovano na grupama postaje predvidljivije.
- Vredi direktno proveriti namespace labels kao što je `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` su korisni, ali ne sprečavaju kreiranje rizičnog pod-a.

## Trijaža osnovnog stanja runtime-a

Osnovno stanje runtime-a predstavlja brzu proveru koja pokazuje da li container izgleda kao uobičajen izolovani workload ili kao foothold u control plane-u koji može da utiče na host. Trebalo bi prikupiti dovoljno činjenica da bi se odredilo šta sledeće treba pročitati: zloupotreba runtime socket-a, host mounts, namespace-ovi, cgroups, capabilities ili provera image secrets-a.

Korisne provere iz workload-a:
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
Tumačenje:

- Nedostajući ili neograničeni `memory.max` / `pids.max` ukazuju na slabe kontrole blast radius-a čak i bez potpunog escape-a.
- root shell sa `NoNewPrivs: 0`, širokim capabilities i permissive seccomp-om mnogo je zanimljiviji od uskog non-root workload-a.
- Runtime socket-i i writable host mount-ovi obično imaju veći prioritet od kernel exploit-a, jer već izlažu management ili filesystem control path.
- Deljeni PID, network, IPC ili cgroup namespace-i nisu uvek potpuni escape sami po sebi, ali olakšavaju pronalaženje sledećeg koraka.

## Primeri iscrpljivanja resursa

Resource controls nisu glamurozni, ali su deo container security-ja jer ograničavaju blast radius kompromitacije. Bez memory, CPU ili PID limit-a, jednostavan shell može biti dovoljan za degradaciju host-a ili susednih workload-a.

Primeri testova koji utiču na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ovi primeri su korisni jer pokazuju da se svaki opasan ishod u containeru ne završava čistim „escape“-om. Slaba cgroup ograničenja i dalje mogu pretvoriti code execution u stvarni operativni uticaj.

U okruženjima zasnovanim na Kubernetes-u, takođe proverite da li kontrole resursa uopšte postoje pre nego što DoS smatrate samo teorijskim:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Alati za hardening

Za okruženja usmerena na Docker, `docker-bench-security` i dalje predstavlja korisnu osnovu za audit na strani hosta, jer proverava uobičajene probleme sa konfiguracijom u odnosu na široko priznate smernice benchmarka:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Alat nije zamena za threat modeling, ali je i dalje koristan za pronalaženje nemarno podešenih podrazumevanih vrednosti za daemon, mount, mrežu i runtime, koje se vremenom nagomilavaju.

Za Kubernetes i okruženja sa intenzivnim korišćenjem runtime-a, uparite statičke provere sa runtime vidljivošću:

- `Tracee` je koristan za runtime detekciju prilagođenu kontejnerima i brzu forenziku kada treba da potvrdite čemu je kompromitovani workload zaista pristupio.
- `Inspektor Gadget` je koristan kada assessment zahteva telemetry na nivou kernela, mapiranu nazad na podove, kontejnere, DNS activity, izvršavanje fajlova ili mrežno ponašanje.

## Provere

Koristite ih kao brze komande za početnu proveru tokom assessment-a:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Šta je ovde zanimljivo:

- root proces sa širokim capabilities i `Seccomp: 0` zahteva hitnu pažnju.
- root proces koji takođe ima **1:1 UID map** mnogo je zanimljiviji od "root" procesa unutar pravilno izolovanog user namespace-a.
- `cgroup2fs` obično znači da mnogi stariji lanci za escape iz **cgroup v1** nisu najbolja početna tačka, dok odsustvo `memory.max` ili `pids.max` i dalje ukazuje na slabe kontrole blast radius-a.
- Sumnjivi mount-ovi i runtime socket-i često omogućavaju brži put do uticaja nego bilo koji kernel exploit.
- Kombinacija slabe runtime konfiguracije i slabih ograničenja resursa obično ukazuje na generalno permisivno container okruženje, a ne na jednu izolovanu grešku.

## Reference

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}

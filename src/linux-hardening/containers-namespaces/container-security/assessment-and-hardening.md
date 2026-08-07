# Procena i hardening

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena kontejnera treba da pruži odgovor na dva paralelna pitanja. Prvo, šta attacker može da uradi iz trenutno pokrenutog workload-a? Drugo, koje odluke operatora su to omogućile? Enumeration alati pomažu pri odgovoru na prvo pitanje, a smernice za hardening pri odgovoru na drugo. Držanje oba aspekta na jednoj stranici čini ovu sekciju korisnijom kao terensku referencu, a ne samo kao katalog escape trikova.

Jedno praktično ažuriranje za moderna okruženja jeste to što mnogi stariji tekstovi o kontejnerima podrazumevaju **rootful runtime**, **bez izolacije user namespace-a**, a često i **cgroup v1**. Te pretpostavke više nisu bezbedne. Pre nego što utrošite vreme na stare escape primitive, prvo proverite da li je workload rootless ili userns-remapped, da li host koristi cgroup v2 i da li Kubernetes ili runtime sada primenjuje podrazumevane seccomp i AppArmor profile. Ovi detalji često određuju da li je poznati breakout i dalje moguć.

## Enumeration alati

Brojni alati su i dalje korisni za brzo određivanje karakteristika container okruženja:

- `linpeas` može da identifikuje mnoge indikatore kontejnera, montirane socket-e, skupove capabilities, opasne filesystem-e i nagoveštaje breakout-a.
- `CDK` je posebno fokusiran na container okruženja i uključuje enumeration, kao i neke automatizovane escape provere.
- `amicontained` je lagan i koristan za identifikovanje ograničenja kontejnera, capabilities, izloženosti namespace-a i verovatnih klasa breakout-a.
- `deepce` je još jedan enumerator fokusiran na kontejnere, sa proverama usmerenim na breakout.
- `grype` je koristan kada procena uključuje pregled ranjivosti paketa u image-u, a ne samo analizu runtime escape-a.
- `Tracee` je koristan kada su vam potrebni **runtime dokazi**, a ne samo statički prikaz posture-a, posebno za sumnjivo izvršavanje procesa, pristup fajlovima i prikupljanje događaja uz razumevanje kontejnera.
- `Inspektor Gadget` je koristan u Kubernetes i Linux-host istragama kada vam je potrebna vidljivost zasnovana na eBPF-u, povezana sa podovima, kontejnerima, namespace-ovima i drugim konceptima višeg nivoa.

Vrednost ovih alata ogleda se u brzini i obuhvatu, a ne u izvesnosti. Oni pomažu da se brzo otkrije približna postura, ali zanimljivi nalazi i dalje zahtevaju ručno tumačenje u odnosu na stvarni runtime, namespace, capabilities i model mount-ova.

## Prioriteti hardening-a

Najvažniji principi hardening-a su konceptualno jednostavni, iako se njihova implementacija razlikuje u zavisnosti od platforme. Izbegavajte privileged kontejnere. Izbegavajte montirane runtime socket-e. Nemojte kontejnerima davati writable host putanje osim ako za to postoji veoma konkretan razlog. Koristite user namespace-ove ili rootless izvršavanje gde je to izvodljivo. Uklonite sve capabilities i vratite samo one koje su workload-u zaista potrebne. Ostavite seccomp, AppArmor i SELinux omogućene umesto da ih isključujete radi rešavanja problema kompatibilnosti aplikacije. Ograničite resurse kako kompromitovani kontejner ne bi mogao trivijalno da izazove uskraćivanje usluge hostu.

Higijena image-a i build procesa podjednako je važna kao i runtime postura. Koristite minimalne image-e, često ih ponovo build-ujte, skenirajte ih, zahtevajte provenance gde je to praktično i držite secrets van layer-a. Kontejner koji radi kao non-root, sa malim image-om i uskom syscall i capability površinom, mnogo je lakše braniti nego veliki convenience image koji radi kao root ekvivalentan hostu i unapred ima instalirane debugging alate.

Za Kubernetes, savremene hardening baseline smernice su preciznije nego što mnogi operatori i dalje pretpostavljaju. Ugrađeni **Pod Security Standards** tretiraju `restricted` kao profil koji predstavlja „trenutnu najbolju praksu“: `allowPrivilegeEscalation` treba da bude `false`, workload-i treba da rade kao non-root, seccomp treba eksplicitno podesiti na `RuntimeDefault` ili `Localhost`, a skupove capabilities treba agresivno ukloniti. Tokom procene ovo je važno zato što klaster koji koristi samo `warn` ili `audit` label-e može na papiru izgledati hardenizovano, dok u praksi i dalje prihvata rizične podove.<sup>[[1]](#references)</sup>

## Moderna triage pitanja

Pre nego što pređete na stranice posvećene escape-u, odgovorite na sledeća kratka pitanja:

1. Da li je workload **rootful**, **rootless** ili **userns-remapped**?
2. Da li node koristi **cgroup v1** ili **cgroup v2**?
3. Da li su **seccomp** i **AppArmor/SELinux** eksplicitno konfigurisani ili se samo nasleđuju kada su dostupni?
4. U Kubernetes-u, da li namespace zaista **enforcing** `baseline` ili `restricted`, ili samo izdaje upozorenja/vrši auditing?

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

- Ako `/proc/self/uid_map` prikazuje da je root u containeru mapiran na **visoki opseg UID-ova na hostu**, mnogi stariji writeup-ovi o host-root pristupu postaju manje relevantni jer root u containeru više nije ekvivalentan root-u na hostu.
- Ako je `/sys/fs/cgroup` `cgroup2fs`, stari writeup-ovi specifični za **cgroup v1**, kao što je zloupotreba `release_agent` mehanizma, više ne bi trebalo da budu vaša prva pretpostavka.
- Ako se seccomp i AppArmor nasleđuju samo implicitno, portability može biti slabiji nego što defenderi očekuju. U Kubernetes-u je eksplicitno podešavanje `RuntimeDefault` često jače od tihog oslanjanja na podrazumevana podešavanja node-a.
- Ako je `supplementalGroupsPolicy` postavljen na `Strict`, pod bi trebalo da izbegne tiho nasleđivanje dodatnih članstava u grupama iz `/etc/group` unutar image-a, što ponašanje pristupa volume-ima i fajlovima zasnovano na grupama čini predvidljivijim.
- Vredi direktno proveriti namespace labele kao što je `pod-security.kubernetes.io/enforce=restricted`. `warn` i `audit` su korisni, ali ne sprečavaju kreiranje rizičnog poda.

## Početna procena runtime okruženja

Početna procena runtime okruženja je brza provera koja pokazuje da li container izgleda kao uobičajen izolovan workload ili kao foothold kontrolne ravni sa uticajem na host. Trebalo bi prikupiti dovoljno činjenica da bi se odredilo šta sledeće treba pročitati: zloupotreba runtime socket-a, mount-ovi hosta, namespace-ovi, cgroup-ovi, capabilities ili provera image secret-a.

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

- Nedostatak ili neograničeni `memory.max` / `pids.max` ukazuje na slabe kontrole blast radius-a čak i bez potpunog escape-a.
- Root shell sa `NoNewPrivs: 0`, širokim capabilities i permissive seccomp-om mnogo je zanimljiviji od uskog non-root workload-a.
- Runtime sockets i writable host mounts obično imaju prednost nad kernel exploit-ima jer već otkrivaju management ili filesystem control path.
- Shared PID, network, IPC ili cgroup namespaces nisu uvek potpuni escape sami po sebi, ali olakšavaju pronalaženje sledećeg koraka.

## Primeri iscrpljivanja resursa

Kontrole resursa nisu glamurozne, ali su deo container security-a jer ograničavaju blast radius kompromitovanja. Bez ograničenja za memory, CPU ili PID, jednostavan shell može biti dovoljan za degradaciju host-a ili susednih workload-a.

Primeri testova koji utiču na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ovi primeri su korisni jer pokazuju da svaki opasan ishod kontejnera nije čisto „escape“. Slaba cgroup ograničenja i dalje mogu pretvoriti izvršavanje koda u stvarni operativni uticaj.

U okruženjima zasnovanim na Kubernetes-u, takođe proverite da li kontrole resursa uopšte postoje pre nego što DoS smatrate teorijskim slučajem:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening alati

Za okruženja usmerena na Docker, `docker-bench-security` i dalje predstavlja korisnu osnovu za audit na hostu, jer proverava uobičajene probleme u konfiguraciji u odnosu na široko prihvaćene smernice benchmarka:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Alat nije zamena za threat modeling, ali je i dalje koristan za pronalaženje nemarnih podrazumevanih podešavanja za daemon, mount, mrežu i runtime koja se vremenom nagomilavaju.

Za Kubernetes i okruženja koja se intenzivno oslanjaju na runtime, uparite statičke provere sa runtime vidljivošću:

- `Tracee` je koristan za runtime detekciju prilagođenu kontejnerima i brzu forenziku kada treba da potvrdite čemu je kompromitovani workload zapravo pristupao.
- `Inspektor Gadget` je koristan kada procena zahteva telemetriju na nivou kernela mapiranu nazad na podove, kontejnere, DNS aktivnost, izvršavanje fajlova ili ponašanje mreže.

## Provere

Koristite ih kao komande za prvu proveru tokom procene:
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

- root proces sa širokim capabilities i `Seccomp: 0` zaslužuje hitnu pažnju.
- root proces koji takođe ima **1:1 UID map** mnogo je zanimljiviji od "root" procesa unutar pravilno izolovanog user namespace-a.
- `cgroup2fs` obično znači da mnogi stariji **cgroup v1** escape lanci nisu najbolja početna tačka, dok odsustvo `memory.max` ili `pids.max` i dalje ukazuje na slabe kontrole blast radius-a.
- Sumnjivi mount-ovi i runtime socket-i često pružaju brži put do uticaja nego bilo koji kernel exploit.
- Kombinacija slabe runtime posture i slabih ograničenja resursa obično ukazuje na generalno permisivno container okruženje, a ne na jednu izolovanu grešku.

## Reference

- [1] [Kubernetes standardi bezbednosti podova](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker bezbednosno upozorenje: Višestruke ranjivosti u runc, BuildKit i Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}

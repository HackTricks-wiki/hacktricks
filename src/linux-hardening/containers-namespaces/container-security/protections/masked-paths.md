# Njia Zilizofichwa

{{#include ../../../../banners/hacktricks-training.md}}

Njia zilizofichwa ni ulinzi wa wakati wa utekelezaji unaoficha maeneo nyeti hasa ya mfumo wa faili yanayohusiana na kernel kutoka kwa container kwa kuyawekea bind-mount au kuyafanya yasifikike kwa njia nyingine. Ufafanuzi wa OCI wa runtime unaweka `maskedPaths` kuwa njia kamili ambazo hazipaswi kusomeka ndani ya container. <sup>[[1]](#references)</sup>

Hili ni muhimu kwa sababu njia nyingi za kutoroka kutoka kwa container na hila zinazoathiri host huanza kwa kusoma au kuandika faili maalum chini ya `/proc` au `/sys`. Ikiwa maeneo hayo yamefichwa, mshambulizi hupoteza ufikiaji wa moja kwa moja wa sehemu muhimu ya kiolesura cha udhibiti wa kernel, hata baada ya kupata uwezo wa kutekeleza msimbo ndani ya container.

## Uendeshaji

Runtime kwa kawaida huficha njia zilizochaguliwa kama vile:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Orodha kamili hutegemea runtime na usanidi wa host. Jambo muhimu ni kwamba njia hiyo haiwezi kufikiwa au hubadilishwa kwa mtazamo wa container, ingawa bado ipo kwenye host.

## Maabara

Kagua usanidi wa njia zilizofichwa unaoonyeshwa na Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Chunguza tabia halisi ya mount ndani ya workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Njia iliyoorodheshwa si lazima iweze kusomeka: runc inaweza kuficha faili kwa bind mount ya `/dev/null` na saraka kwa tmpfs tupu ya kusomeka tu. Kagua mountpoint halisi, si kuangalia tu kama `ls` inafanya kazi. <sup>[[4]](#references)</sup>

## Security Impact

Kuficha hakutengenezi mpaka mkuu wa isolation, lakini huondoa malengo kadhaa yenye thamani kubwa baada ya unyonyaji. Bila kuficha, container iliyoathiriwa inaweza kuweza kukagua hali ya kernel, kusoma taarifa nyeti za michakato au za keying, au kuingiliana na vitu vya procfs/sysfs ambavyo havikupaswa kamwe kuonekana na programu.

## Misconfigurations

Kosa kuu ni kufichua tena makundi mapana ya njia kwa urahisi au utatuzi wa hitilafu. Katika Podman, hili linaweza kuonekana kama `--security-opt unmask=ALL` au kufichua tena njia mahususi. <sup>[[2]](#references)</sup> Katika Kubernetes, kufichua proc kwa upana kupita kiasi kunaweza kuonekana kupitia `procMount: Unmasked`; Kubernetes ya sasa inahitaji `spec.hostUsers: false` (user namespace) kwa mpangilio huu, ilhali matoleo ya 1.12–1.29 hayakutekeleza sharti hilo. <sup>[[3]](#references)</sup> Tatizo jingine kubwa ni kufichua host `/proc` au `/sys` kupitia bind mount, jambo linalopuuza kabisa dhana ya mwonekano uliopunguzwa wa container.

## Abuse

Ikiwa kuficha ni dhaifu au hakupo, anza kwa kutambua ni njia zipi nyeti za procfs/sysfs zinazofikika moja kwa moja:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Ikiwa njia inayodhaniwa kuwa imefichwa inaweza kufikiwa, ichunguze kwa makini:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Mambo ambayo amri hizi zinaweza kufichua:

- `/proc/timer_list` inaweza kufichua data ya timer na scheduler ya host. Hii hutumika zaidi kwa reconnaissance, lakini inathibitisha kuwa container inaweza kusoma taarifa zinazohusu kernel ambazo kwa kawaida hufichwa.
- `/proc/keys` huorodhesha metadata ya keys tu ambazo msomaji ana ruhusa ya **view**, kulingana na ukaguzi wa LSM. Inaweza kufichua aina na maelezo ya keys, lakini haitoi payload za keys. <sup>[[6]](#references)</sup>
- `/sys/firmware` husaidia kutambua hali ya boot, interfaces za firmware, na maelezo ya platform ambayo yanafaa kwa fingerprinting ya host na kuelewa kama workload inaona hali ya kiwango cha host.
- `/proc/config.gz` inaweza kufichua usanidi wa kernel inayoendeshwa, ambao ni muhimu kwa kulinganisha masharti ya exploit za kernel za umma au kuelewa kwa nini kipengele fulani kinaweza kufikiwa.
- `/proc/sched_debug` hufichua hali ya scheduler na mara nyingi hupita matarajio ya kawaida kwamba PID namespace inapaswa kuficha kabisa taarifa za process zisizohusiana.

Matokeo ya kuvutia ni pamoja na kusoma faili hizo moja kwa moja, ushahidi kwamba data hiyo ni ya host badala ya mwonekano wenye vizuizi wa container, au ufikiaji wa maeneo mengine ya procfs/sysfs ambayo kwa kawaida hufichwa kwa chaguo-msingi.

### Race ya chanzo cha mask wakati wa kuwasha container

Katika matoleo hatarishi ya runc, file masks hutegemea inode ya `/dev/null` ya container. Mshambulizi anayeweza kupanga containers zinazoendeshwa kwa wakati mmoja zenye mounts zinazoshirikiwa, ikiwemo hatua sambamba za BuildKit, anaweza kushindana wakati wa startup na kuondoa `/dev/null` kabla runc haijaibind juu ya faili za procfs zilizofichwa. Kisha runtime huchukulia chanzo **source** kilichokosekana kana kwamba destination ya mask haipo na huruka file masks hizo kimyakimya. Tatizo hili hutegemea race wakati wa usanidi wa runtime; kuondoa `/dev/null` baada ya startup hakubatilishi mask ambayo tayari imewekwa. <sup>[[4]](#references)</sup>

Baada ya jaribio linalodhibitiwa, linganisha orodha ya masks zilizoombwa na mountpoints halisi ndani ya container mpya. <sup>[[4]](#references)</sup> `findmnt -M` hukagua mountpoint iliyotajwa badala ya kutumia mount ya mzazi; ikiwa `findmnt` haipo, kagua `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> Kufanikiwa kwa `ls` au matokeo matupu ya `cat` hayawezi kuthibitisha kuwa mask haipo. <sup>[[4]](#references)</sup>

Tumia [ukaguzi ulio hapa chini](#checks) kulinganisha masks zilizoombwa na mounts halisi katika container mpya.

File mask iliyorukwa inaweza kufichua data ya procfs ikiwa ruhusa za kawaida na sera ya LSM zinaruhusu. Hii **haifanyi** `/proc/sys` iweze kuandikwa yenyewe: huo ni udhibiti tofauti wa [read-only-path](read-only-paths.md). Ubadilishaji tofauti wa symlink ya `/dev/null` unaoweza kuelekeza bind mount kwenye lengo la procfs linaloweza kuandikwa umeelezwa chini ya [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

Lengo la ukaguzi huu ni kubaini ni paths zipi runtime ilizificha kimakusudi na kama workload ya sasa bado inaona mfumo wa faili unaohusu kernel uliopunguzwa.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Tumia ukaguzi wa mount halisi, kwa sababu faili iliyofichwa bado inaweza kuwepo na usomaji unaweza kurudisha matokeo tupu kutoka `/dev/null`. Kukosekana kwa mountpoint ni finding inayopaswa kuchunguzwa, si uthibitisho wa kuwa data ya host inaweza kusomeka. <sup>[[4]](#references)[[5]](#references)</sup>

Mambo ya kuzingatia hapa:

- Orodha ndefu ya paths zilizofichwa ni ya kawaida katika runtimes zilizoimarishwa kiusalama.
- Kukosekana kwa ufichaji kwenye maingizo nyeti ya procfs kunahitaji uchunguzi wa karibu zaidi.
- Ikiwa path nyeti inafikika na container pia ina capabilities imara au mounts pana, ufichuzi huo una umuhimu zaidi.

## Chaguomsingi za Runtime

| Runtime / platform | Hali chaguomsingi | Tabia chaguomsingi | Njia za kawaida za kudhoofisha kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Imewashwa kwa chaguomsingi | Docker hufafanua orodha chaguomsingi ya paths zilizofichwa | kuweka wazi mounts za host proc/sys, `--privileged` |
| Podman | Imewashwa kwa chaguomsingi | Podman hutumia paths chaguomsingi zilizofichwa isipokuwa ziondolewe kwenye ufichaji kwa mikono | `--security-opt unmask=ALL`, kuondoa ufichaji kwa paths maalum, `--privileged` |
| Kubernetes | Hurithi chaguomsingi za runtime | Hutumia tabia ya ufichaji ya runtime ya msingi isipokuwa mipangilio ya Pod idhoofishe ufichuzi wa proc | `procMount: Unmasked` (inahitaji `hostUsers: false` katika matoleo ya sasa), mifumo ya workloads zenye ruhusa za juu, mounts pana za host |
| containerd / CRI-O chini ya Kubernetes | Chaguomsingi za runtime | Kwa kawaida hutumia paths zilizofichwa za OCI/runtime isipokuwa zibatilishwe | mabadiliko ya moja kwa moja ya usanidi wa runtime, njia zilezile za kudhoofisha za Kubernetes |

Kwa kawaida, paths zilizofichwa huwa zimewekwa kwa chaguomsingi. Tatizo kuu la kiutendaji si kutokuwepo kwake kwenye runtime, bali ni kuziondoa kwenye ufichaji kimakusudi au kutumia host bind mounts zinazobatilisha ulinzi huo.

## References

- [1] [Open Container Initiative - Usanidi wa Linux container: Paths Zilizofichwa](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Nyaraka za Podman - options za usalama za `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Nyaraka za Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Ushauri wa runc: race ya chanzo cha mount ya path iliyofichwa](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Mwongozo wa findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Mwongozo wa keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}

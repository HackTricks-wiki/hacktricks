# Njia Zilizofichwa

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths ni protections za wakati wa runtime zinazoficha maeneo nyeti ya filesystem yanayohusiana na kernel kutoka kwenye container kwa kuyawekea bind-mount au kuyafanya yasifikike kwa njia nyingine. Lengo ni kuzuia workload kuingiliana moja kwa moja na interfaces ambazo applications za kawaida hazihitaji, hasa ndani ya procfs.

Hili ni muhimu kwa sababu container escapes nyingi na tricks zinazoathiri host huanza kwa kusoma au kuandika files maalum chini ya `/proc` au `/sys`. Ikiwa maeneo hayo yamefichwa, attacker hupoteza access ya moja kwa moja kwenye sehemu muhimu ya kernel control surface hata baada ya kupata code execution ndani ya container.

## Uendeshaji

Runtimes kwa kawaida huficha paths zilizochaguliwa kama:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Orodha kamili hutegemea runtime na host configuration. Sifa muhimu ni kwamba path huwa haipatikani au hubadilishwa kwa mtazamo wa container, ingawa bado ipo kwenye host.

## Maabara

Kagua masked-path configuration inayofichuliwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Chunguza tabia halisi ya mount ndani ya workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Athari za Usalama

Masking haiundi boundary kuu ya isolation, lakini huondoa targets kadhaa zenye thamani kubwa za post-exploitation. Bila masking, container iliyoathiriwa inaweza kuweza kukagua hali ya kernel, kusoma taarifa nyeti za process au keys, au kuingiliana na objects za procfs/sysfs ambazo hazikupaswa kamwe kuonekana kwa application.

## Mipangilio Isiyo Sahihi

Kosa kuu ni ku-unmask makundi mapana ya paths kwa ajili ya urahisi au debugging. Katika Podman, hii inaweza kuonekana kama `--security-opt unmask=ALL` au unmasking maalum. Katika Kubernetes, proc exposure iliyo pana kupita kiasi inaweza kuonekana kupitia `procMount: Unmasked`. Tatizo jingine kubwa ni ku-expose host `/proc` au `/sys` kupitia bind mount, jambo linalopita kabisa wazo la reduced container view.

## Matumizi Mabaya

Ikiwa masking ni dhaifu au haipo, anza kwa kutambua ni paths zipi nyeti za procfs/sysfs zinazoweza kufikiwa moja kwa moja:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Ikiwa njia inayodaiwa kuwa imefichwa inaweza kufikiwa, ichunguze kwa makini:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Wanachoweza kufichua commands hizi:

- `/proc/timer_list` inaweza kufichua data ya host kuhusu timers na scheduler. Hii kwa kiasi kikubwa ni reconnaissance primitive, lakini inathibitisha kwamba container inaweza kusoma taarifa zinazoelekea kwenye kernel ambazo kwa kawaida hufichwa.
- `/proc/keys` ni nyeti zaidi. Kulingana na configuration ya host, inaweza kufichua entries za keyring, maelezo ya keys, na uhusiano kati ya services za host zinazotumia kernel keyring subsystem.
- `/sys/firmware` husaidia kutambua boot mode, firmware interfaces, na maelezo ya platform yanayofaa kwa host fingerprinting na kuelewa ikiwa workload inaona state ya kiwango cha host.
- `/proc/config.gz` inaweza kufichua configuration ya kernel inayoendesha, jambo lenye thamani kwa kulinganisha prerequisites za public kernel exploit au kuelewa kwa nini feature fulani inaweza kufikiwa.
- `/proc/sched_debug` hufichua state ya scheduler na mara nyingi hupita matarajio ya kawaida kwamba PID namespace inapaswa kuficha kabisa taarifa za processes zisizohusiana.

Matokeo ya kuvutia yanajumuisha usomaji wa moja kwa moja kutoka kwenye files hizo, ushahidi kwamba data ni ya host badala ya kuwa ya view iliyozuiwa ya container, au access ya maeneo mengine ya procfs/sysfs ambayo kwa kawaida hufichwa kwa default.

## Checks

Lengo la checks hizi ni kubaini ni paths zipi runtime ilificha kimakusudi na ikiwa workload ya sasa bado inaona filesystem iliyopunguzwa inayohusiana na kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Kinachovutia hapa:

- Orodha ndefu ya masked paths ni ya kawaida katika runtimes zilizoimarishwa.
- Kukosekana kwa masking kwenye entries nyeti za procfs kunastahili kuchunguzwa kwa karibu zaidi.
- Ikiwa path nyeti inaweza kufikiwa na container pia ina capabilities zenye nguvu au mounts pana, exposure hiyo huwa muhimu zaidi.

## Runtime Defaults

| Runtime / platform | Hali ya msingi | Tabia ya msingi | Udhaifu wa kawaida unaofanywa manually |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa msingi | Docker hufafanua orodha ya msingi ya masked paths | kufichua host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa msingi | Podman hutumia masked paths za msingi isipokuwa ziondolewe masking manually | `--security-opt unmask=ALL`, kuondoa masking kwa targets maalum, `--privileged` |
| Kubernetes | Hurithi defaults za runtime | Hutumia tabia ya masking ya runtime ya msingi isipokuwa Pod settings zipunguze ulinzi wa proc | `procMount: Unmasked`, mifumo ya privileged workload, host mounts pana |
| containerd / CRI-O under Kubernetes | Default ya runtime | Kwa kawaida hutumia masked paths za OCI/runtime isipokuwa zibadilishwe | mabadiliko ya moja kwa moja kwenye runtime config, njia zilezile za kudhoofisha Kubernetes |

Masked paths kwa kawaida huwa zipo kwa msingi. Tatizo kuu la kiutendaji si kutokuwepo kwake kwenye runtime, bali ni kuondolewa masking kwa makusudi au host bind mounts zinazobatilisha ulinzi huo.
{{#include ../../../../banners/hacktricks-training.md}}

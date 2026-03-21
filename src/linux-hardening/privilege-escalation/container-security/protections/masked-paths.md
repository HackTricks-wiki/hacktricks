# Njia Zilizo Fichwa

{{#include ../../../../banners/hacktricks-training.md}}

Njia zilizofichwa (masked paths) ni ulinzi wakati wa runtime unaoficha maeneo ya mfumo wa faili yanayomkabili kernel na yenye uzito mkubwa kutoka kwa container kwa ku-bind-mount juu yao au kwa kuyafanya yasipatikane kwa njia nyingine. Lengo ni kuzuia workload kuingiliana moja kwa moja na interfaces ambazo applications za kawaida hazihitaji, hasa ndani ya procfs.

Hii ni muhimu kwa sababu container escapes nyingi na mbinu zinazoweza kuathiri host huanza kwa kusoma au kuandika faili maalum chini ya `/proc` au `/sys`. Ikiwa maeneo hayo yamefichwa, mshambuliaji atapoteza ufikiaji wa moja kwa moja wa sehemu yenye manufaa ya kernel control surface hata baada ya kupata code execution ndani ya container.

## Uendeshaji

Runtimes kwa kawaida huficha njia zilizochaguliwa kama:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Orodha kamili inategemea runtime na usanidi wa host. Sifa muhimu ni kwamba njia hiyo inakuwa haipatikani au imebadilishwa kutoka kwa mtazamo wa container ingawa bado ipo kwenye host.

## Maabara

Chunguza usanidi wa masked-path unaoonyeshwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Chunguza tabia halisi ya mount ndani ya workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Kuficha hakutengenezi mpaka kuu wa utenganisho, lakini huondoa malengo kadhaa ya thamani kubwa ya post-exploitation. Bila kuficha, container iliyovamiwa inaweza kuweza kuchunguza hali ya kernel, kusoma taarifa nyeti kuhusu mchakato au funguo, au kuingiliana na vitu vya procfs/sysfs ambavyo hakukupaswa kuonekana kwa programu.

## Misconfigurations

Hitilafu kuu ni kuondoa kuficha kwa makundi mapana ya paths kwa urahisi au kwa kusaka/d-debugging. Katika Podman hili linaweza kuonekana kama `--security-opt unmask=ALL` au kuondoa kuficha kwa lengo maalum. Katika Kubernetes, kufichuliwa kupita kiasi kwa proc kunaweza kuonekana kupitia `procMount: Unmasked`. Tatizo jingine kubwa ni kufichua host `/proc` au `/sys` kupitia bind mount, ambalo linavuka kabisa dhana ya mtazamo mdogo wa container.

## Abuse

Ikiwa masking ni dhaifu au haipo, anza kwa kubainisha ni njia gani za procfs/sysfs nyeti zinazofikiwa moja kwa moja:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Kama njia inayodhaniwa kuwa imefichwa inapatikana, ichunguze kwa makini:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` inaweza kufichua data za timer na scheduler za host. Hii kwa kawaida ni reconnaissance primitive, lakini inathibitisha kwamba container inaweza kusoma kernel-facing information ambayo kwa kawaida imefichwa.
- `/proc/keys` ni nyeti zaidi. Kulingana na host configuration, inaweza kufichua keyring entries, key descriptions, na uhusiano kati ya host services zinazotumia kernel keyring subsystem.
- `/sys/firmware` husaidia kubaini boot mode, firmware interfaces, na maelezo ya platform ambayo ni muhimu kwa host fingerprinting na kuelewa kama workload inaona host-level state.
- `/proc/config.gz` inaweza kufichua running kernel configuration, ambayo ni muhimu kwa kulinganisha prerequisites za public kernel exploits au kuelewa kwa nini feature fulani inafikika.
- `/proc/sched_debug` inaonyesha scheduler state na mara nyingi inapita matarajio ya kiakili kwamba PID namespace inapaswa kuficha kabisa taarifa za michakato isiyohusiana.

Matokeo ya kuvutia ni pamoja na kusoma moja kwa moja kutoka kwa faili hizo, ushahidi kwamba data inamilikiwa na host badala ya mtazamo uliokandamizwa wa container, au ufikivu kwa maeneo mengine ya procfs/sysfs ambayo kwa kawaida yamefichwa kwa default.

## Checks

Lengo la checks hizi ni kubaini ni paths gani runtime ilizificha kwa makusudi na kama current workload bado inaona filesystem iliyopunguzwa inayomuelekea kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Kinachovutia hapa:

- Orodha ndefu ya masked-path ni ya kawaida katika runtimes zilizohifadhiwa kwa usalama.
- Kutokuwepo kwa masking kwenye procfs entries nyeti kunastahili uchunguzi wa karibu.
- Ikiwa sensitive path inapatikana na container pia ina capabilities kali au host mounts pana, mfichiko huo una umuhimu zaidi.

## Runtime Defaults

| Runtime / jukwaa | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhaifu wa kawaida unaofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Docker inafafanua orodha ya masked path kwa chaguo-msingi | kuonyesha host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | Podman inaweka masked paths za chaguo-msingi isipokuwa zifunguliwe kwa mkono | `--security-opt unmask=ALL`, unmasking lengwa, `--privileged` |
| Kubernetes | Inarithi chaguo-msingi za runtime | Inatumia tabia za masking za runtime inayotumika chini isipokuwa mipangilio ya Pod idhoofishe ufunikaji wa proc | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Chaguo-msingi cha runtime | Kawaida inatumia masked paths za OCI/runtime isipokuwa zikibadilishwa | mabadiliko ya moja kwa moja ya config ya runtime, njia zile zile za kudhoofisha za Kubernetes |

Masked paths kwa kawaida hupatikana kwa chaguo-msingi. Tatizo kuu la uendeshaji si kutokuwepo ndani ya runtime, bali kuondolewa kwa masking kwa makusudi au host bind mounts ambazo zinabatilisha ulinzi.

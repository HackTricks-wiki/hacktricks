# Njia Zilizofichwa

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths ni ulinzi wa runtime unaoficha maeneo nyeti hasa ya filesystem yanayohusiana na kernel kutoka kwa container kwa kuyawekea bind-mount au kuyafanya yasifikike kwa njia nyingine. Lengo ni kuzuia workload kuingiliana moja kwa moja na interfaces ambazo applications za kawaida hazihitaji, hasa ndani ya procfs.

Hili ni muhimu kwa sababu container escapes nyingi na mbinu zinazoathiri host huanza kwa kusoma au kuandika faili maalum zilizo chini ya `/proc` au `/sys`. Ikiwa maeneo hayo yamefichwa, attacker hupoteza ufikiaji wa moja kwa moja wa sehemu muhimu ya kernel control surface hata baada ya kupata code execution ndani ya container.

## Uendeshaji

Runtimes kwa kawaida huficha paths zilizochaguliwa kama vile:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Orodha kamili hutegemea runtime na configuration ya host. Sifa muhimu ni kwamba path huwa haifikiki au hubadilishwa kwa mtazamo wa container, ingawa bado ipo kwenye host.

## Maabara

Kagua masked-path configuration inayoonyeshwa na Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Kagua tabia halisi ya mount ndani ya workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Athari za Usalama

Masking haiundi mpaka mkuu wa isolation, lakini huondoa malengo kadhaa yenye thamani kubwa baada ya kupata ufikiaji wa mfumo. Bila masking, container iliyoathiriwa inaweza kukagua hali ya kernel, kusoma taarifa nyeti za process au keying, au kuingiliana na vitu vya procfs/sysfs ambavyo havikupaswa kamwe kuonekana kwa application.

## Misconfigurations

Kosa kuu ni kuondoa masking kwa makundi mapana ya paths kwa ajili ya urahisi au debugging. Katika Podman, hii inaweza kuonekana kama `--security-opt unmask=ALL` au unmasking inayolenga paths maalum. Katika Kubernetes, proc exposure iliyo pana kupita kiasi inaweza kuonekana kupitia `procMount: Unmasked`. Tatizo jingine kubwa ni kuweka host `/proc` au `/sys` wazi kupitia bind mount, jambo linalokiuka kabisa dhana ya reduced container view.

## Abuse

Ikiwa masking ni dhaifu au haipo, anza kwa kubaini ni paths zipi nyeti za procfs/sysfs zinafikiwa moja kwa moja:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Ikiwa path inayodhaniwa kuwa imefichwa inaweza kufikiwa, ichunguze kwa makini:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Mambo ambayo commands hizi zinaweza kufichua:

- `/proc/timer_list` inaweza kufichua data ya timer na scheduler ya host. Hii hasa ni primitive ya reconnaissance, lakini inathibitisha kuwa container inaweza kusoma taarifa zinazoelekea kwenye kernel ambazo kwa kawaida hufichwa.
- `/proc/keys` ni nyeti zaidi. Kulingana na configuration ya host, inaweza kufichua entries za keyring, maelezo ya keys, na mahusiano kati ya services za host zinazotumia kernel keyring subsystem.
- `/sys/firmware` husaidia kutambua boot mode, interfaces za firmware, na maelezo ya platform ambayo ni muhimu kwa host fingerprinting na kuelewa kama workload inaona hali ya kiwango cha host.
- `/proc/config.gz` inaweza kufichua configuration ya kernel inayotumika, jambo lenye thamani kwa kulinganisha prerequisites za public kernel exploits au kuelewa kwa nini feature fulani inaweza kufikiwa.
- `/proc/sched_debug` hufichua hali ya scheduler na mara nyingi hupita matarajio ya kawaida kwamba PID namespace inapaswa kuficha kabisa taarifa za processes zisizohusiana.

Matokeo ya kuvutia yanajumuisha kusoma moja kwa moja files hizo, ushahidi kwamba data hiyo ni ya host badala ya kuwa ya view iliyowekewa mipaka ya container, au kufikia locations nyingine za procfs/sysfs ambazo kwa kawaida hufichwa kwa default.

## Checks

Lengo la checks hizi ni kubaini ni paths zipi runtime ilificha kwa makusudi na kama workload ya sasa bado inaona filesystem iliyopunguzwa inayohusiana na kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Kinachovutia hapa:

- Orodha ndefu ya `masked-path` ni jambo la kawaida katika hardened runtimes.
- Kukosekana kwa masking kwenye entries nyeti za procfs kunastahili uchunguzi wa karibu zaidi.
- Ikiwa path nyeti inaweza kufikiwa na container pia ina capabilities zenye nguvu au mounts pana, kufichuliwa huko kuna umuhimu zaidi.

## Runtime Defaults

| Runtime / platform | Hali ya kawaida | Tabia ya kawaida | Udhaifu wa kawaida unaofanywa kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa default | Docker hufafanua orodha ya default ya masked paths | kufichua host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa default | Podman hutumia masked paths za default isipokuwa ziondolewe masking kwa mikono | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Hurithi default za runtime | Hutumia tabia ya masking ya runtime ya msingi isipokuwa Pod settings zidhoofishe proc exposure | `procMount: Unmasked`, mifumo ya privileged workload, host mounts pana |
| containerd / CRI-O under Kubernetes | Default ya runtime | Kwa kawaida hutumia masked paths za OCI/runtime isipokuwa zibadilishwe | mabadiliko ya moja kwa moja kwenye runtime config, njia zilezile za kudhoofisha Kubernetes |

Masked paths kwa kawaida huwa zipo kwa default. Tatizo kuu la kiutendaji si kutokuwepo kwake kwenye runtime, bali unmasking ya makusudi au host bind mounts zinazobatilisha ulinzi huo.

{{#include ../../../../banners/hacktricks-training.md}}

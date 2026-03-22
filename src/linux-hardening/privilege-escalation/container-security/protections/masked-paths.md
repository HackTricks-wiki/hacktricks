# Njia Zilizofichwa

{{#include ../../../../banners/hacktricks-training.md}}

Njia zilizofichwa ni ulinzi unaotekelezwa wakati wa runtime unaoficha maeneo ya mfumo wa faili yanayomkabili kernel yenye nyeti zaidi kutoka kwa container kwa kuziweka kama bind-mount juu yao au kwa kuyafanya yasiyofikika kwa njia nyingine. Kusudi ni kuzuia workload kuingiliana moja kwa moja na interfaces ambazo applications za kawaida hazihitaji, hasa ndani ya procfs.

Hili ni muhimu kwa sababu mengi container escapes na host-impacting tricks huanza kwa kusoma au kuandika faili maalum chini ya `/proc` au `/sys`. Ikiwa maeneo hayo yamefichwa, mshambuliaji hupoteza ufikiaji wa moja kwa moja kwa sehemu muhimu ya uso wa udhibiti wa kernel hata baada ya kupata utekelezaji wa msimbo ndani ya container.

## Operesheni

Runtimes kawaida huweka mask kwenye path zilizo chaguliwa kama:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

Orodha halisi inategemea runtime na host configuration. Sifa muhimu ni kwamba path inakuwa haifikiki au imebadilishwa kwa mtazamo wa container ingawa bado ipo kwenye host.

## Maabara

Inspect the masked-path configuration exposed by Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Chunguza tabia halisi ya mount ndani ya workload:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Madhara ya Usalama

Masking haitengenezi mipaka kuu ya kutenganisha, lakini huondoa malengo kadhaa ya thamani kubwa ya post-exploitation. Bila masking, container iliyovamiwa inaweza kuchunguza hali ya kernel, kusoma taarifa nyeti za mchakato au taarifa za ufunguo, au kuingiliana na vitu vya procfs/sysfs ambavyo havipaswi kuonekana kwa programu.

## Makosa ya Mipangilio

Kosa kuu ni kuondoa masking kwa makundi mapana ya paths kwa urahisi au kwa ajili ya utatuzi wa matatizo. Katika Podman hili linaweza kuonekana kama `--security-opt unmask=ALL` au kuondoa masking kwa lengo maalum. Katika Kubernetes, kufichuliwa kupita kiasi kwa proc kunaweza kuonekana kupitia `procMount: Unmasked`. Tatizo jingine kubwa ni kufichua host `/proc` au `/sys` kupitia bind mount, ambayo huvuruga kabisa wazo la mtazamo mdogo wa container.

## Matumizi Mabaya

Ikiwa masking ni dhaifu au haipo, anza kwa kubaini ni paths zipi nyeti za procfs/sysfs zinaweza kufikiwa moja kwa moja:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Ikiwa njia inayosemekana kuwa imefichwa inapatikana, iangalie kwa makini:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Kile ambacho amri hizi zinaweza kufichua:

- `/proc/timer_list` inaweza kufichua data za timer na scheduler za mwenyeji. Hii kwa kawaida ni mbinu ya msingi ya uchunguzi, lakini inathibitisha kwamba container inaweza kusoma taarifa zinazokutana na kernel ambazo kwa kawaida zimetenguliwa.
- `/proc/keys` ni nyeti zaidi. Kulingana na usanidi wa mwenyeji, inaweza kufichua vipengee vya keyring, maelezo ya key, na uhusiano kati ya huduma za mwenyeji zinazotumia kernel keyring subsystem.
- `/sys/firmware` husaidia kubaini boot mode, interfaces za firmware, na maelezo ya platform ambayo ni muhimu kwa host fingerprinting na kuelewa ikiwa workload inaona state ya kiwango cha host.
- `/proc/config.gz` inaweza kufichua usanidi wa kernel unaoendesha, jambo la thamani kwa kulinganisha prerequisites za public kernel exploit au kuelewa kwa nini kipengele fulani kinapatikana.
- `/proc/sched_debug` inafichua state ya scheduler na mara nyingi hupita matarajio ya kimantiki kwamba PID namespace inapaswa kuficha taarifa za mchakato zisizo husiana kabisa.

Matokeo yanayovutia ni pamoja na kusoma moja kwa moja kutoka kwa faili hizo, ushahidi kwamba data inamhusu mwenyeji badala ya mtazamo uliowekwa kikomo wa container, au ufikiaji wa maeneo mengine ya procfs/sysfs ambayo kwa kawaida yamefichwa kwa default.

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ni njia gani runtime ilizificha kwa makusudi na kama workload ya sasa bado inaona filesystem iliyopunguzwa inayokutana na kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Kinachovutia hapa:

- Orodha ndefu ya masked-path ni ya kawaida katika runtimes zilizoimarishwa.
- Kukosekana kwa kufichwa kwenye ingizo nyeti za procfs kunastahili uchunguzi wa karibu.
- Ikiwa njia nyeti inapatikana na container pia ina capabilities kali au broad mounts, mfichuko unakuwa muhimu zaidi.

## Chaguo-msingi za Runtime

| Runtime / jukwaa | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida unaofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Imewezeshwa kwa chaguo-msingi | Docker hufafanua orodha ya masked path kwa chaguo-msingi | kuweka wazi host proc/sys mounts, `--privileged` |
| Podman | Imewezeshwa kwa chaguo-msingi | Podman inaweka masked paths za chaguo-msingi isipokuwa zikifunguliwa kwa mkono | `--security-opt unmask=ALL`, kuondoa kufichwa kwa njia lengwa, `--privileged` |
| Kubernetes | Inarithi chaguo-msingi za runtime | Inatumia tabia ya masking ya runtime inayosimama chini yake isipokuwa mipangilio ya Pod yanaporudisha ufichaji wa proc | `procMount: Unmasked`, mifumo ya workloads za privileged, host mounts pana |
| containerd / CRI-O under Kubernetes | Chaguo-msingi za runtime | Kwa kawaida inatumia OCI/runtime masked paths isipokuwa zikibadilishwa | mabadiliko ya moja kwa moja ya config ya runtime, njia zile zile za kuudhoofisha za Kubernetes |

Masked paths kawaida huwa zipo kama chaguo-msingi. Tatizo kuu la operative si kutoonekana kwake kwenye runtime, bali ni kuondolewa kwa makusudi kwa kufichwa (unmasking) au host bind mounts ambazo zinafuta ulinzi.
{{#include ../../../../banners/hacktricks-training.md}}

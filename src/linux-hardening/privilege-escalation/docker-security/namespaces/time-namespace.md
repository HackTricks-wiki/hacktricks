# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Namespace ya muda katika Linux inaruhusu offsets za kila namespace kwa saa za mfumo zisizobadilika na saa za kuanzisha. Inatumika sana katika kontena za Linux kubadilisha tarehe/saa ndani ya kontena na kurekebisha saa baada ya kurejesha kutoka kwa alama ya ukaguzi au picha.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba namespace mpya ya kuunganisha ina **mtazamo sahihi na wa kutengwa wa taarifa za mchakato maalum kwa namespace hiyo**.

<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanajumuishwa.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanajumuishwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa kawaida wa PID.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, namespace mpya ya PID inatunzwa kwa usahihi, ikiruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na hitilafu ya ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni namespace ipi mchakato wako uko ndani
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Pata majina yote ya Time namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya muda namespace
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}

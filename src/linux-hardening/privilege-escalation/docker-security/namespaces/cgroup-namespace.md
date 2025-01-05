# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Cgroup namespace ni kipengele cha kernel ya Linux ambacho kinatoa **kujitengea kwa hierarchies za cgroup kwa michakato inayofanya kazi ndani ya namespace**. Cgroups, kifupi kwa **control groups**, ni kipengele cha kernel kinachoruhusu kupanga michakato katika vikundi vya kihierarchi ili kudhibiti na kutekeleza **mipaka kwenye rasilimali za mfumo** kama CPU, kumbukumbu, na I/O.

Ingawa cgroup namespaces si aina tofauti ya namespace kama zile tulizo jadili awali (PID, mount, network, nk), zinahusiana na dhana ya kujitengea kwa namespace. **Cgroup namespaces zinafanya virtualize mtazamo wa hierarchi ya cgroup**, hivyo michakato inayofanya kazi ndani ya cgroup namespace ina mtazamo tofauti wa hierarchi ikilinganishwa na michakato inayofanya kazi kwenye mwenyeji au namespaces nyingine.

### How it works:

1. Wakati cgroup namespace mpya inaundwa, **inaanza na mtazamo wa hierarchi ya cgroup kulingana na cgroup ya mchakato unaounda**. Hii inamaanisha kwamba michakato inayofanya kazi katika cgroup namespace mpya itaona tu sehemu ya hierarchi nzima ya cgroup, iliyopunguzia kwenye cgroup subtree iliyoanzishwa kwenye cgroup ya mchakato unaounda.
2. Michakato ndani ya cgroup namespace itakuwa **inaona cgroup yao wenyewe kama mzizi wa hierarchi**. Hii inamaanisha kwamba, kutoka mtazamo wa michakato ndani ya namespace, cgroup yao wenyewe inaonekana kama mzizi, na hawawezi kuona au kufikia cgroups nje ya subtree yao wenyewe.
3. Cgroup namespaces hazitoi moja kwa moja kujitengea kwa rasilimali; **zinatoa tu kujitengea kwa mtazamo wa hierarchi ya cgroup**. **Udhibiti wa rasilimali na kujitengea bado unatekelezwa na cgroup** subsystems (mfano, cpu, memory, nk) wenyewe.

Kwa maelezo zaidi kuhusu CGroups angalia:

{{#ref}}
../cgroups.md
{{#endref}}

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba nafasi mpya ya kuunganisha ina **mtazamo sahihi na uliojitegemea wa taarifa za mchakato zinazohusiana na nafasi hiyo**.

<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia nafasi mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda nafasi mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa nafasi mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii katika nafasi mpya; ni watoto wake tu wanaingia.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika nafasi ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika nafasi mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa nafasi hiyo ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato yatima. Kernel ya Linux itazima kuteua PID katika nafasi hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika nafasi mpya kunasababisha kusafishwa kwa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda nafasi mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika nafasi mpya. `/bin/bash` na watoto wake wanakuwa salama ndani ya nafasi hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu kuteua PID kwa kawaida.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, nafasi mpya ya PID inashikiliwa kwa usahihi, ikiruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na hitilafu ya kugawa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni namespace ipi mchakato wako uko ndani yake
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Pata majina yote ya CGroup namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya cgroup namespace
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** katika namespace nyingine **bila deskteta** inayorejelea hiyo (kama `/proc/self/ns/cgroup`).

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}

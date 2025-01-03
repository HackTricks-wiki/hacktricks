# Network Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Namespace ya mtandao ni kipengele cha kernel ya Linux kinachotoa kutengwa kwa stack ya mtandao, ikiruhusu **kila namespace ya mtandao kuwa na usanidi wake wa mtandao huru**, interfaces, anwani za IP, meza za routing, na sheria za firewall. Kutengwa hiki ni muhimu katika hali mbalimbali, kama vile uundaji wa kontena, ambapo kila kontena linapaswa kuwa na usanidi wake wa mtandao, huru kutoka kwa kontena nyingine na mfumo wa mwenyeji.

### How it works:

1. Wakati namespace mpya ya mtandao inaundwa, inaanza na **stack ya mtandao iliyotengwa kabisa**, ikiwa na **interfaces za mtandao** isipokuwa kwa interface ya loopback (lo). Hii inamaanisha kwamba michakato inayofanyika katika namespace mpya ya mtandao haiwezi kuwasiliana na michakato katika namespaces nyingine au mfumo wa mwenyeji kwa default.
2. **Interfaces za mtandao za virtual**, kama vile veth pairs, zinaweza kuundwa na kuhamishwa kati ya namespaces za mtandao. Hii inaruhusu kuanzisha muunganisho wa mtandao kati ya namespaces au kati ya namespace na mfumo wa mwenyeji. Kwa mfano, mwisho mmoja wa veth pair unaweza kuwekwa katika namespace ya mtandao ya kontena, na mwisho mwingine unaweza kuunganishwa na **bridge** au interface nyingine ya mtandao katika namespace ya mwenyeji, ikitoa muunganisho wa mtandao kwa kontena.
3. Interfaces za mtandao ndani ya namespace zinaweza kuwa na **anwani zao za IP, meza za routing, na sheria za firewall**, huru kutoka kwa namespaces nyingine. Hii inaruhusu michakato katika namespaces tofauti za mtandao kuwa na usanidi tofauti wa mtandao na kufanya kazi kana kwamba zinakimbia kwenye mifumo tofauti ya mtandao.
4. Michakato inaweza kuhamishwa kati ya namespaces kwa kutumia wito wa mfumo `setns()`, au kuunda namespaces mpya kwa kutumia wito wa mfumo `unshare()` au `clone()` na bendera ya `CLONE_NEWNET`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, utaanza kutumia usanidi wa mtandao na interfaces zinazohusiana na namespace hiyo.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba namespace mpya ya kuunganisha ina **mtazamo sahihi na uliojitegemea wa taarifa za mchakato maalum kwa namespace hiyo**.

<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanajumuishwa.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato yatima. Kernel ya Linux itazima kuteua PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanajumuishwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu kuteua PID kwa kawaida.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, namespace mpya ya PID inatunzwa ipasavyo, ikiruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na hitilafu ya kugawa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;Angalia ni namespace ipi mchakato wako uko ndani yake
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Pata majina yote ya mitandao ya majimbo
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya mtandao wa namespace
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace nyingine ya mchakato ikiwa wewe ni root**. Na huwezi **kuingia** katika namespace nyingine **bila desktopa** inayorejelea hiyo (kama `/proc/self/ns/net`).

## Marejeo

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}

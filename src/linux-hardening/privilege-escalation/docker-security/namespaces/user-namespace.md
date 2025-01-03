# User Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

User namespace ni kipengele cha kernel ya Linux ambacho **kinatoa kutengwa kwa ramani za ID za mtumiaji na kundi**, kuruhusu kila user namespace kuwa na **seti yake ya kipekee ya ID za mtumiaji na kundi**. Kutengwa huku kunaruhusu michakato inayofanya kazi katika user namespaces tofauti **kuwa na mamlaka na umiliki tofauti**, hata kama zinashiriki ID za mtumiaji na kundi kwa nambari.

User namespaces ni muhimu sana katika uundaji wa kontena, ambapo kila kontena linapaswa kuwa na seti yake huru ya ID za mtumiaji na kundi, kuruhusu usalama bora na kutengwa kati ya kontena na mfumo wa mwenyeji.

### How it works:

1. Wakati user namespace mpya inaundwa, **inaanza na seti tupu ya ramani za ID za mtumiaji na kundi**. Hii inamaanisha kwamba mchakato wowote unaofanya kazi katika user namespace mpya utakuwa **na mamlaka hakuna nje ya namespace**.
2. Ramani za ID zinaweza kuanzishwa kati ya ID za mtumiaji na kundi katika namespace mpya na zile katika namespace ya mzazi (au mwenyeji). Hii **inaruhusu michakato katika namespace mpya kuwa na mamlaka na umiliki yanayolingana na ID za mtumiaji na kundi katika namespace ya mzazi**. Hata hivyo, ramani za ID zinaweza kuwekewa mipaka kwa anuwai maalum na sehemu za IDs, kuruhusu udhibiti wa kina juu ya mamlaka zinazotolewa kwa michakato katika namespace mpya.
3. Ndani ya user namespace, **michakato inaweza kuwa na mamlaka kamili ya root (UID 0) kwa shughuli ndani ya namespace**, wakati bado ikiwa na mamlaka zilizopunguzwa nje ya namespace. Hii inaruhusu **kontena kuendesha kwa uwezo kama root ndani ya namespace yao bila kuwa na mamlaka kamili ya root kwenye mfumo wa mwenyeji**.
4. Michakato inaweza kuhamia kati ya namespaces kwa kutumia wito wa mfumo wa `setns()` au kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWUSER`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, utaanza kutumia ramani za ID za mtumiaji na kundi zinazohusiana na namespace hiyo.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba namespace mpya ya kuunganisha ina **mtazamo sahihi na uliojitegemea wa taarifa za mchakato maalum kwa namespace hiyo**.

<details>

<summary>Hitilafu: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, hitilafu inakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanaingia.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna michakato mingine, kwani PID 1 ina jukumu maalum la kupokea michakato ya yatima. Kernel ya Linux itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa hitilafu ya "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanakuwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID wa kawaida.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, namespace mpya ya PID inatunzwa ipasavyo, ikiruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na hitilafu ya kugawa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Ili kutumia user namespace, Docker daemon inahitaji kuanzishwa na **`--userns-remap=default`**(Katika ubuntu 14.04, hii inaweza kufanywa kwa kubadilisha `/etc/default/docker` na kisha kutekeleza `sudo service docker restart`)

### &#x20;Angalia ni namespace ipi mchakato wako uko ndani
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Inawezekana kuangalia ramani ya mtumiaji kutoka kwenye kontena la docker kwa:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Au kutoka kwa mwenyeji na:
```bash
cat /proc/<pid>/uid_map
```
### Pata majina yote ya Mtumiaji
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace nyingine ya mchakato ikiwa wewe ni root**. Na huwezi **kuingia** katika namespace nyingine **bila deskteta** inayorejelea hiyo (kama `/proc/self/ns/user`).

### Unda namespace Mpya ya Mtumiaji (ikiwa na ramani)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Kupona Uwezo

Katika kesi ya majina ya watumiaji, **wakati jina jipya la mtumiaji linaundwa, mchakato unaoingia kwenye jina hilo unapata seti kamili ya uwezo ndani ya jina hilo**. Uwezo huu unaruhusu mchakato kufanya operesheni zenye mamlaka kama vile **kuunganisha** **safu za faili**, kuunda vifaa, au kubadilisha umiliki wa faili, lakini **tu ndani ya muktadha wa jina lake la mtumiaji**.

Kwa mfano, unapokuwa na uwezo wa `CAP_SYS_ADMIN` ndani ya jina la mtumiaji, unaweza kufanya operesheni ambazo kawaida zinahitaji uwezo huu, kama kuunganisha safu za faili, lakini tu ndani ya muktadha wa jina lako la mtumiaji. Operesheni zozote unazofanya kwa uwezo huu hazitaathiri mfumo wa mwenyeji au majina mengine.

> [!WARNING]
> Hivyo, hata kama kupata mchakato mpya ndani ya jina jipya la Mtumiaji **kutakupa uwezo wote tena** (CapEff: 000001ffffffffff), kwa kweli unaweza **tu kutumia zile zinazohusiana na jina hilo** (kuunganisha kwa mfano) lakini si kila mmoja. Hivyo, hii peke yake haitoshi kutoroka kutoka kwa kontena la Docker.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}

# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Namespace ya UTS (UNIX Time-Sharing System) ni kipengele cha kernel ya Linux kinachotoa **kujitengea kwa vitambulisho viwili vya mfumo**: **hostname** na **NIS** (Network Information Service) jina la eneo. Kujitengea hii inaruhusu kila namespace ya UTS kuwa na **hostname yake huru na jina la eneo la NIS**, ambayo ni muhimu hasa katika hali za uanzishaji wa kontena ambapo kila kontena linapaswa kuonekana kama mfumo tofauti wenye hostname yake.

### How it works:

1. Wakati namespace mpya ya UTS inaundwa, inaanza na **nakala ya hostname na jina la eneo la NIS kutoka kwa namespace yake ya mzazi**. Hii inamaanisha kwamba, wakati wa uundaji, namespace mpya **inashiriki vitambulisho sawa na mzazi wake**. Hata hivyo, mabadiliko yoyote yanayofuata kwa hostname au jina la eneo la NIS ndani ya namespace hayataathiri namespaces zingine.
2. Mchakato ndani ya namespace ya UTS **unaweza kubadilisha hostname na jina la eneo la NIS** kwa kutumia `sethostname()` na `setdomainname()` system calls, mtawalia. Mabadiliko haya ni ya ndani kwa namespace na hayaathiri namespaces zingine au mfumo wa mwenyeji.
3. Mchakato unaweza kuhamasishwa kati ya namespaces kwa kutumia `setns()` system call au kuunda namespaces mpya kwa kutumia `unshare()` au `clone()` system calls na bendera ya `CLONE_NEWUTS`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, utaanza kutumia hostname na jina la eneo la NIS linalohusishwa na namespace hiyo.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba namespace mpya ya kuunganisha ina **mtazamo sahihi na wa kutengwa wa taarifa za mchakato maalum kwa namespace hiyo**.

<details>

<summary>Kosa: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanajumuishwa.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa kosa la "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kuendesha `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanajumuishwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID wa kawaida.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, namespace mpya ya PID inatunzwa kwa usahihi, ikiruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Angalia ni namespace ipi mchakato wako uko ndani
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Pata majina yote ya UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}

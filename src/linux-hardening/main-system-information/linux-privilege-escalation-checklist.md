# Orodha Hakiki ya Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Orodha Hakiki - Linux Privilege Escalation



### **Zana bora ya kutafuta njia za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Taarifa za Mfumo](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Kagua [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), je, kuna **folda inayoweza kuandikwa**?
- [ ] Kagua [**env variables**](../linux-basics/linux-privilege-escalation/index.html#env-info), je, kuna taarifa nyeti?
- [ ] Tafuta [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **kwa kutumia scripts** (DirtyCow?)
- [ ] Kabla ya kuendesha kernel PoC, thibitisha **masharti yake halisi**, si `uname -r` pekee: architecture, chaguo/modules za `CONFIG_*` zinazohitajika, uwezo wa kuunda namespace na mitigations zinazotumika. Kwa mfano, jaribu upatikanaji wa user/network namespace kwa `unshare -Urn true`; exploits za kisasa za netfilter zinaweza kuhitaji `CONFIG_USER_NS`, user namespaces zisizo na ruhusa za juu na `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Kagua** kama [**toleo la sudo** lina udhaifu](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Uthibitishaji wa sahihi ya [**Dmesg** umeshindwa](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Kagua [**kernel module na makosa ya usanidi wa kupakia modules**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, utekelezaji wa masharti ya sahihi na `modules_disabled`.
- [ ] Kagua [**njia za kutumia vibaya kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) ikiwa njia ya helper inaweza kubadilishwa au kuchochewa.
- [ ] Kagua [**njia za /lib/modules zinazoweza kuandikwa**](kernel-modules-and-modprobe.md#writable-libmodules-review), zikiwemo faili za `.ko*` na metadata ya `modules.*` zinazoweza kuandikwa.
- [ ] Taarifa nyingine za mfumo ([tarehe, takwimu za mfumo, taarifa za CPU, printers](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Orodhesha defenses zaidi](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizowekwa
- [ ] **Kuna drive ambayo haijawekwa?**
- [ ] **Kuna creds kwenye fstab?**

### [**Software Iliyosakinishwa**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Kagua kama** [**software muhimu**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **imesakinishwa**
- [ ] **Kagua kama** [**software yenye udhaifu**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **imesakinishwa**
- [ ] Kwenye Debian/Ubuntu, kagua kama **uchanganuzi wa interpreter wa needrestart** umesakinishwa/umewashwa: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Builds zenye udhaifu zilivuka mpaka wa privilege kwa kutumia tena `PYTHONPATH`/`RUBYLIB` zinazodhibitiwa na mshambuliaji, kushindania `/proc/<pid>/exe`, au kuchanganua njia za Perl zinazodhibitiwa na mshambuliaji wakati APT au `unattended-upgrades` ilipoendesha needrestart kama root.<sup>[[4]](#references)</sup>

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Je, kuna **software isiyojulikana inayoendeshwa**?
- [ ] Je, kuna software inayoendeshwa ikiwa na **privileges zaidi kuliko inavyopaswa kuwa nazo**?
- [ ] Tafuta **exploits za processes zinazoendeshwa** (hasa toleo linaloendeshwa).
- [ ] Je, unaweza **kubadilisha binary** ya process yoyote inayoendeshwa?
- [ ] **Fuatilia processes** na ukague kama kuna process yoyote ya kuvutia inayoendeshwa mara kwa mara.
- [ ] Je, unaweza **kusoma** **process memory** inayovutia (ambapo passwords zinaweza kuwa zimehifadhiwa)?

### [Jobs zilizopangwa/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)inabadilishwa na cron fulani na unaweza **kuandika** humo?
- [ ] Kuna [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)kwenye cron job yoyote?
- [ ] Kuna [**script inayoweza kubadilishwa** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)inayo**endeshwa** au iliyo ndani ya **folda inayoweza kubadilishwa**?
- [ ] Je, umegundua **script** inayoweza au inayoendelea [**kuendeshwa** mara **nyingi**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Kuna faili ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayoendeshwa na **service**?
- [ ] Kuna **helper, config au environment file inayoweza kuandikwa, inayorejelewa na root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Kagua unit iliyounganishwa kwa `systemctl cat <unit>` na uchunguze [matumizi mabaya ya faili za service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Je, workflow ya privileged inayohitajika inapohitajika huendesha helper chini ya directory inayoweza kuandikwa yenye privilege ya chini? Kagua helper na parent yake ili kutafuta [root inayoendesha paths zinazoweza kubadilishwa na user](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); helpers zinazoishi kwa muda mfupi zinaweza kuonekana tu workflow inapoendeshwa.
- [ ] Kuna **folda inayoweza kuandikwa ndani ya systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** katika `/etc/systemd/system/<unit>.d/*.conf` inayoweza kubatilisha `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Kuna faili ya **.socket inayoweza kuandikwa**?
- [ ] Je, unaweza **kuwasiliana na socket yoyote**?
- [ ] Kuna **HTTP sockets** zenye taarifa za kuvutia?
- [ ] Je, unaweza kufikia [**API ya container-runtime au node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) kama `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` au endpoint ya kubelet? Jaribu API ghafi ya HTTP/gRPC hata kama CLI yake ya kawaida haipo.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Orodhesha network ili kujua ulipo
- [ ] Kuna **ports zilizo wazi ambazo hukuweza kufikia kabla** ya kupata shell ndani ya mashine?
- [ ] Je, unaweza **kunusa traffic** kwa kutumia `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Orodhesha users/groups kwa ujumla
- [ ] Je, una UID **kubwa sana**? Je, **mashine** ina **udhaifu**?
- [ ] Je, unaweza [**kupandisha privileges kwa sababu ya group**](../user-information/interesting-groups-linux-pe/index.html) uliyomo?
- [ ] Data ya **Clipboard**?
- [ ] Sera ya Password?
- [ ] Jaribu **kutumia** kila **password inayojulikana** uliyogundua awali kuingia kama **kila** **user** anayewezekana. Jaribu pia kuingia bila password.

### [PATH Inayoweza Kuandikwa](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **ruhusa ya kuandika kwenye folda fulani iliyo ndani ya PATH**, unaweza kuweza kupandisha privileges

### [Amri za SUDO na SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Je, unaweza kutekeleza **amri yoyote kwa sudo**? Je, unaweza kuitumia KUSOMA, KUANDIKA au KUTEKELEZA kitu chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, kagua **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili kuhariri faili yoyote kwenye matoleo yenye udhaifu (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Kuna **SUID binary inayoweza kutumiwa vibaya**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, amri za [**sudo** zimewekewa **vikwazo** vya **path**? Je, unaweza **kukwepa** vikwazo hivyo](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyoainishwa**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary yenye path iliyoainishwa**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Kwepa
- [ ] [**LD_PRELOAD vuln**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ukosefu wa .so library kwenye SUID binary**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) kutoka kwenye folda inayoweza kuandikwa?
- [ ] [**SUID RPATH/RUNPATH au library path inayoweza kuandikwa**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens zinapatikana**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Je, unaweza kuunda SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Je, unaweza [**kusoma au kubadilisha faili za sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Je, unaweza [**kubadilisha /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Amri ya [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Kuna binary yoyote yenye **capability isiyotarajiwa**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Kuna faili yoyote yenye **ACL isiyotarajiwa**?

### [Shell sessions Zilizofunguliwa](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Thamani za usanidi wa SSH zinazovutia**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Faili Zinazovutia](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Faili za profile** - Unaweza kusoma data nyeti? Kuandika ili kupandisha privileges?
- [ ] **Faili za passwd/shadow** - Unaweza kusoma data nyeti? Kuandika ili kupandisha privileges?
- [ ] **Kagua folda zinazovutia kwa kawaida** ili kutafuta data nyeti
- [ ] **Faili zilizo kwenye maeneo yasiyo ya kawaida/zilizomilikiwa na wengine,** huenda unaweza kuzifikia au kubadilisha faili zinazotekelezeka
- [ ] Ziliz**obadilishwa** ndani ya dakika za mwisho
- [ ] **Faili za SQLite DB**
- [ ] **Faili zilizofichwa**
- [ ] **Scripts/Binaries zilizo kwenye PATH**
- [ ] **Faili za wavuti** (passwords?)
- [ ] **Backups**?
- [ ] **Faili zinazojulikana kuwa na passwords**: Tumia **Linpeas** na **LaZagne**
- [ ] **Utafutaji wa jumla**

### [**Faili Zinazoweza Kuandikwa**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Je, unaweza **kubadilisha python library** ili kutekeleza amri kiholela?
- [ ] Je, unaweza **kubadilisha log files**? Exploit ya **Logtotten**
- [ ] Je, unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Exploit ya Centos/Redhat
- [ ] Je, unaweza [**kuandika kwenye ini, int.d, systemd au rc.d files**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Mbinu nyingine**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Je, unaweza [**kutumia NFS vibaya ili kupandisha privileges**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**kutoka kwenye shell yenye vikwazo**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Ushauri wa usalama wa Sudo: kuhariri faili kiholela kwa sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Nyaraka za Oracle Linux: usanidi wa systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: masharti na utafiti wa exploit ya CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Ushauri wa Usalama wa Qualys: LPEs katika needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}

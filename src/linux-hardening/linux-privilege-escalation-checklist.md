# Orodha ya Ukaguzi - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Chombo bora cha kutafuta vector za Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Pata **taarifa za OS**
- [ ] Angalia [**PATH**](privilege-escalation/index.html#path), kuna **folda inayoweza kuandikwa**?
- [ ] Angalia [**env variables**](privilege-escalation/index.html#env-info), kuna maelezo nyeti?
- [ ] Tafuta [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) kwa kutumia scripts (DirtyCow?)
- [ ] Angalia ikiwa [**sudo version**](privilege-escalation/index.html#sudo-version) ina udhaifu
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Zaidi ya utambuzi wa mfumo ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Tambua zaidi ulinzi unaowezekana](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizosimikwa
- [ ] Kuna drive isiyosimikwa?
- [ ] Kuna **credentials** katika fstab?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Angalia** [ **useful software**](privilege-escalation/index.html#useful-software) imewekwa
- [ ] **Angalia** [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) imewekwa

### [Processes](privilege-escalation/index.html#processes)

- [ ] Kuna **software isiyojulikana inayotendeka**?
- [ ] Kuna software inayotendeka kwa **vigezo vya juu kuliko inavyostahili**?
- [ ] Tafuta **exploits** za michakato inayotenda (hasa toleo linalotumika).
- [ ] Je, unaweza **kubadilisha binary** ya mchakato wowote unaotenda?
- [ ] **Fuatilia michakato** na angalia kama kuna mchakato wa kuvutia unaotendeka mara kwa mara.
- [ ] Je, unaweza **kusoma** kumbukumbu ya mchakato ambayo inaweza kuwa na nywila?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH** ](privilege-escalation/index.html#cron-path) inabadilishwa na cron fulani na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) kwenye cron job?
- [ ] Je, kuna [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) inayoendeshwa au iko ndani ya **folda inayoweza kuhaririwa**?
- [ ] Umegundua kwamba script fulani inaweza kuendeshwa [**sana mara**](privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](privilege-escalation/index.html#services)

- [ ] Kuna faili ya **.service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **service**?
- [ ] Kuna **folda inayoweza kuandikwa katika systemd PATH**?
- [ ] Kuna **systemd unit drop-in inayoweza kuandikwa** katika `/etc/systemd/system/<unit>.d/*.conf` ambayo inaweza kuingilia `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Kuna faili ya **.socket inayoweza kuandikwa**?
- [ ] Je, unaweza **kuwasiliana na socket yoyote**?
- [ ] **HTTP sockets** zenye taarifa za kuvutia?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](privilege-escalation/index.html#network)

- [ ] Fanya utambuzi wa mtandao ili ujue uko wapi
- [ ] **Porti zilizo wazi ambazo hukuweza kufikia kabla** ya kupata shell ndani ya mashine?
- [ ] Je, unaweza **kuskia trafiki** kwa kutumia `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Utambuzi wa watumiaji/madereva kwa ujumla
- [ ] Je, una **UID kubwa sana**? Je, **mashine** ni **nyeti**?
- [ ] Je, unaweza [**kupandisha hadhi kwa msaada wa group**](privilege-escalation/interesting-groups-linux-pe/index.html) unayemiliki?
- [ ] Data ya **Clipboard**?
- [ ] Sera ya nywila?
- [ ] Jaribu **kutumia** kila **nywila unazojua** ambazo umegundua hapo awali kuingia kwa kila **mtumiaji** anayetegemewa. Jaribu kuingia pia bila nenosiri.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **idhini ya kuandika kwenye folda fulani katika PATH** unaweza kuwa na uwezo wa kupandisha hadhi

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Je, unaweza kutekeleza **amri yoyote kwa sudo**? Je, unaweza kuitumia kusoma, kuandika au kutekeleza chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Ikiwa `sudo -l` inaruhusu `sudoedit`, angalia **sudoedit argument injection** (CVE-2023-22809) kupitia `SUDO_EDITOR`/`VISUAL`/`EDITOR` ili kuhariri faili yoyote kwenye toleo zilizoathirika (`sudo -V` < 1.9.12p2). Mfano: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Je, kuna **SUID binary inayoweza kushambuliwa**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, [**sudo** amri zimepunguzwa kwa **path**? unaweza **kuzipita** vizuizi](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) kutoka kwa folda inayoweza kuandikwa?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Je, unaweza [**kusoma au kubadilisha sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Je, unaweza [**kubadilisha /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) amri

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Je, binary yoyote ina **capability isiyotarajiwa**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Je, faili yoyote ina **ACL isiyotarajiwa**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Soma data nyeti? Andika kwa privesc?
- [ ] **passwd/shadow files** - Soma data nyeti? Andika kwa privesc?
- [ ] **Angalia folda zinazojulikana kwa kuwa zenye data nyeti**
- [ ] **Maeneo yasiyo ya kawaida/Miliki wa faili,** unaweza kuwa na ufikiaji au kubadili faili zinazotekelezwa
- [ ] **Imerekebishwa** katika dakika za hivi karibuni
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries katika PATH**
- [ ] **Web files** (nywila?)
- [ ] **Backups**?
- [ ] **Faili zinazojuwa kuwa na nywila**: Tumia **Linpeas** na **LaZagne**
- [ ] **Utafutaji wa jumla**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Badilisha library ya python** ili kutekeleza amri zozote?
- [ ] Je, unaweza **kuhariri log files**? **Logtotten** exploit
- [ ] Je, unaweza **kuhariri /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Je, unaweza [**kuandika katika ini, init.d, systemd au rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Je, unaweza [**kutitumia NFS kupandisha hadhi**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Unahitaji [**kutoka kwenye shell iliyofungwa**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Marejeo

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}

# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Pata **habari za OS**
- [ ] Angalia [**PATH**](privilege-escalation/index.html#path), kuna **folda inayoweza kuandikwa**?
- [ ] Angalia [**env variables**](privilege-escalation/index.html#env-info), kuna maelezo yoyote nyeti?
- [ ] Tafuta [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **ukitumia scripts** (DirtyCow?)
- [ ] **Angalia** kama [**sudo version** inahatarishwa](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** uthibitisho wa saini umeshindwa](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Mengi zaidi ya mfumo ([tarehe, takwimu za mfumo, taarifa za cpu, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Tathmini ulinzi zaidi](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Orodhesha** drives zilizowekwa
- [ ] **Kuna drive isiyowekwa?**
- [ ] **Kuna creds katika fstab?**

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Angalia** [**programu muhimu**](privilege-escalation/index.html#useful-software) **zilizowekwa**
- [ ] **Angalia** [**programu zinazohatarishwa**](privilege-escalation/index.html#vulnerable-software-installed) **zilizowekwa**

### [Processes](privilege-escalation/index.html#processes)

- [ ] Je, kuna **programu isiyojulikana inayoendesha**?
- [ ] Je, kuna programu inayoendesha na **haki zaidi kuliko inavyopaswa kuwa**?
- [ ] Tafuta **exploits za michakato inayoendesha** (hasa toleo linaloendesha).
- [ ] Je, unaweza **kubadilisha binary** ya mchakato wowote unaoendesha?
- [ ] **Fuatilia michakato** na angalia kama kuna mchakato wa kuvutia unaoendesha mara kwa mara.
- [ ] Je, unaweza **kusoma** baadhi ya **kumbukumbu za mchakato** (ambapo nywila zinaweza kuhifadhiwa)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Je, [**PATH**](privilege-escalation/index.html#cron-path) inabadilishwa na cron na unaweza **kuandika** ndani yake?
- [ ] Kuna [**wildcard**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) katika kazi ya cron?
- [ ] Baadhi ya [**script inayoweza kubadilishwa**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) inatekelezwa au iko ndani ya **folda inayoweza kubadilishwa**?
- [ ] Je, umegundua kuwa baadhi ya **script** zinaweza au zina [**tekelezwa** mara **mara kwa mara**](privilege-escalation/index.html#frequent-cron-jobs)? (kila dakika 1, 2 au 5)

### [Services](privilege-escalation/index.html#services)

- [ ] Kuna **faili ya .service inayoweza kuandikwa**?
- [ ] Kuna **binary inayoweza kuandikwa** inayotekelezwa na **huduma**?
- [ ] Kuna **folda inayoweza kuandikwa katika systemd PATH**?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Kuna **timer inayoweza kuandikwa**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Kuna **faili ya .socket inayoweza kuandikwa**?
- [ ] Je, unaweza **kuwasiliana na socket yoyote**?
- [ ] **HTTP sockets** zikiwa na maelezo ya kuvutia?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Je, unaweza **kuwasiliana na D-Bus yoyote**?

### [Network](privilege-escalation/index.html#network)

- [ ] Tathmini mtandao ili kujua uko wapi
- [ ] **Port zilizofunguliwa ambazo huwezi kufikia kabla** ya kupata shell ndani ya mashine?
- [ ] Je, unaweza **kusniff traffic** ukitumia `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Orodha ya watumiaji/mikundi **ya jumla**
- [ ] Je, una **UID kubwa sana**? Je, **mashine** **inahatarishwa**?
- [ ] Je, unaweza [**kuinua haki kwa sababu ya kundi**](privilege-escalation/interesting-groups-linux-pe/) unalotegemea?
- [ ] **Data za Clipboard**?
- [ ] Sera ya Nywila?
- [ ] Jaribu **kutumia** kila **nywila inayojulikana** uliyogundua awali kuingia **na kila** **mtumiaji** anayeweza. Jaribu kuingia pia bila nywila.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Ikiwa una **haki za kuandika juu ya folda fulani katika PATH** unaweza kuwa na uwezo wa kuinua haki

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Je, unaweza kutekeleza **amri yoyote na sudo**? Je, unaweza kuitumia KUSOMA, KUANDIKA au KUTEKELEZA chochote kama root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, kuna **binary inayoweza kutumika ya SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Je, [**amri za sudo** **zimepunguziliwa** na **path**? Je, unaweza **kuzidi** vizuizi](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary bila path iliyotajwa**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary ikitaja path**](privilege-escalation/index.html#suid-binary-with-command-path)? Pita
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Ukosefu wa maktaba ya .so katika binary ya SUID**](privilege-escalation/index.html#suid-binary-so-injection) kutoka folda inayoweza kuandikwa?
- [ ] [**SUDO tokens zinazopatikana**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Je, unaweza kuunda token ya SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Je, unaweza [**kusoma au kubadilisha faili za sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Je, unaweza [**kubadilisha /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) amri

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Je, kuna binary yoyote yenye **uwezo usiotarajiwa**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Je, kuna faili yoyote yenye **ACL isiyotegemewa**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Faili za Profaili** - Soma data nyeti? Andika kwa privesc?
- [ ] **faili za passwd/shadow** - Soma data nyeti? Andika kwa privesc?
- [ ] **Angalia folda zinazovutia** kwa data nyeti
- [ ] **Mahali/Picha za ajabu,** unaweza kuwa na ufikiaji au kubadilisha faili zinazoweza kutekelezwa
- [ ] **Imebadilishwa** katika dakika za mwisho
- [ ] **Faili za Sqlite DB**
- [ ] **Faili zilizofichwa**
- [ ] **Script/Binaries katika PATH**
- [ ] **Faili za Mtandao** (nywila?)
- [ ] **Nakala za akiba**?
- [ ] **Faili zinazojulikana ambazo zina nywila**: Tumia **Linpeas** na **LaZagne**
- [ ] **Utafutaji wa jumla**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Badilisha maktaba ya python** ili kutekeleza amri zisizo za kawaida?
- [ ] Je, unaweza **kubadilisha faili za log**? **Logtotten** exploit
- [ ] Je, unaweza **kubadilisha /etc/sysconfig/network-scripts/**? Centos/Redhat exploit
- [ ] Je, unaweza [**kuandika katika faili za ini, int.d, systemd au rc.d**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Je, unaweza [**kudhulumu NFS ili kuinua haki**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Je, unahitaji [**kutoroka kutoka shell yenye vizuizi**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}

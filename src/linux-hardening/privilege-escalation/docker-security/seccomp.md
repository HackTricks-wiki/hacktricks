# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

**Seccomp**, जिसका मतलब Secure Computing mode है, **Linux kernel की एक सुरक्षा विशेषता है जो सिस्टम कॉल को फ़िल्टर करने के लिए डिज़ाइन की गई है**। यह प्रक्रियाओं को सिस्टम कॉल के एक सीमित सेट (`exit()`, `sigreturn()`, `read()`, और `write()` के लिए पहले से खुले फ़ाइल डिस्क्रिप्टर) तक सीमित करता है। यदि कोई प्रक्रिया कुछ और कॉल करने की कोशिश करती है, तो इसे SIGKILL या SIGSYS का उपयोग करके कर्नेल द्वारा समाप्त कर दिया जाता है। यह तंत्र संसाधनों को वर्चुअलाइज़ नहीं करता है बल्कि प्रक्रिया को उनसे अलग करता है।

Seccomp को सक्रिय करने के दो तरीके हैं: `PR_SET_SECCOMP` के साथ `prctl(2)` सिस्टम कॉल के माध्यम से, या Linux kernels 3.17 और उससे ऊपर के लिए, `seccomp(2)` सिस्टम कॉल के माध्यम से। `/proc/self/seccomp` में लिखकर seccomp को सक्षम करने का पुराना तरीका `prctl()` के पक्ष में हटा दिया गया है।

एक सुधार, **seccomp-bpf**, एक अनुकूलन योग्य नीति के साथ सिस्टम कॉल को फ़िल्टर करने की क्षमता जोड़ता है, जो Berkeley Packet Filter (BPF) नियमों का उपयोग करता है। इस विस्तार का उपयोग OpenSSH, vsftpd, और Chrome OS और Linux पर Chrome/Chromium ब्राउज़रों जैसे सॉफ़्टवेयर द्वारा लचीले और कुशल syscall फ़िल्टरिंग के लिए किया जाता है, जो अब अप्रयुक्त systrace के लिए एक विकल्प प्रदान करता है।

### **Original/Strict Mode**

इस मोड में Seccomp **केवल syscalls** `exit()`, `sigreturn()`, `read()` और `write()` को पहले से खुले फ़ाइल डिस्क्रिप्टर के लिए अनुमति देता है। यदि कोई अन्य syscall किया जाता है, तो प्रक्रिया को SIGKILL का उपयोग करके मार दिया जाता है।
```c:seccomp_strict.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

यह मोड **कनफिगर करने योग्य नीति का उपयोग करके सिस्टम कॉल को फ़िल्टर करने** की अनुमति देता है, जो बर्कले पैकेट फ़िल्टर नियमों का उपयोग करके लागू किया गया है।
```c:seccomp_bpf.c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Seccomp in Docker

**Seccomp-bpf** का समर्थन **Docker** द्वारा किया जाता है ताकि **syscalls** को प्रभावी ढंग से प्रतिबंधित किया जा सके, जिससे सतह क्षेत्र कम हो जाता है। आप [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) में **डिफ़ॉल्ट** द्वारा **ब्लॉक किए गए syscalls** को पा सकते हैं और **डिफ़ॉल्ट seccomp प्रोफ़ाइल** यहाँ मिल सकती है [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)।\
आप एक **विभिन्न seccomp** नीति के साथ एक डॉकर कंटेनर चला सकते हैं:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
यदि आप उदाहरण के लिए किसी कंटेनर को कुछ **syscall** जैसे `uname` को निष्पादित करने से **रोकना** चाहते हैं, तो आप [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) से डिफ़ॉल्ट प्रोफ़ाइल डाउनलोड कर सकते हैं और बस **सूची से `uname` स्ट्रिंग को हटा सकते हैं।**\
यदि आप यह सुनिश्चित करना चाहते हैं कि **कोई बाइनरी एक डॉकर कंटेनर के अंदर काम न करे**, तो आप बाइनरी द्वारा उपयोग किए जा रहे syscalls की सूची बनाने के लिए strace का उपयोग कर सकते हैं और फिर उन्हें रोक सकते हैं।\
निम्नलिखित उदाहरण में `uname` के **syscalls** का पता लगाया गया है:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> यदि आप **Docker का उपयोग केवल एक एप्लिकेशन लॉन्च करने के लिए कर रहे हैं**, तो आप इसे **`strace`** के साथ **प्रोफाइल** कर सकते हैं और केवल उन syscalls की अनुमति दे सकते हैं जिनकी इसे आवश्यकता है।

### उदाहरण Seccomp नीति

[Example from here](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Seccomp फीचर को स्पष्ट करने के लिए, आइए एक Seccomp प्रोफाइल बनाते हैं जो "chmod" सिस्टम कॉल को नीचे की तरह निष्क्रिय करता है।
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
उपरोक्त प्रोफ़ाइल में, हमने डिफ़ॉल्ट क्रिया को "अनुमति" पर सेट किया है और "chmod" को अक्षम करने के लिए एक काली सूची बनाई है। अधिक सुरक्षित होने के लिए, हम डिफ़ॉल्ट क्रिया को ड्रॉप पर सेट कर सकते हैं और सिस्टम कॉल को चयनात्मक रूप से सक्षम करने के लिए एक सफेद सूची बना सकते हैं।\
निम्नलिखित आउटपुट "chmod" कॉल को त्रुटि लौटाते हुए दिखाता है क्योंकि इसे seccomp प्रोफ़ाइल में अक्षम किया गया है।
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
निम्नलिखित आउटपुट "docker inspect" द्वारा प्रोफ़ाइल को प्रदर्शित करता है:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}

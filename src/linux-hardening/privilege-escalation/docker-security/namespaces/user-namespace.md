# यूज़र नेमस्पेस

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## संदर्भ

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## बुनियादी जानकारी

एक यूज़र नेमस्पेस Linux kernel की एक सुविधा है जो **user और group ID मैपिंग्स का अलगाव प्रदान करती है**, जिससे प्रत्येक यूज़र नेमस्पेस के पास अपनी **अपनी user और group IDs का सेट** हो सकता है। यह अलगाव विभिन्न यूज़र नेमस्पेस में चलने वाली प्रक्रियाओं को **विभिन्न प्रिविलेज और ओनरशिप** रखने में सक्षम बनाता है, भले ही उनका संख्यात्मक user और group ID समान हो।

यूज़र नेमस्पेस कंटेनरीकरण में विशेष रूप से उपयोगी हैं, जहाँ प्रत्येक container का अपना स्वतंत्र user और group ID सेट होना चाहिए, जिससे कंटेनरों और होस्ट सिस्टम के बीच बेहतर सुरक्षा और अलगाव सुनिश्चित होता है।

### यह कैसे काम करता है:

1. जब एक नया यूज़र नेमस्पेस बनाया जाता है, तो यह **user और group ID मैपिंग्स के खाली सेट के साथ शुरू होता है**। इसका मतलब है कि नए यूज़र नेमस्पेस में चल रही कोई भी प्रक्रिया **प्रारम्भ में नेमस्पेस के बाहर कोई अधिकार नहीं रखेगी**।
2. ID मैपिंग्स नए नेमस्पेस और parent (या host) नेमस्पेस में मौजूद user और group IDs के बीच स्थापित की जा सकती हैं। इससे **नए नेमस्पेस में प्रक्रियाओं को parent नेमस्पेस के user और group IDs के अनुरूप प्रिविलेज और ओनरशिप मिल सकती है**। हालांकि, ID मैपिंग्स को विशिष्ट रेंज और ID के उपसमूहों तक सीमित किया जा सकता है, जिससे नेमस्पेस को दिए जाने वाले प्रिविलेज पर सूक्ष्म नियंत्रण संभव होता है।
3. एक यूज़र नेमस्पेस के भीतर, **प्रोसेस को नेमस्पेस के अंदर के ऑपरेशनों के लिए पूर्ण root प्रिविलेज (UID 0) मिल सकते हैं**, जबकि नेमस्पेस के बाहर उनके प्रिविलेज सीमित रहेंगे। यह अनुमति देता है कि **कंटेनर अपने नेमस्पेस के भीतर root-जैसी क्षमताओं के साथ चलें बिना होस्ट सिस्टम पर पूर्ण root प्रिविलेज के**।
4. प्रक्रियाएँ `setns()` system call का उपयोग करके नेमस्पेस के बीच जा सकती हैं या `unshare()` या `clone()` system calls के साथ `CLONE_NEWUSER` फ्लैग का उपयोग करके नए नेमस्पेस बना सकती हैं। जब कोई प्रक्रिया नए नेमस्पेस में चली जाती है या नया नेमस्पेस बनाती है, तो वह उस नेमस्पेस से संबंधित user और group ID मैपिंग्स का उपयोग शुरू कर देगी।

## लैब:

### विभिन्न नेमस्पेस बनाएँ

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
user namespace का उपयोग करने के लिए, Docker daemon को **`--userns-remap=default`**(ubuntu 14.04 में, यह `/etc/default/docker` को संशोधित करके और फिर `sudo service docker restart` चलाकर किया जा सकता है)

### जाँचें कि आपका process किस namespace में है
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
docker container से user map की जांच की जा सकती है:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
या होस्ट से निम्न के साथ:
```bash
cat /proc/<pid>/uid_map
```
### सभी User namespaces खोजें
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### User namespace के अंदर प्रवेश करें
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
साथ ही, आप केवल **root होने पर किसी अन्य process namespace में प्रवेश कर सकते हैं**। और आप **प्रवेश नहीं कर सकते** **किसी अन्य namespace में** **बिना किसी descriptor के** जो उस पर इशारा करे (जैसे `/proc/self/ns/user`)।

### नया User namespace बनाएँ (mappings के साथ)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### अनप्रिविलेज्ड UID/GID मैपिंग नियम

जब वह प्रक्रिया जो `uid_map`/`gid_map` में लिख रही है **parent user namespace में CAP_SETUID/CAP_SETGID नहीं रखती है**, तो kernel कड़े नियम लागू करता है: कॉलर की प्रभावी UID/GID के लिए केवल एक ही मैपिंग अनुमति है, और `gid_map` के लिए आपको पहले `setgroups(2)` को अक्षम करना होगा — `/proc/<pid>/setgroups` में `deny` लिखकर।
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-मैप्ड माउंट्स (MOUNT_ATTR_IDMAP)

ID-mapped mounts **user namespace mapping को एक mount से जोड़ते हैं**, इसलिए जब उस माउंट के माध्यम से फ़ाइल तक पहुँच की जाती है तो फ़ाइल का मालिकाना पुन:मैप हो जाता है। यह आमतौर पर container runtimes (विशेषकर rootless) द्वारा host paths को recursive `chown` किए बिना साझा करने के लिए इस्तेमाल किया जाता है, जबकि user namespace के UID/GID translation को लागू किया जाता है।

ऑफेंसिव दृष्टिकोण से, **यदि आप एक mount namespace बना सकते हैं और अपने user namespace के अंदर `CAP_SYS_ADMIN` रख सकते हैं**, और फ़ाइल सिस्टम ID-mapped mounts को सपोर्ट करता है, तो आप bind mounts के मालिकाना *दृश्यों* को रीमैप कर सकते हैं। यह **on-disk ownership को बदलता नहीं है**, पर यह अन्यथा लिखने-योग्य नहीं फ़ाइलों को आपके मैप किए गए UID/GID द्वारा उस namespace के भीतर मालिक दिखा सकता है।

### क्षमतियाँ पुनः प्राप्त करना

user namespaces के मामले में, **जब एक नया user namespace बनाया जाता है, तो उस namespace में प्रवेश करने वाली प्रक्रिया को उस namespace के भीतर capabilities का एक पूरा सेट दिया जाता है**। ये capabilities प्रक्रिया को privileged operations करने की अनुमति देती हैं जैसे **mounting** **filesystems**, devices बनाना, या फ़ाइलों का ownership बदलना, पर **केवल अपने user namespace के संदर्भ में**।

उदाहरण के लिए, जब आपके पास किसी user namespace के भीतर `CAP_SYS_ADMIN` capability होती है, तो आप उन ऑपरेशनों को कर सकते हैं जिनके लिए सामान्यतः यह capability चाहिए होती है, जैसे mounting filesystems, पर यह सब केवल आपके user namespace के संदर्भ में ही लागू होगा। आप इस capability के साथ जो भी ऑपरेशन करते हैं वह host system या अन्य namespaces को प्रभावित नहीं करेगा।

> [!WARNING]
> इसलिए, भले ही किसी नए User namespace के अंदर एक नया प्रोसेस पाना **आपको सभी capabilities वापस देगा** (CapEff: 000001ffffffffff), आप वास्तव में **केवल उन्हीं का उपयोग कर सकते हैं जो namespace से संबंधित हैं** (mount उदाहरण के लिए) पर हर एक का नहीं। इसलिए, यह अपने आप Docker container से निकलने के लिए पर्याप्त नहीं है।
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## संदर्भ

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}

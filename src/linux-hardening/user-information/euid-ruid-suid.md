# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### User Identification Variables

- **`ruid`**: **real user ID** उस user को दर्शाता है जिसने process शुरू किया है।
- **`euid`**: इसे **effective user ID** के रूप में जाना जाता है। यह उस user identity को दर्शाता है जिसका उपयोग system process privileges निर्धारित करने के लिए करता है। सामान्यतः, `euid`, `ruid` के समान होता है। इसका अपवाद SetUID binary का execution है, जिसमें `euid` file owner की identity अपना लेता है और इस प्रकार विशेष operational permissions मिलती हैं।
- **`suid`**: यह **saved user ID** तब महत्वपूर्ण होता है जब कोई high-privilege process (आमतौर पर root के रूप में चलने वाला) कुछ tasks करने के लिए अस्थायी रूप से अपने privileges छोड़ना चाहता है और बाद में अपनी प्रारंभिक elevated status पुनः प्राप्त करना चाहता है।

#### Important Note

root के अंतर्गत न चलने वाला process अपने `euid` को केवल वर्तमान `ruid`, `euid`, या `suid` के समान मान में बदल सकता है।

### Understanding set\*uid Functions

- **`setuid`**: प्रारंभिक धारणा के विपरीत, `setuid` मुख्य रूप से `euid` को बदलता है, `ruid` को नहीं। विशेष रूप से, privileged processes के लिए यह `ruid`, `euid`, और `suid` को निर्दिष्ट user, अक्सर root, के साथ align करता है और `suid` के overriding प्रभाव के कारण इन IDs को प्रभावी रूप से स्थायी बना देता है। विस्तृत जानकारी [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) में मिल सकती है।
- **`setreuid`** और **`setresuid`**: ये functions `ruid`, `euid`, और `suid` को सूक्ष्म रूप से adjust करने की अनुमति देते हैं। हालांकि, उनकी capabilities process के privilege level पर निर्भर करती हैं। non-root processes के लिए modifications वर्तमान `ruid`, `euid`, और `suid` values तक सीमित होते हैं। इसके विपरीत, root processes या `CAP_SETUID` capability वाले processes इन IDs को arbitrary values दे सकते हैं। अधिक जानकारी [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) और [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) में प्राप्त की जा सकती है।

इन functionalities को security mechanism के रूप में नहीं, बल्कि इच्छित operational flow को सुविधाजनक बनाने के लिए design किया गया है, जैसे कि जब कोई program अपने effective user ID को बदलकर किसी अन्य user की identity अपना लेता है।

ध्यान दें कि `setuid` root तक privilege elevation के लिए एक सामान्य विकल्प हो सकता है (क्योंकि यह सभी IDs को root के साथ align करता है), लेकिन अलग-अलग scenarios में user ID behaviors को समझने और manipulate करने के लिए इन functions के बीच अंतर करना महत्वपूर्ण है।

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` पहले argument द्वारा निर्धारित program को शुरू करता है। यह दो array arguments लेता है: arguments के लिए `argv` और environment के लिए `envp`।
- **Behavior**: यह caller का memory space बनाए रखता है, लेकिन stack, heap और data segments को refresh करता है। Program का code नए program से replace हो जाता है।
- **User ID Preservation**:
- `ruid`, `euid`, और supplementary group IDs अपरिवर्तित रहते हैं।
- यदि नए program में SetUID bit set है, तो `euid` में सूक्ष्म changes हो सकते हैं।
- execution के बाद `suid`, `euid` से update हो जाता है।
- **Documentation**: विस्तृत जानकारी [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) पर मिल सकती है।

#### **`system` Function**

- **Functionality**: `execve` के विपरीत, `system` `fork` का उपयोग करके child process बनाता है और उस child process के भीतर `execl` का उपयोग करके command execute करता है।
- **Command Execution**: यह command को `sh` के माध्यम से `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` द्वारा execute करता है।
- **Behavior**: चूंकि `execl`, `execve` का एक रूप है, इसलिए यह समान तरीके से operate करता है, लेकिन नए child process के context में।
- **Documentation**: अधिक जानकारी [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) से प्राप्त की जा सकती है।

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- इसमें `-p` option है, जो `euid` और `ruid` के treatment को प्रभावित करता है।
- `-p` के बिना, यदि शुरुआत में दोनों अलग हों, तो `bash` `euid` को `ruid` पर set करता है।
- `-p` के साथ, प्रारंभिक `euid` preserve रहता है।
- अधिक जानकारी [`bash` man page](https://linux.die.net/man/1/bash) में मिल सकती है।
- **`sh`**:
- इसमें `bash` के `-p` के समान कोई mechanism नहीं है।
- `-i` option के अंतर्गत user IDs के behavior का स्पष्ट उल्लेख नहीं है, सिवाय इसके कि `euid` और `ruid` की equality बनाए रखने पर जोर दिया गया है।
- अतिरिक्त जानकारी [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) में उपलब्ध है।

ये mechanisms अपने operation में अलग होते हुए, programs को execute करने और उनके बीच transition करने के लिए options की एक versatile range प्रदान करते हैं, जिसमें user IDs के management और preservation के तरीके में विशेष nuances होते हैं।

### Testing User ID Behaviors in Executions

Examples https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail से लिए गए हैं; आगे की जानकारी के लिए इसे देखें।

#### Case 1: Using `setuid` with `system`

**Objective**: `setuid` को `system` और `bash` को `sh` के रूप में उपयोग करने के साथ समझना।

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**Compilation और Permissions:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- `ruid` और `euid` क्रमशः 99 (nobody) और 1000 (frank) से शुरू होते हैं।
- `setuid` दोनों को 1000 पर सेट करता है।
- `system`, sh से bash की symlink के कारण `/bin/bash -c id` execute करता है।
- `bash`, `-p` के बिना, `euid` को `ruid` से match करने के लिए adjust करता है, जिसके परिणामस्वरूप दोनों 99 (nobody) हो जाते हैं।

#### Case 2: setreuid के साथ system का उपयोग

**C Code**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**Compilation और अनुमतियाँ:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Analysis:**

- `setreuid` ruid और euid दोनों को 1000 पर सेट करता है।
- `system` bash को invoke करता है, जो उनकी समानता के कारण user IDs को बनाए रखता है और प्रभावी रूप से frank के रूप में काम करता है।

#### Case 3: setuid और execve का उपयोग

Objective: setuid और execve के बीच interaction का अध्ययन।
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- `ruid` 99 ही रहता है, लेकिन euid को 1000 पर सेट किया जाता है, जो setuid के प्रभाव के अनुरूप है।

**C Code Example 2 (Calling Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- हालांकि `setuid` द्वारा `euid` को 1000 पर सेट किया जाता है, `-p` के अभाव के कारण `bash` `euid` को `ruid` (99) पर रीसेट कर देता है।

**C Code Example 3 (bash -p का उपयोग):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## References

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}

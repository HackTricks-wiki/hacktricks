# macOS xattr-acls extra stuff

```markdown
# macOS xattr-acls 追加情報

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```

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

<summary>get_aclsのコード</summary>

\`\`\`c // gcc -o get\_acls get\_acls #include #include #include

int main(int argc, char \*argv\[]) { if (argc != 2) { fprintf(stderr, "Usage: %s \n", argv\[0]); return 1; }

const char \*filepath = argv\[1]; acl\_t acl = acl\_get\_file(filepath, ACL\_TYPE\_EXTENDED); if (acl == NULL) { perror("acl\_get\_file"); return 1; }

char \*acl\_text = acl\_to\_text(acl, NULL); if (acl\_text == NULL) { perror("acl\_to\_text"); acl\_free(acl); return 1; }

printf("ACL for %s:\n%s\n", filepath, acl\_text);

// Convert acl\_text to hexadecimal and print it printf("ACL in hex: "); for (char \*c = acl\_text; \*c != '\0'; c++) { printf("\x%02x", (unsigned char)\*c); } printf("\n");

acl\_free(acl); acl\_free(acl\_text); return 0; }

````
Since you haven't provided any English text to translate, I'm unable to proceed with the translation. Please provide the specific English content from the file you mentioned, and I'll be happy to translate it into Japanese for you.
```bash
# Lets add the xattr com.apple.xxx.xxxx with the acls
mkdir start
mkdir start/protected
./set_xattr start/protected
echo something > start/protected/something
````



</details>

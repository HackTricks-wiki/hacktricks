# macOS FS Tricks

{{#include ../../../../banners/hacktricks-training.md}}

## POSIX permissions combinations

**ディレクトリ**では、3つの permission bit は通常ファイルの場合とは異なる意味を持ちます。`chmod(1)` は、ディレクトリに適用された場合、execute bit を「**search**」と呼びます:<sup>[[2]](#references)</sup>

> `0100` ファイルでは、owner に実行を許可する。ディレクトリでは、owner にディレクトリ内の **search** を許可する。

- **read** - ディレクトリのエントリを列挙（名前を一覧表示）できます。
- **write** - ディレクトリ内のエントリを **作成、名前変更、削除** できます。これはファイルではなく、*親* ディレクトリの属性であることに注意してください。親ディレクトリに write できれば、読み取りや書き込みができないファイルでも削除できます。
  - **サブディレクトリ**を削除するには空にする必要があり、そのためには中身をすべて削除できるだけの権限が必要です。
  - ディレクトリに **sticky bit**（`S_ISVTX`、`/tmp` など）が設定されている場合、これは制限されます。POSIX では、プロセスがその中のファイルを削除または名前変更できるのは、そのファイルまたはディレクトリの所有者であるか、適切な権限を持つ場合に限られると規定されています。<sup>[[1]](#references)</sup>
- **execute / search** - ディレクトリを **たどる** ことができます。パス名の解決では、各コンポーネントは「その前のコンポーネントで指定されたディレクトリ内」にあるものとして特定されます。そのため、パスの prefix にあるいずれか1つのコンポーネントで search 権限を失うと、末尾のファイルが全ユーザーに読み取り可能でも、その下のすべてにパス経由でアクセスできなくなります。<sup>[[1]](#references)</sup>

### Dangerous Combinations

**root が所有するファイル／フォルダを上書きする方法**:

- パス内の親 **ディレクトリの所有者**の1人がユーザーである
- パス内の親 **ディレクトリの所有者**の1人が、**write access** を持つ **users group** である
- users **group** が **ファイル**への **write** access を持つ

上記のいずれかの組み合わせでは、攻撃者は想定されるパスに **sym/hard link** を **inject** し、特権付きの任意書き込みを実行できます。

### Folder root R+X special case

これは、前述のパス名解決ルールから直接導かれます。**ディレクトリが root にのみ R+X を許可**している場合、他のユーザーはその中のファイルに *パス経由で*アクセスできません。ただし、**ファイル自体の permission bit は緩いまま**である可能性があります。妨げになっているのはディレクトリだけです。

したがって、ファイルをその **ディレクトリの外に出す**プリミティブ、つまり、攻撃者が選んだパスを、たどることのできる場所へ **移動／名前変更／コピー**する特権プロセスがあれば、ファイル自体の mode を突破することなく、任意読み取りが可能になります:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

特権プロセスが、低い権限のユーザーからソースパスを受け取るファイル移動処理（インストーラー、ログローテーター、クラッシュ／診断情報の収集ツール、バックアップや「エクスポート」機能）を探します。

## Symbolic Link / Hard Link

### 書き込み可能なファイル／フォルダー

特権プロセスが、低い権限のユーザーに**制御されている**、または低い権限のユーザーが**事前に作成した**可能性のある**ファイル**にデータを書き込む場合、ユーザーはそのファイルをシンボリックリンクまたはハードリンクで別のファイルに**向ける**だけで、特権プロセスにそのファイルへの書き込みを行わせることができます。

攻撃者が任意の書き込みを**悪用して権限昇格**できる可能性については、ほかのセクションも確認してください。

### `O_NOFOLLOW` を指定した `open`

[`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html) によると、*「マスクに `O_NOFOLLOW` が指定されていて、`open()` に渡された対象ファイルがシンボリックリンクの場合、`open()` は失敗する」*。チェックされるのは**最後の**要素だけです。**中間の**要素はすべて引き続き解決され、たどられます。そのため、`O_NOFOLLOW` で書き込みを「保護」した開発者に対しても、対象パスの**親ディレクトリ**のいずれかにシンボリックリンクを仕掛けることで攻撃できます。<sup>[[3]](#references)</sup>

同じ man page には、この抜け穴を実際に塞ぐフラグが記載されています。<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *「`open()` に渡されたパスのいずれかの要素がシンボリックリンクの場合、`open()` は失敗する」*
- **`O_RESOLVE_BENEATH`** — *「指定したパスの解決先が fd に関連付けられたディレクトリの外に出る場合、`openat()` は失敗する」*

それ以外では、検証済みのディレクトリ FD を基準にした `openat()`、または `realpath()` と再検証が、パスの途中でのシンボリックリンク差し替えを防ぐ方法として残されています。

## .fileloc

**`.fileloc`** 拡張子のファイルは、ほかのアプリケーションやバイナリを指すことができます。そのため、そのファイルを開くと、指定先のアプリケーション／バイナリが実行されます。\
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

`open` の呼び出しにフラグ `O_CLOEXEC` が指定されていない場合、ファイルディスクリプタは子プロセスに継承されます。そのため、特権プロセスが特権ファイルを開いて、攻撃者が制御するプロセスを実行すると、攻撃者は**特権ファイルの FD を継承**します。

代表的な例は、**OS X 10.10 の `DYLD_PRINT_TO_FILE` LPE**です（[SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html）:<sup>[[4]](#references)</sup>

- `dyld` は、特定の変数が `processDyldEnvironmentVariable()` の外で解析されていたため、**制限付き（suid root）バイナリ**でも `DYLD_PRINT_TO_FILE=/path` を受け入れました。
- `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)` を実行したため、**任意のパスに root 所有のファイルを作成**しました。
- FD は**閉じられることがなく、close-on-exec フラグも設定されていなかった**ため、suid バイナリのすべての子プロセスが、root 所有ファイルへの**書き込み可能な FD**を継承しました。
- たとえば `DYLD_PRINT_TO_FILE=/etc/target suid_binary` を実行し、子プロセスで継承した FD 番号を読み取ると、root 所有ファイルへの任意の書き込みが可能でした。`fcntl(fd, F_SETFL, 0)` を使えば `O_APPEND` も解除でき、追記ではなく上書きできました。

同様の問題は、特権プロセスが、制御下にあるものを `exec` する**前に**ファイルを開く場合（ヘルパーツール、`$EDITOR` 経由で起動する `crontab` 形式のエディタ、環境変数で指定されたパスから開くログ／デバッグファイルなど）に発生します。継承した FD は、次の方法で列挙できます。

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

`2` より大きく、自分では開けないファイルを指すものは、任意書き込み（または任意読み取り）プリミティブです。

## quarantine xattrs の小技を避ける

### 削除する

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### uchg / uchange / uimmutable フラグ

ファイルやフォルダにこの immutable 属性が設定されている場合、xattr を付与できません。

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### xattr をサポートしないファイルシステム

macOS がマウントできるファイルシステムのすべてが、**extended attributes** をネイティブに保存できるわけではありません。HFS+ と APFS は対応していますが、**FAT32、exFAT、および（ほとんどの）NFS マウントは対応していません**。macOS は `._<filename>` という名前の **AppleDouble** サイドファイルを書き込んで、これらをエミュレートします（[The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)）。<sup>[[5]](#references)</sup>

quarantine ではこれが重要です。xattr が保持されるのは、同じボリュームに実際に書き込めて、そこから**読み戻せる**場合に限られるためです。

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

ボリュームが後で `._` の companion を無視するパスから読み込まれた場合（または companion が除去・削除された場合）、ファイルは**quarantine flag が付いていない状態で**到着します。quarantine が付いていない `.app` であれば、[macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute) で解説したように、App Sandbox から脱出するには十分です。

### writeextattr ACL と AppleDouble quarantine の動作

`writeextattr` ACL の例、`com.apple.acl.text` AppleDouble の仕組み、サイドカーの作成と検証の手順については、[AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md) を参照してください。

## 署名チェックのバイパス

### platform binaries チェックのバイパス

一部のセキュリティチェックでは、たとえば XPC service への接続を許可するため、バイナリが**platform binary**かどうかを確認します。しかし、https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/ で紹介されているバイパスの1つのように、platform binary（`/bin/ls` など）を取得し、環境変数 `DYLD_INSERT_LIBRARIES` を使って dyld 経由で exploit を注入することで、このチェックをバイパスできます。<sup>[[7]](#references)</sup>

### `CS_REQUIRE_LV` と `CS_FORCED_LV` フラグのバイパス

次のようなコードで、実行中のバイナリが自身のフラグを変更し、チェックをバイパスできます。<sup>[[7]](#references)</sup>

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



## コード署名のバイパス

Bundleには **`_CodeSignature/CodeResources`** ファイルが含まれており、これは **bundle** 内のすべての **file** の **hash** を保持しています。CodeResourcesのhashも **executable** に埋め込まれているため、これも変更できない点に注意してください。

ただし、署名がチェックされないファイルもあります。これらはplist内の`omit`キーで指定されています。たとえば:

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

CLIからリソースの署名を計算できます:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## dmgをマウントする

ユーザーは、既存のフォルダの上にも、独自に作成したdmgをマウントできます。以下は、独自のコンテンツを含むカスタムdmgパッケージを作成する方法です。

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

通常、macOS は `/usr/libexec/diskarbitrationd` が提供する Mach サービス `com.apple.DiskArbitrarion.diskarbitrariond` に接続してディスクをマウントします。LaunchDaemons の plist ファイルにパラメータ `-d` を追加して再起動すると、ログが `/var/log/diskarbitrationd.log` に保存されます。\
ただし、`hdik` や `hdiutil` などのツールを使って、`com.apple.driver.DiskImages` kext と直接通信することも可能です。

## 任意書き込み

### 定期実行される sh スクリプト

スクリプトが **shell script** として解釈されるのであれば、毎日実行される **`/etc/periodic/daily/999.local`** shell script を上書きできます。

次のコマンドで、このスクリプトの実行を**偽装**できます: **`sudo periodic daily`**

### デーモン

任意のスクリプトを実行する plist を使って、**`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** のような任意の **LaunchDaemon** を書き込みます。たとえば:

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

Just generate the script `/Applications/Scripts/privesc.sh` with the **commands** you would like to run as root.

### Sudoers File

**arbitrary write** が可能であれば、**`/etc/sudoers.d/`** 内にファイルを作成し、自分に **sudo** 権限を付与できます。

### PATH files

**`/etc/paths`** は、PATH 環境変数の設定に使われる主な場所の1つです。上書きには root 権限が必要ですが、**privileged process** のスクリプトが**フルパスを指定せずに**コマンドを実行している場合、このファイルを変更してコマンドを**hijack**できる可能性があります。

**`/etc/paths.d`** にファイルを書き込み、PATH 環境変数に新しいフォルダを追加することもできます。

### cups-files.conf

このテクニックは[こちらのwriteup](https://www.kandji.io/blog/macos-audit-story-part1)で使用されました。<sup>[[8]](#references)</sup>

次の内容でファイル `/etc/cups/cups-files.conf` を作成します：

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

これにより、パーミッションが777のファイル `/etc/sudoers.d/lpe` が作成されます。末尾の余計な文字列は、エラーログを作成させるためのものです。

次に、権限昇格に必要な設定（`%staff ALL=(ALL) NOPASSWD:ALL` など）を `/etc/sudoers.d/lpe` に書き込みます。

その後、`/etc/cups/cups-files.conf` を再度変更して `LogFilePerm 700` を指定し、`cupsctl` を実行して新しい sudoers ファイルを有効にします。

### Sandbox Escape

FS arbitrary write を使えば、macOS sandbox から脱出できます。例については [macOS Auto Start](../../../../macos-auto-start-locations.md) を参照してください。よくある方法の1つは、起動時にコマンドを実行する Terminal の設定ファイルを `~/Library/Preferences/com.apple.Terminal.plist` に書き込み、`open` を使って呼び出すことです。

## 他のユーザーとして書き込み可能なファイルを生成する

非常によく使われる privesc primitive は、**特権プロセスに、自分が制御するディレクトリ内でファイルを作成させ**、そのファイルへの**書き込み権限**を維持することです。必要な要素は2つあります。

1. 自分が所有するディレクトリ（または**継承可能な ACL**を設定できるディレクトリ）。これにより、内部に作成されたファイルは自分の権限を継承します。
2. ファイルの作成場所を指定できる特権付きのプロセスまたは `/suid` プロセス。通常は、デバッグ用またはログ用の環境変数、設定ファイル、あるいはヘルパーの XPC API を通じて指定します。

**継承可能な ACL** によって、作成されたファイルの所有者が別のユーザーでも、自分がそのファイルに書き込めるようになります。`file_inherit` / `directory_inherit` 継承フラグについては、[`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html) に記載されています。<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

これで、特権プロセスが `$DIRNAME` 内に作成するファイルはすべて**あなたが書き込み可能**になります。そのディレクトリが後で**rootとして実行される**場所（`/etc/periodic/*`、`/etc/cron.d`、`/etc/sudoers.d`、LaunchDaemonのディレクトリなど）でもある場合、これは直接的なroot権限昇格につながります。ファイルを取得した後に何を書き込むかについては、上記の [Sudoers File](#sudoers-file) セクションと [cups-files.conf](#cups-filesconf) セクションを参照してください。

「環境変数によってrootプロセスにファイルを作成させ、そのFDがあなたに漏れる」一連の流れを示す完全な実例は、上記の [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) を参照してください。

## POSIX共有メモリ

**POSIX共有メモリ**を使うと、POSIX準拠のオペレーティングシステム上のプロセス間で共通のメモリ領域にアクセスでき、他のプロセス間通信方式より高速な通信が可能になります。`shm_open()` で共有メモリオブジェクトを作成または開き、`ftruncate()` でサイズを設定した後、`mmap()` を使ってプロセスのアドレス空間にマッピングします。これにより、プロセスはこのメモリ領域を直接読み書きできます。並行アクセスを管理し、データの破損を防ぐために、mutexやセマフォなどの同期機構がよく使われます。最後に、プロセスは `munmap()` と `close()` で共有メモリのマッピングを解除して閉じ、必要に応じて `shm_unlink()` でメモリオブジェクトを削除します。この方式は、複数のプロセスが共有データにすばやくアクセスする必要がある環境で、効率的かつ高速なIPCを実現するのに特に有効です。

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

**macOSCguarded descriptors**は、ユーザーアプリケーションにおける**file descriptor operations**の安全性と信頼性を高めるため、macOSで導入されたセキュリティ機能です。guarded descriptorsを使うと、file descriptorに特定の制限、つまり「guard」を設定でき、カーネルによって適用されます。

この機能は、**不正なファイルアクセス**や**race condition**など、特定の種類のセキュリティ脆弱性を防ぐのに特に役立ちます。たとえば、あるスレッドがファイルを操作しているときに、**別の脆弱なスレッドがそのファイルにアクセスできる状態になる**場合や、file descriptorが脆弱な子プロセスに**継承される**場合に、こうした脆弱性が発生します。この機能に関連する関数には、次のものがあります。

- `guarded_open_np`: guard付きでfile descriptorを開く
- `guarded_close_np`: file descriptorを閉じる
- `change_fdguard_np`: descriptorのguardフラグを変更する（guardによる保護の解除も可能）

## References

- [1] [POSIX.1-2024 — Base Definitions, Ch. 4 (File Access Permissions, Directory Protection, Pathname Resolution)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` man page](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` man page](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - OS X 10.10 DYLD_PRINT_TO_FILE Local Privilege Escalation](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Which file systems and cloud services preserve extended attributes?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - A New Era of macOS Sandbox Escapes](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Uncovering Apple Vulnerabilities: The diskarbitrationd and storagekitd Audit Story Part 1](https://www.kandji.io/blog/macos-audit-story-part1)

{{#include ../../../../banners/hacktricks-training.md}}

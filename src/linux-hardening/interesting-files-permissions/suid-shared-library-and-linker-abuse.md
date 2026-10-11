# SUID共有ライブラリとリンカーの悪用

{{#include ../../banners/hacktricks-training.md}}

SUIDバイナリは通常、直接的なコマンド実行について調査されますが、カスタムSUIDプログラムは動的リンカーを通じて脆弱になることもあります。共通する仕組みは単純です。特権実行ファイルが、低い権限のユーザーが影響を与えられるパスや設定からコードを読み込みます。<sup>[[1]](#references)</sup>

このページでは、一般的な手法パターンとして、ライブラリの欠落、書き込み可能なライブラリディレクトリ、`RPATH`/`RUNPATH`、sudo 経由の `LD_PRELOAD`、リンカー設定、SUIDハードリンクの誤認を扱います。

これらの確認の背景にあるELFプログラムヘッダー、動的セクション、ローダーの動作については、[ELFの基本情報](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)を参照してください。

## 迅速な列挙

まず、通常とは異なるSUIDファイルを見つけ、動的リンクされているかを確認します。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

不明な実行ファイルには `readelf` を使ってください。[`ldd` は信頼できない ELF interpreter を実行する可能性があります](https://man7.org/linux/man-pages/man1/ldd.1.html)。`readelf` で直接の依存関係を確認し、実際に loader が選択するパスは別途確認してください。<sup>[[1]](#references)[[3]](#references)</sup>

標準外の場所、カスタムアプリケーションのパス、パッケージ管理対象のディレクトリ外にある root 所有のバイナリ、書き込み可能なディレクトリから読み込まれる依存関係に注目してください。<sup>[[1]](#references)</sup>

書き込み可能性の確認に便利なコマンド：

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

一部のカスタム SUID バイナリは、存在しない shared object をロードしようとします。そのパスが攻撃者の制御下にあるディレクトリ内にある場合、バイナリが攻撃者の用意したコードを実効ユーザーとしてロードする可能性があります。<sup>[[1]](#references)</sup>

同じ境界の問題は、**sudo での実行が許可されたカスタムバイナリ**が、呼び出し元が書き込み可能なホームディレクトリや設定ディレクトリ内の絶対 `.so` パスを `dlopen()` で読み込む場合にも当てはまります。この遅延ライブラリ読み込みは、`ldd` の出力や ELF の `NEEDED` エントリに現れないことがあります。範囲を限定した `strings` による確認や、**非特権ユーザー**による実行のトレースで、読み込みを試みるパスを特定できます。アプリケーションのパスワードやメニューの選択が、この検索処理の実行条件になっている場合もあります。エスカレーションと判断する前に、sudo ルール、正確なパスと親ディレクトリの権限、そして特権実行時にその検索処理へ到達することを確認してください。対象を列挙するだけの目的で sudo から実行してはいけません。

`strace` のシステムコールフィルターを使って、ライブラリ読み込みの失敗を探します。<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

バイナリが writable なパスで `libexample.so` を検索する場合、最小限の proof library では constructor を使えます。検証中は影響の実証を無害なものにしてください:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

binaryが読み込もうとする正確なファイル名でビルドします:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

悪用可能な状態は、単にライブラリが欠落しているだけではありません。攻撃者が、特権ローダーが受け入れるパスに互換性のある共有オブジェクトを配置できる必要があります。<sup>[[1]](#references)</sup>

## 書き込み可能なライブラリディレクトリ

依存関係がすべて存在していても、依存関係の解決に使われるディレクトリのいずれかが書き込み可能な場合があります。これにより、読み込まれるライブラリを置き換えたり、同じ名前の優先順位が高いライブラリを配置したりできる可能性があります。<sup>[[1]](#references)</sup>

同じ確認は、**sudo 経由で許可された**カスタム ELF にも当てはまります。ELF に SUID bit がなく、許可された RunAs アカウントが root 以外の場合も同様です。`DT_NEEDED` エントリと、ローダーが解決するライブラリのパス名を照合し、呼び出し元がそのファイルに書き込めるか、または書き込み可能な親ディレクトリを通じて置き換えられるかを確認します。正確な sudo RunAs ルール、シンボリックリンクと ACL、ローダーのポリシー、および対象プロセスがより高い権限のアカウントとしてライブラリを読み込むことを確認してください。書き込み可能な `.so` や依存関係名だけでは手がかりにすぎません。sudo コマンドを実行せずにメタデータを調べてください。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

依存関係のパスを確認します。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

ディレクトリが書き込み可能な場合は、ラボでコピーを使った安全な方法で検証してください。稼働中のホストでシステムライブラリを置き換えると、同時に起動するプロセスが不整合なバージョンのライブラリを読み込む可能性があります。<sup>[[8]](#references)</sup>

### chroot 内の書き込み可能なライブラリ

chroot だけでは、継承されたファイルディスクリプターは閉じられず、ファイルシステムへのすべてのアクセスが制限されるわけでもありません。サンドボックスが新しいルートの外を指すディレクトリディスクリプターを残し、隔離されたプロセスがそのディスクリプターをたどれる場合（たとえば、アクセス可能な `/proc/<pid>/fd/` エントリーを介する場合）、ホストのパスに引き続きアクセスできる可能性があります。これはファイルシステム境界の問題であり、それ自体で root 権限が得られるわけではありません。<sup>[[11]](#references)[[12]](#references)</sup>

隔離されたユーザーが、jail から起動したときに**ホストの root-SUID 実行ファイル**が使用するライブラリディレクトリに書き込めるかどうかを、別途確認してください。loader はプロセスのファイルシステムビュー内で依存関係を解決するため、その場所にある攻撃者が制御するライブラリは、SUID プログラムの実効 ID で実行される可能性があります。対象の実行ファイル、その SUID ビットとマウントポリシー、ディスクリプターの参照先とアクセス権限、jail のライブラリ検索パス、およびプログラムが実際にホストの実行ファイルへ到達できることを確認してください。サンドボックスの起動プログラムに設定された file capability、書き込み可能な jail、またはホストの SUID バイナリだけでは、手がかりにすぎません。攻撃チェーン全体が成立するかは、サンドボックスの実装によります。<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` と `RUNPATH` は、ライブラリの検索場所を loader に伝える dynamic-section エントリーです。攻撃者が書き込み可能なディレクトリを指している場合、SUID プログラムでは危険です。<sup>[[1]](#references)</sup>

検出方法：<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

リスクのある出力例:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

`/opt/app/lib`が書き込み可能で、バイナリが`libcustom.so`を必要とする場合、攻撃者はそこに悪意のある`libcustom.so`を配置できる可能性があります:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` と `RUNPATH` は、すべての解決方法の詳細において同一ではありませんが、権限昇格の調査で実際に確認すべき点は同じです。SUID バイナリが、攻撃者が書き込み可能なディレクトリからライブラリ名を検索するかどうかです。<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

通常のプログラムでは、`LD_PRELOAD` と `LD_LIBRARY_PATH` によって、共有オブジェクトの読み込みを強制したり、影響を与えたりできます。SUID プログラムの場合、dynamic loader は通常、secure-execution モードに入り、危険な環境変数を無視します。<sup>[[1]](#references)</sup>

つまり、ユーザーが `LD_PRELOAD` を設定できるというだけで、通常の SUID バイナリが脆弱になるわけではありません。<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

一般的な例外は、`SETENV` tag や適用される `setenv` option など、対象コマンドへのコマンドライン環境変数の設定を許可する sudo policy です。対象が動的リンクされており、sudo が `LD_PRELOAD=/path/to/library` を受け入れる場合、対象が呼び出し元の制御下にあるコードをロードする可能性があります。有効な rule と対象の identity を確認してください。`env_keep` に `LD_PRELOAD` を追加するだけでは不十分です。システムによっては、SUID の `sudo` process が起動する前に、dynamic loader が継承された `LD_PRELOAD` を削除するためです。コマンドラインでの設定は、sudo 自身の起動後に sudo によって評価されます。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

これらのケースを混同しないでください。上記の loader と sudo policy のルールで区別できます:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 通常の SUID binary に対する `LD_PRELOAD`：通常、secure execution によってブロックされます。
- 特権を持つ動的リンクされたターゲットに対し、sudo のコマンドライン引数として指定された `LD_PRELOAD`：悪用できる可能性があります。
- 書き込み可能なパスにある `.so` の欠落：SUID binary がそのパスを自然に読み込む場合、悪用できます。
- 書き込み可能なディレクトリを指定する `RPATH`/`RUNPATH`：必要な library を制御できる場合、悪用できます。
- `/etc/ld.so.preload` または linker config への書き込みアクセス：システム全体に影響し、影響度が高いです。

## Linker Configuration

`ld.so` は linker cache と `/etc/ld.so.preload` を使用します。`ldconfig` は `/etc/ld.so.conf` と、そこから読み込まれるファイル（一般的には `/etc/ld.so.conf.d/` 内のファイル）をもとに、その cache を構築します。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

重要度の高い確認項目:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

書き込み可能なリンカー設定は、単一の脆弱なSUIDバイナリよりも通常深刻な問題です。動的リンクされた多数のプロセスに影響する可能性があるためです。特に`/etc/ld.so.preload`は、特権プロセスに共有オブジェクトを強制的に読み込ませることができるため、非常に危険です。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinkを使うと、同じSUID inodeを複数の名前で表示できます。<sup>[[9]](#references)</sup> これは、特権ヘルパーを隠したり、クリーンアップを混乱させたり、単純なパスベースの調査を回避したりするのに役立ちます。

リンク数が1より大きいSUIDファイルを検索します。<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

同じ inode へのすべてのパスを確認する:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

悪用の本質は、hardlink が権限を変更することではありません。問題はパスの混同です。特権付き inode が、防御担当者やスクリプトの想定しない名前からアクセス可能な場合があります。<sup>[[9]](#references)</sup> inode と hardlink の詳しい仕組みについては、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) を参照してください。

## Defensive Notes

- SUID バイナリは最小限に抑え、監査し、可能な限りパッケージで管理してください。
- 書き込み可能なディレクトリやアプリケーションが管理するディレクトリを指す `RPATH`/`RUNPATH` エントリは避けてください。<sup>[[1]](#references)[[8]](#references)</sup>
- ライブラリのディレクトリは root が所有し、一般ユーザーが書き込めないようにしてください。<sup>[[8]](#references)</sup>
- `LD_PRELOAD`、`LD_LIBRARY_PATH` などのローダー変数を sudo 経由で引き継がないでください。<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および予期しない SUID ファイルを監視してください。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlink された SUID ファイルを確認し、標準的なシステムパス以外にある独自の SUID ラッパーを調査してください。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU バイナリユーティリティ)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux マニュアルページ](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [共通属性 (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker のハードニング (GNU C ライブラリ)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [ハードリンク (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU バイナリユーティリティ)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}

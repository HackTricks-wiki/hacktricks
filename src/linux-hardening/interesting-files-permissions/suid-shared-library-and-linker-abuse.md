# SUID共有ライブラリとリンカーの悪用

{{#include ../../banners/hacktricks-training.md}}

SUIDバイナリは通常、直接的なコマンド実行について調査されますが、カスタムSUIDプログラムは動的リンカーを通じて脆弱になることもあります。共通する仕組みは単純です。特権実行ファイルが、権限の低いユーザーが影響を与えられるパスや設定からコードを読み込みます。<sup>[[1]](#references)</sup>

このページでは、汎用的な手法のパターンとして、ライブラリの欠落、書き込み可能なライブラリディレクトリ、`RPATH`/`RUNPATH`、sudo経由の`LD_PRELOAD`、リンカー設定、SUIDハードリンクの混同に焦点を当てます。

これらの確認の背景にあるELFプログラムヘッダー、動的セクション、ローダーの動作については、[ELF basic information](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md)を参照してください。

## すばやい列挙

まず、通常と異なるSUIDファイルを見つけ、動的リンクされているか確認します。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

見慣れない実行ファイルには `readelf` を使用してください。`ldd` は信頼できない ELF interpreter を実行する可能性があります（[こちら](https://man7.org/linux/man-pages/man1/ldd.1.html)）。`readelf` で直接依存関係を確認し、実際に loader が選択するパスは別途確認してください。<sup>[[1]](#references)[[3]](#references)</sup>

標準外の場所、カスタムアプリケーションのパス、パッケージ管理対象のディレクトリ外にある root 所有のバイナリ、書き込み可能なディレクトリからロードされる依存関係に注目してください。<sup>[[1]](#references)</sup>

書き込み可能性を確認する便利な方法：

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

カスタムSUIDバイナリの中には、存在しない共有オブジェクトを読み込もうとするものがあります。存在しないパスが攻撃者の制御下にあるディレクトリ内にある場合、そのバイナリは攻撃者が用意したコードを実効ユーザーとして読み込む可能性があります。<sup>[[1]](#references)</sup>

同じ境界は、**sudoでの実行が許可されたカスタムバイナリ**が、呼び出し元が書き込み可能なホームディレクトリや設定ディレクトリ内の絶対`.so`パスを指定して`dlopen()`を呼び出す場合にも当てはまります。このような実行時のライブラリ読み込みは、`ldd`やELFの`NEEDED`エントリには現れないことがあります。`strings`で範囲を絞って調べるか、**権限のない状態で**実行をトレースすれば、読み込みを試みるパスが判明することがあります。アプリケーションのパスワードやメニューの選択が、この検索の条件になっている場合もあります。昇格と判断する前に、sudoルールの実効性、正確なパスと親ディレクトリの権限、そして特権付きの実行がその検索処理に到達することを確認してください。対象を列挙するだけの目的でsudo実行しないでください。

`strace`のシステムコールフィルターを使って、ライブラリ読み込みの失敗を見つけます:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

バイナリが書き込み可能なパスから `libexample.so` を検索する場合、最小限の実証用ライブラリでは constructor を使用できます。検証中は、影響の実証を無害なものにしてください:<sup>[[6]](#references)</sup>

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

バイナリが読み込もうとするファイル名と完全に同じ名前でビルドします:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

悪用可能な条件は、単にライブラリが欠落していることではありません。攻撃者が、特権ローダーに受け入れられるパスに互換性のある共有オブジェクトを配置できる必要があります。<sup>[[1]](#references)</sup>

## 書き込み可能なライブラリディレクトリ

依存関係がすべて存在していても、それらの解決に使われるディレクトリのいずれかが書き込み可能な場合があります。これにより、読み込み済みのライブラリを置き換えたり、同じ名前の優先度が高いライブラリを配置したりできる可能性があります。<sup>[[1]](#references)</sup>

同じ確認は、**sudoで許可された**カスタムELFにも適用されます。ELFにSUIDビットがなく、許可されたRunAsアカウントがrootでない場合も同様です。`DT_NEEDED`エントリと、ローダーが解決するライブラリのパス名を照合し、呼び出し元がそのファイルに書き込めるか、または書き込み可能な検索可能ディレクトリを親に持つことで置き換えられるかを確認してください。正確なsudo RunAsルール、シンボリックリンクとACL、ローダーポリシー、および対象プロセスがより高い権限のアカウントでライブラリを読み込むことも確認してください。書き込み可能な`.so`や依存関係名だけでは手掛かりにすぎません。sudoコマンドを実行せずにメタデータを調べてください。<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

依存関係のパスを確認してください。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

ディレクトリが書き込み可能なら、ラボでコピーを使った安全な方法で検証してください。稼働中のホストでシステムライブラリを置き換えると、同時に起動するプロセスが異なるバージョンのライブラリを読み込む状態になり得ます。<sup>[[8]](#references)</sup>

### chroot 内の書き込み可能なライブラリ

chroot だけでは、継承されたファイルディスクリプタは閉じられず、すべてのファイルシステムアクセスが制限されるわけでもありません。サンドボックスが新しいルート外を指すディレクトリディスクリプタを残しており、隔離されたプロセスがそのディスクリプタを参照できる場合（たとえば、アクセス可能な `/proc/<pid>/fd/` エントリを通じて）、ホストのパスに到達できる可能性があります。これはファイルシステム境界の問題であり、それだけで root 権限が得られるわけではありません。<sup>[[11]](#references)[[12]](#references)</sup>

隔離されたユーザーが、jail から起動されたときに**ホストの root-SUID 実行ファイル**が使用するライブラリディレクトリに書き込めるかどうかも、別途確認してください。loader はプロセスのファイルシステムビュー内で依存関係を解決するため、その場所にある攻撃者が制御するライブラリが、SUID プログラムの実効 ID で実行される可能性があります。対象の実行ファイル、その SUID ビットとマウントポリシー、ディスクリプタの指す先とアクセス権限、jail のライブラリ検索パス、そしてプログラムが実際にホストの実行ファイルに到達できることを確認してください。サンドボックス起動プログラムの file capability、書き込み可能な jail、またはホストの SUID バイナリが単独で見つかっただけなら、それは手掛かりにすぎません。完全な攻撃経路が成立するかどうかは、サンドボックスの実装に左右されます。<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH and RUNPATH

`RPATH` と `RUNPATH` は、loader にライブラリの検索場所を指定する dynamic-section のエントリです。攻撃者が書き込み可能なディレクトリを指している場合、SUID プログラムでは危険です。<sup>[[1]](#references)</sup>

検出方法:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

危険な出力例：

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

`/opt/app/lib` が書き込み可能で、バイナリが `libcustom.so` を必要とする場合、攻撃者はそこに悪意のある `libcustom.so` を配置できる可能性があります。<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` と `RUNPATH` はすべての解決処理において同一ではありませんが、権限昇格の観点で実際に確認すべきことは同じです。SUID バイナリが、ライブラリ名を検索する際に攻撃者が書き込み可能なディレクトリを検索するかどうかです。<sup>[[1]](#references)</sup>

## LD_PRELOAD、LD_LIBRARY_PATH と SUID

通常のプログラムでは、`LD_PRELOAD` と `LD_LIBRARY_PATH` を使って共有オブジェクトの読み込みを強制または制御できます。SUID プログラムでは、通常、動的ローダーがセキュア実行モードに入り、危険な環境変数を無視します。<sup>[[1]](#references)</sup>

つまり、ユーザーが `LD_PRELOAD` を設定できるというだけで、通常の SUID バイナリに脆弱性があるとは限りません。<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

一般的な例外は、`SETENV` タグや該当する `setenv` オプションなどにより、対象コマンドへのコマンドライン環境変数の設定を許可する sudo ポリシーです。対象が動的リンクされており、sudo が `LD_PRELOAD=/path/to/library` を受け入れる場合、対象は呼び出し元が制御するコードを読み込む可能性があります。有効なルールと対象の実行ユーザーを確認してください。`env_keep` に `LD_PRELOAD` を追加するだけでは不十分です。動的ローダーが SUID の `sudo` プロセスの起動前に継承した `LD_PRELOAD` を削除するシステムでは、コマンドラインで指定した値は sudo 自体の起動後に評価されます。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

これらのケースを混同しないでください。上記のloaderとsudo policy rulesで区別されています:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 通常のSUID binaryに対する`LD_PRELOAD`: 通常、secure executionによってブロックされます。
- 特権付きの動的リンクされたtargetに対するsudoのコマンドライン代入として受け入れられる`LD_PRELOAD`: 悪用できる可能性があります。
- 書き込み可能なパスにある不足した`.so`: SUID binaryがそのパスを自然に読み込む場合、悪用できます。
- 書き込み可能なディレクトリを指定する`RPATH`/`RUNPATH`: 必要なlibraryを制御できる場合、悪用できます。
- `/etc/ld.so.preload`またはlinker configへの書き込みアクセス: システム全体に影響し、影響度が高いです。

## Linker Configuration

`ld.so`はlinker cacheと`/etc/ld.so.preload`を使用します。`ldconfig`は`/etc/ld.so.conf`およびそこから読み込まれるファイル（通常は`/etc/ld.so.conf.d/`内のファイル）を基にcacheを構築します。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

重要度の高い確認項目:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

書き込み可能なlinker設定は、単一の脆弱なSUIDバイナリより深刻な場合がほとんどです。多くの動的リンクされたプロセスに影響を与える可能性があるためです。特に`/etc/ld.so.preload`は、共有オブジェクトを特権プロセスに強制的に読み込ませることができるため、非常に危険です。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlinkによる混乱

Hardlinkを使うと、同じSUID inodeを複数の名前で参照できます。<sup>[[9]](#references)</sup> これは、特権ヘルパーを隠したり、クリーンアップを混乱させたり、単純なパスベースの確認を回避したりするのに役立ちます。

リンク数が2以上のSUIDファイルを探します。<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

同一 inode へのすべてのパスを調査します:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

悪用の本質は、hardlinkによって権限が変わることではありません。問題はパスの混同です。特権を持つinodeが、防御側やスクリプトが想定していない名前からアクセス可能になることがあります。<sup>[[9]](#references)</sup> inodeとhardlinkの詳しい仕組みについては、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md)を参照してください。

## 防御上の注意点

- SUIDバイナリは最小限にし、監査を行い、可能な場合はパッケージ管理下に置いてください。
- 書き込み可能なディレクトリやアプリケーション管理下のディレクトリを指す`RPATH`/`RUNPATH`エントリは避けてください。<sup>[[1]](#references)[[8]](#references)</sup>
- ライブラリディレクトリはroot所有とし、一般ユーザーが書き込めないようにしてください。<sup>[[8]](#references)</sup>
- sudo経由で`LD_PRELOAD`、`LD_LIBRARY_PATH`などのローダー変数を引き継がないでください。<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および予期しないSUIDファイルを監視してください。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlinkされたSUIDファイルを確認し、標準的なシステムパス以外にある独自のSUIDラッパーを調査してください。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linuxマニュアルページ](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}

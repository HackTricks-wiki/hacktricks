# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linuxは通常、ディスクまたはメモリ上に保存された実行可能ファイルからプログラムを実行します。実行可能ファイルはパス名またはファイルディスクリプタで識別できるため、通常のファイルシステム上のパス名が常に必要とは限りません。<sup>[[2]](#references)</sup>

DDexec / EverythingExecは、**すでに実行中のプロセス**のメモリを利用します。[Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md)ページでは、匿名ファイルからの実行、および関連する検出とフォレンジック収集について説明しています。[Memory Bypasses overview](index.html#memory-bypasses)からは、MemExecとMemdlopenについても参照できます。<sup>[[1]](#references)</sup>

この手法を使うと、**読み取り専用、noexec、ファイル名のホワイトリスト、ハッシュのホワイトリストなど、一般的な保護手法をバイパス**できます。<sup>[[1]](#references)</sup>

## Dependencies

最終的なスクリプトを動作させるには、以下のツールが必要です。これらは攻撃対象のシステムから利用できる必要があります（通常、どの環境にもすべて揃っています）。

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## この手法

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは、既存のプロセスをハイジャックして別のプログラムに置き換えるために利用できます。これを実現する方法は、`ptrace()` syscall（syscallを実行できるか、システム上でgdbを利用できる必要があります）を使う方法と、より興味深い方法として、`/proc/$pid/mem` に書き込む方法があります。<sup>[[1]](#references)</sup>

`/proc/$pid/mem` ファイルは、プロセスのアドレス空間全体（_例：_ x86-64では `0x0000000000000000` から `0x7ffffffffffff000` まで）を1対1でマッピングしたものです。つまり、このファイルのオフセット `x` を読み書きすると、仮想アドレス `x` の内容を読み取る、または変更するのと同じです。

ここで、対処すべき基本的な問題が4つあります。

- 一般に、このファイルを変更できるのはrootとファイルの所有者であるプログラムだけです。
- ASLR。
- プログラムのアドレス空間にマッピングされていないアドレスを読み書きしようとすると、I/Oエラーが発生します。

これらの問題には、完璧ではないものの有効な解決策があります。

- ほとんどのシェルインタプリタでは、子プロセスに引き継がれるファイルディスクリプタを作成できます。書き込み権限でシェルの `mem` ファイルを指すfdを作成すれば、そのfdを使う子プロセスからシェルのメモリを変更できます。
- ASLRは問題にすらなりません。シェルの `maps` ファイルやprocfs内の他のファイルを確認すれば、プロセスのアドレス空間に関する情報を得られます。
- そのため、ファイル上で `lseek()` を実行する必要があります。シェルからこれを行うには、悪名高い `dd` を使うしかありません。

### 詳細

手順は比較的簡単で、理解するのに特別な専門知識は必要ありません。<sup>[[1]](#references)</sup>

- 実行したいバイナリとloaderを解析し、必要なマッピングを特定します。次に、概ね、`execve()` が呼び出されるたびにkernelが行う処理と同じことを実行する「shell」codeを作成します。
  - 必要なマッピングを作成する。
  - バイナリをそれらのマッピングに読み込む。
  - 権限を設定する。
  - 最後に、プログラムの引数を使ってstackを初期化し、auxiliary vector（loaderが必要とするもの）を配置する。
  - loaderにジャンプし、残りの処理（プログラムに必要なlibraryの読み込み）を任せる。
- `syscall` ファイルから、実行中のsyscallの後にプロセスが戻るアドレスを取得します。
- その場所は実行可能なので、そこをshellcodeで上書きします（`mem` を通じて、書き込み不可のページも変更できます）。
- 実行したいプログラムをプロセスのstdinに渡します（その「shell」codeが `read()` で読み込みます）。
- ここからはloaderが、プログラムに必要なlibraryを読み込み、プログラムにジャンプします。

**ツールは** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)**を参照してください。**<sup>[[1]](#references)</sup>

## EverythingExec

`dd` にはいくつかの代替手段があり、そのうちの1つである `tail` は現在、`mem` ファイル上で `lseek()` を実行するための標準プログラムとして使われています（これが `dd` を使う唯一の目的でした）。代替手段は以下のとおりです。<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

`SEEKER` 変数を設定すると、使用するseekerを変更できます。_たとえば_:

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

スクリプトに実装されていない別の有効な seeker を見つけた場合でも、`SEEKER_ARGS` 変数を設定すれば使用できます。

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

これをブロックしろ、EDR。

## References

- [1] [DDexec: Linux上でバイナリをファイルレスかつステルスに実行する手法](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux マニュアルページ](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}

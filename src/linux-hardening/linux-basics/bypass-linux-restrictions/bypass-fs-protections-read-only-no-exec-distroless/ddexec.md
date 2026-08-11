# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linuxでプログラムを実行するには、それがファイルとして存在し、ファイルシステム階層を通じて何らかの方法でアクセス可能でなければなりません（これは単に`execve()`の動作です）。このファイルはディスク上またはram（tmpfs、memfd）上に存在できますが、ファイルパスが必要です。この仕組みにより、Linuxシステム上で何が実行されるかを制御することが非常に容易になり、脅威や攻撃者のツールを検出したり、攻撃者が自身のものを実行しようとするのを完全に防止したりできます（_例_：非特権ユーザーが実行可能ファイルをどこにでも配置することを許可しない）。

しかし、このtechniqueはこれらすべてを変えるために存在します。実行したいプロセスを開始できないなら、**すでに存在するプロセスを乗っ取る**のです。

このtechniqueにより、read-only、noexec、file-name whitelisting、hash whitelistingなどの一般的な保護techniqueを**bypassできます**。<sup>[[1]](#references)</sup>

## Dependencies

最終的なscriptは動作するために以下のtoolsに依存します。攻撃対象のsystemでそれらにアクセスできる必要があります（デフォルトでは、これらはどこにでも存在します）。
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
## この technique

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは、既存のプロセスを hijack し、別のプログラムに置き換えるために使用できます。これを実現するには、`ptrace()` syscall（syscall を実行する能力、またはシステム上で gdb を利用できることが必要）を使用する方法と、より興味深い方法として `/proc/$pid/mem` に書き込む方法があります。<sup>[[1]](#references)</sup>

`/proc/$pid/mem` ファイルは、プロセスのアドレス空間全体（_e. g._ x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）との one-to-one mapping です。つまり、このファイルのオフセット `x` から読み取ること、またはオフセット `x` に書き込むことは、仮想アドレス `x` の内容を読み取ること、または変更することと同じです。

ここで、対処すべき基本的な問題が4つあります。

- 一般的に、ファイルを変更できるのは root とファイルの所有者であるプログラムだけです。
- ASLR。
- プログラムのアドレス空間に map されていないアドレスを読み書きしようとすると、I/O エラーが発生します。

これらの問題には、完全ではないものの、十分に有効な解決策があります。

- ほとんどの shell interpreter では、子プロセスに継承される file descriptor を作成できます。write permissions を付けて shell の `mem` ファイルを指す fd を作成すれば、その fd を使用する子プロセスから shell のメモリを変更できるようになります。
- ASLR は問題にすらなりません。shell の `maps` ファイルや、procfs 内のその他のファイルを調べることで、プロセスのアドレス空間に関する情報を取得できます。
- そのため、ファイルに対して `lseek()` を実行する必要があります。shell からこれを行うには、悪名高い `dd` を使用するしかありません。

### 詳細

手順は比較的簡単で、理解するために特別な expertise は必要ありません。<sup>[[1]](#references)</sup>

- 実行したい binary と loader を解析し、それらが必要とする mapping を特定します。次に、概ね、`execve()` が呼び出されるたびに kernel が行うのと同じ手順を実行する "shell"code を作成します。
- それらの mapping を作成します。
- binary をそれらの mapping に読み込みます。
- permissions を設定します。
- 最後に、プログラムの引数で stack を初期化し、auxiliary vector（loader に必要）を配置します。
- loader に jump し、残りの処理（プログラムが必要とする libraries の load）を任せます。
- `syscall` ファイルから、実行中の syscall の後にプロセスが return するアドレスを取得します。
- その場所は executable なので、shellcode で上書きします（`mem` を通じて unwritable pages を変更できます）。
- 実行したいプログラムをプロセスの stdin に渡します（その "shell"code によって `read()` されます）。
- この時点で、プログラムに必要な libraries を load し、プログラムへ jump するのは loader の役割です。

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)。<sup>[[1]](#references)</sup>

## EverythingExec

`dd` にはいくつかの alternative があり、その1つである `tail` は現在、`mem` ファイルに対して `lseek()` を実行するために使用される default program です（これが `dd` を使用する唯一の目的でした）。これらの alternative は次のとおりです。<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
変数 `SEEKER` を設定すると、使用される seeker を変更できます。_例_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
スクリプトに実装されていない別の有効な seeker を見つけた場合でも、`SEEKER_ARGS` 変数を設定して使用できます：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
これをBlockしてください、EDR。

## References

- [1] [Linux上でバイナリをfilelessかつステルスに実行するtechnique](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}

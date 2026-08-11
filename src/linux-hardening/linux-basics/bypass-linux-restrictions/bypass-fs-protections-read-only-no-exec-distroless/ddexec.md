# DDexec / EverythingExec

## コンテキスト

Linuxでプログラムを実行するには、そのプログラムがファイルとして存在し、ファイルシステム階層を通じて何らかの方法でアクセス可能でなければなりません（これは単に`execve()`の仕組みによるものです）。このファイルはディスク上またはram（tmpfs、memfd）上に存在できますが、filepathが必要です。このため、Linuxシステム上で何が実行されるかを非常に簡単に制御でき、脅威や攻撃者のツールを容易に検出したり、攻撃者が自分のものを実行しようとすること自体を防止したりできます（_例_：unprivileged usersがどこにもexecutable filesを配置できないようにする）。

しかし、このtechniqueはこれらすべてを変えるためのものです。実行したいprocessを開始できないなら、**すでに存在するものをhijackする**のです。

このtechniqueにより、read-only、noexec、file-name whitelisting、hash whitelistingなどの**一般的なprotection techniquesをbypass**できます。<sup>[[1]](#references)</sup>

## Dependencies

最終的なscriptが動作するには、以下のtoolsに依存します。攻撃対象のsystem上でこれらにアクセスできる必要があります（デフォルトでは、どこでもこれらすべてを見つけられます）。
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
## The technique

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは、既存のプロセスを hijack し、別のプログラムに置き換えるために利用できます。これを実現するには、`ptrace()` syscall（syscall を実行する能力、またはシステム上で gdb を利用できることが必要）を使用する方法と、より興味深い方法として `/proc/$pid/mem` に書き込む方法があります。<sup>[[1]](#references)</sup>

`/proc/$pid/mem` ファイルは、プロセスのアドレス空間全体（_e. g._ x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）との 1 対 1 の mapping です。つまり、このファイルの offset `x` から読み取り、または offset `x` に書き込むことは、仮想アドレス `x` の内容を読み取り、または変更することと同じです。

ここで、対処すべき基本的な問題が 4 つあります。

- 一般的に、ファイルを変更できるのは root とファイルの owner だけです。
- ASLR。
- プログラムのアドレス空間に mapping されていないアドレスを読み取り、または書き込もうとすると、I/O error が発生します。

これらの問題には、完全ではないものの有効な解決策があります。

- ほとんどの shell interpreter では、子プロセスに継承される file descriptor を作成できます。書き込み権限付きで shell の `mem` ファイルを指す fd を作成すれば、その fd を使用する子プロセスが shell のメモリを変更できるようになります。
- ASLR は問題にすらなりません。shell の `maps` ファイルや procfs 内のその他のファイルを確認すれば、プロセスのアドレス空間に関する情報を取得できます。
- そのため、ファイルに対して `lseek()` を実行する必要があります。shell からこれを行うには、悪名高い `dd` を使う必要があります。

### In more detail

手順は比較的簡単で、理解するために特別な専門知識は必要ありません。<sup>[[1]](#references)</sup>

- 実行したい binary と loader を parse し、それらが必要とする mapping を特定します。次に、概ね kernel が `execve()` の各 call で実行するのと同じ手順を行う "shell"code を作成します。
- それらの mapping を作成します。
- binary をそれらに読み込みます。
- permissions を設定します。
- 最後に、プログラムの arguments で stack を初期化し、auxiliary vector（loader が必要とするもの）を配置します。
- loader に jump し、残りの処理（プログラムが必要とする libraries の load）を任せます。
- `syscall` file から、プロセスが実行中の syscall の後に return する address を取得します。
- その場所は executable なので、`mem` を通じて our shellcode で上書きします（`mem` を使えば unwritable な pages も変更できます）。
- 実行したいプログラムをプロセスの stdin に渡します（この stdin は、上述の "shell"code によって `read()` されます）。
- この時点で、必要な libraries を load してプログラムに jump する処理は loader に任されます。

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)。<sup>[[1]](#references)</sup>

## EverythingExec

`dd` にはいくつかの alternatives があり、その 1 つである `tail` は現在、`mem` file に対して `lseek()` を実行するために使用される default program です（これが `dd` を使う唯一の目的でした）。このような alternatives は次のとおりです。<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
`SEEKER` 変数を設定すると、使用する seeker を変更できます。_例_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
スクリプトに実装されていない別の有効な seeker を見つけた場合でも、`SEEKER_ARGS` 変数を設定して使用できます:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
これをブロックしてください、EDR。

## References

- [1] [DDexec: Linux上でバイナリをファイルレスかつステルスに実行するtechnique](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}

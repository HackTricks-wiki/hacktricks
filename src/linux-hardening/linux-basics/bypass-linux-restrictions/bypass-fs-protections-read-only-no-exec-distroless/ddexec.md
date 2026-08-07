# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linuxでプログラムを実行するには、それがファイルとして存在し、ファイルシステム階層を通じて何らかの形でアクセス可能でなければなりません（これは`execve()`の仕組みによるものです）。このファイルはディスク上にあっても、ram（tmpfs、memfd）上にあっても構いませんが、filepathが必要です。このため、Linuxシステム上で何が実行されるかを制御することが非常に容易になり、脅威や攻撃者のtoolsの検出、あるいはそれらが何かを実行すること自体の防止（_例_：unprivileged usersがどこにもexecutable filesを配置できないようにすること）が容易になります。

しかし、このtechniqueはそのすべてを変えるためのものです。実行したいprocessを起動できないなら……**すでに存在するものをhijackすればよいのです**。

このtechniqueにより、**read-only、noexec、file-name whitelisting、hash whitelistingなどの一般的なprotection techniquesをbypassできます**。<sup>[[1]](#references)</sup>

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
## The technique

プロセスのメモリを任意に変更できる場合、そのプロセスを乗っ取ることができます。これは、既存のプロセスを hijack し、別のプログラムに置き換えるために利用できます。これを実現するには、`ptrace()` syscall（syscall を実行する能力、またはシステム上で gdb を利用できることが必要）を使う方法と、より興味深い方法として `/proc/$pid/mem` に書き込む方法があります。<sup>[[1]](#references)</sup>

`/proc/$pid/mem` ファイルは、プロセスのアドレス空間全体（x86-64 では _e. g._ `0x0000000000000000` から `0x7ffffffffffff000` まで）と 1 対 1 に対応しています。つまり、このファイルのオフセット `x` から読み書きすることは、仮想アドレス `x` の内容を読み取ったり変更したりすることと同じです。

ここで、対処すべき基本的な問題が 4 つあります。

- 一般的に、そのファイルを変更できるのは root とファイルの所有者であるプログラムだけです。
- ASLR。
- プログラムのアドレス空間にマッピングされていないアドレスを読み書きしようとすると、I/O エラーが発生します。

これらの問題には、完全ではないものの有効な解決策があります。

- ほとんどの shell interpreter では、子プロセスに継承される file descriptor を作成できます。write 権限付きで shell の `mem` ファイルを指す fd を作成すれば、その fd を使用する子プロセスから shell のメモリを変更できるようになります。
- ASLR は問題にすらなりません。shell の `maps` ファイルや、procfs 内のその他のファイルを確認すれば、プロセスのアドレス空間に関する情報を取得できます。
- したがって、ファイル上で `lseek()` を実行する必要があります。shell からこれを行うには、悪名高い `dd` を使う必要があります。

### In more detail

手順は比較的簡単で、理解するために特別な専門知識は必要ありません。<sup>[[1]](#references)</sup>

- 実行したい binary と loader を解析し、それらが必要とする mapping を特定します。そして、概ね kernel が `execve()` の各呼び出し時に行うのと同じ手順を実行する "shell"code を作成します。
- その mapping を作成します。
- binary をそれらに読み込みます。
- permission を設定します。
- 最後に、プログラムの引数を含むように stack を初期化し、auxiliary vector（loader が必要とします）を配置します。
- loader に jump し、残りの処理（プログラムに必要な library の load）を任せます。
- `syscall` ファイルから、実行中の syscall の後にプロセスが return するアドレスを取得します。
- その場所は executable なので、そこを shellcode で上書きします（`mem` を介せば writable でない page も変更できます）。
- 実行したいプログラムをプロセスの stdin に渡します（その "shell"code によって `read()` されます）。
- この時点で、必要な library をプログラム用に load し、そこへ jump するのは loader の役割です。

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)<sup>[[1]](#references)</sup>

## EverythingExec

`dd` にはいくつかの alternative があり、その 1 つである `tail` は、現在 `mem` ファイル上で `lseek()` を実行するためにデフォルトで使用されるプログラムです（これが `dd` を使う唯一の目的でした）。このような alternative には次のものがあります。<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
変数 `SEEKER` を設定することで、使用する seeker を変更できます。_例えば_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
スクリプトに実装されていない別の有効なseekerを見つけた場合でも、`SEEKER_ARGS`変数を設定して使用できます:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
これをブロックしてください、EDR。

## 参考文献

- [1] [DDexec: Linux上でバイナリファイルをファイルレスかつステルスに実行するTechnique](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}

# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Context

Linuxでプログラムを実行するには、ファイルとして存在し、ファイルシステム階層を通じて何らかの方法でアクセス可能でなければなりません（これは単に`execve()`の仕組みです）。このファイルはディスク上またはram（tmpfs、memfd）上に存在できますが、filepathが必要です。この仕組みにより、Linuxシステム上で何が実行されるかを制御すること、threatやattackerのtoolsを検出すること、あるいはそれらが何かを実行しようとすること自体を防ぐこと（_e. g._ unprivileged userがどこにもexecutable fileを配置できないようにすること）が非常に容易になっています。

しかし、このtechniqueはそのすべてを変えるためのものです。実行したいprocessを開始できないなら……**すでに存在するprocessをhijackする**のです。

このtechniqueにより、read-only、noexec、file-name whitelisting、hash whitelistingなどの**一般的なprotection techniqueをbypassできます**。

## Dependencies

最終的なscriptは動作するために以下のtoolsに依存します。攻撃対象のsystemからアクセス可能である必要があります（デフォルトでは、これらはどこにでも存在します）。
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

プロセスのメモリを任意に変更できるなら、そのプロセスを乗っ取ることができます。これは、既存のプロセスを hijack し、別のプログラムに置き換えるために利用できます。これを実現するには、`ptrace()` syscall（syscall を実行する能力、またはシステム上で gdb が利用可能であることが必要）を使用する方法と、より興味深い方法として、`/proc/$pid/mem` に書き込む方法があります。

`/proc/$pid/mem` ファイルは、プロセスのアドレス空間全体（_e. g._ x86-64 では `0x0000000000000000` から `0x7ffffffffffff000` まで）を one-to-one mapping したものです。つまり、このファイルの offset `x` から読み取りまたは書き込みを行うことは、仮想アドレス `x` の内容を読み取る、または変更することと同じです。

ここで、対処すべき基本的な問題が 4 つあります。

- 一般に、ファイルを変更できるのは root とファイルの所有者だけです。
- ASLR。
- プログラムのアドレス空間に mapping されていないアドレスを読み書きしようとすると、I/O error が発生します。

これらの問題には、完全ではないものの、有効な解決策があります。

- ほとんどの shell interpreter では、子プロセスに継承される file descriptor を作成できます。write permission 付きで shell の `mem` ファイルを指す fd を作成すれば、その fd を使用する子プロセスから shell のメモリを変更できるようになります。
- ASLR は問題にすらなりません。shell の `maps` ファイル、または procfs 内のその他のファイルを確認して、プロセスのアドレス空間に関する情報を取得できます。
- そのため、ファイル上で `lseek()` を実行する必要があります。shell からこれを行うには、悪名高い `dd` を使用する必要があります。

### In more detail

手順は比較的簡単で、理解するために特別な expertise は必要ありません。

- 実行したい binary と loader を parse し、それらが必要とする mapping を確認します。次に、概ね kernel が `execve()` の各 call で実行するのと同じ手順を実行する "shell"code を craft します。
- これらの mapping を作成します。
- binary を mapping 内に読み込みます。
- permission を設定します。
- 最後に、プログラムの arguments を含むように stack を初期化し、auxiliary vector（loader が必要とするもの）を配置します。
- loader に jump し、残りの処理（プログラムが必要とする libraries の load）を任せます。
- `syscall` ファイルから、実行中の syscall の後にプロセスが return する address を取得します。
- その場所は executable なので、そこを shellcode で overwrite します（`mem` を通じて unwritable な pages も変更できます）。
- 実行したいプログラムをプロセスの stdin に渡します（その "shell"code によって `read()` されます）。
- この時点で、プログラムに必要な libraries を load し、プログラムへ jump する処理は loader に任されます。

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` にはいくつかの alternatives があり、その 1 つである `tail` は現在、`mem` ファイル上で `lseek()` を実行するために使用される default program です（これが `dd` を使用していた唯一の目的でした）。これらの alternatives は次のとおりです。
```bash
tail
hexdump
cmp
xxd
```
変数 `SEEKER` を設定すると、使用する seeker を変更できます。_例_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
スクリプトに実装されていない別の有効な seeker が見つかった場合でも、`SEEKER_ARGS` 変数に設定して使用できます。
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
これをブロックしてください、EDR。

## 参照

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}

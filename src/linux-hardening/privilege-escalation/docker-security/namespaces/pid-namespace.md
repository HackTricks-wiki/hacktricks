# PID 名前空間

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

PID (Process IDentifier) 名前空間は、Linux カーネルの機能で、プロセスのグループに他の名前空間の PID とは別の一意の PID セットを持たせることでプロセスの分離を提供します。これは、プロセス分離がセキュリティやリソース管理に不可欠なコンテナ化で特に有用です。

新しい PID 名前空間が作成されると、その名前空間内の最初のプロセスには PID 1 が割り当てられます。このプロセスは新しい名前空間の "init" プロセスとなり、その名前空間内の他のプロセスを管理する役割を担います。名前空間内で作成される各プロセスは、その名前空間内で一意の PID を持ち、これらの PID は他の名前空間の PID とは独立しています。

PID 名前空間内のプロセスの観点からは、同じ名前空間内のプロセスだけを参照できます。他の名前空間のプロセスを認識せず、従来のプロセス管理ツール（例: `kill`, `wait` など）を使って相互作用することはできません。これにより、プロセス同士が干渉するのを防ぐための分離が提供されます。

### 仕組み:

1. 新しいプロセスが作成されると（例: `clone()` システムコールを使用して）、プロセスは新しいまたは既存の PID 名前空間に割り当てられることがあります。 **新しい名前空間が作成された場合、そのプロセスはその名前空間の "init" プロセスになります**。
2. **kernel** は親名前空間（すなわち新しい名前空間が作成された元の名前空間）における対応する PID と新しい名前空間内の PID との間の **マッピング** を維持します。このマッピングにより、**kernel が必要に応じて PID を翻訳できるようになります**（例えば異なる名前空間間でプロセス間シグナルを送る場合など）。
3. **PID 名前空間内のプロセスは同じ名前空間内の他のプロセスのみを参照・操作できます**。他の名前空間のプロセスを認識せず、各プロセスの PID はその名前空間内で一意です。
4. **PID 名前空間が破棄されると**（例: その名前空間の "init" プロセスが終了したとき）、**その名前空間内のすべてのプロセスは終了されます**。これにより、名前空間に関連するすべてのリソースが適切にクリーンアップされます。

## ラボ:

### 異なる名前空間の作成

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`-f` オプションなしで `unshare` を実行すると、Linux が新しい PID (Process ID) 名前空間を扱う方法によりエラーが発生します。以下に主要な点と解決策を示します。

1. **Problem Explanation**:

- Linux カーネルは `unshare` システムコールでプロセスが新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始したプロセス（ここでは「unshare」プロセスと呼ぶ）はその新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると `/bin/bash` は `unshare` と同じプロセスで起動します。したがって `/bin/bash` とその子プロセスは元の PID 名前空間にいます。
- 新しい名前空間内で `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、PID 1 は孤児プロセスの引き取りなど特別な役割を持つため、他にプロセスがなければ名前空間のクリーンアップが起こります。その結果、Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **Consequence**:

- 新しい名前空間で PID 1 が終了すると `PIDNS_HASH_ADDING` フラグがクリアされます。そのため `alloc_pid` 関数は新しいプロセスのために PID を割り当てられず、"Cannot allocate memory" エラーが発生します。

3. **Solution**:
- この問題は `unshare` に `-f` オプションを付けることで解決できます。これにより `unshare` は新しい PID 名前空間を作成した後に fork して新しいプロセスを生成します。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` 自身が新しい名前空間内の PID 1 になります。これにより `/bin/bash` とその子プロセスは新しい名前空間内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てが行えるようになります。

`unshare` を `-f` フラグ付きで実行することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスはメモリ割り当てエラーに遭遇することなく動作できます。

</details>

`--mount-proc` パラメータを使って `/proc` ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間はその名前空間に特有のプロセス情報に対する**正確で独立したビュー**を持つことが保証されます。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどの namespace にいるかを確認する
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### すべての PID ネームスペースを見つける
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
初期（デフォルト）の PID namespace からの root ユーザーは、新しい PID namespace 内のプロセスであってもすべてのプロセスを見ることができる点に注意してください。そのため、すべての PID namespaces を見ることができます。

### PID namespace 内に入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

また、**他のプロセスの PID namespace に入れるのは root の場合のみです**。そして、**descriptor（例: `/proc/self/ns/pid`）を指すものがないと他の namespace に入ることはできません**。

## 最近の悪用メモ

### CVE-2025-31133: `maskedPaths` を悪用してホスト PID に到達する

runc ≤1.2.7 は、container images または `runc exec` ワークロードを制御する攻撃者が、ランタイムが敏感な procfs エントリをマスクする直前にコンテナ側の `/dev/null` を置き換えることを許していました。レースが成功すると、`/dev/null` は任意のホストパス（例えば `/proc/sys/kernel/core_pattern`）を指すシンボリックリンクに変えられ、結果として新しいコンテナの PID namespace は自分の namespace を出ていないにもかかわらずホスト全体の procfs 設定に対する読み書きアクセスを突然継承してしまいます。`core_pattern` や `/proc/sysrq-trigger` が書き込み可能になると、coredump を生成するか SysRq をトリガーすることで、ホストの PID namespace 上でコード実行やサービス拒否を引き起こせます。

実践的なワークフロー:

1. ホストのパスを指すリンクで `/dev/null` を置き換える OCI bundle を作成する（`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`）。
2. 修正が入る前にコンテナを起動して、runc がそのリンク上にホストの procfs ターゲットを bind-mount するようにする。
3. コンテナ namespace 内で、公開された procfs ファイルに書き込み（例: `core_pattern` を reverse shell helper を指すように設定）し、任意のプロセスをクラッシュさせてホストカーネルにあなたのヘルパーを PID 1 コンテキストで実行させる。

起動前にバンドルが適切なファイルをマスキングしているかどうかを素早く監査できます:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
ランタイムが期待するマスキングエントリを欠いている（または `/dev/null` が消失したためスキップしている）場合、そのコンテナはホストの PID が見えてしまう可能性があるものとして扱ってください。

### `insject` による Namespace 注入

NCC Group の `insject` は LD_PRELOAD ペイロードとしてロードされ、ターゲットプログラムの後期（デフォルトは `main`）にフックして `execve()` の後に一連の `setns()` 呼び出しを行います。これにより、ランタイムが *初期化後* にホスト（または別のコンテナ）から被害者の PID namespace にアタッチでき、コンテナのファイルシステムにバイナリをコピーすることなく `/proc/<pid>` のビューを保持できます。`insject` は PID namespace への参加を fork するまで遅らせることができるため、1 つのスレッドをホスト namespace（CAP_SYS_PTRACE を持たせたまま）に残し、別のスレッドをターゲットの PID namespace で実行させることで、強力なデバッグや攻撃用プリミティブを作り出せます。

使用例:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
namespace injection を悪用または防御する際の主な注意点：

- `-S/--strict` を使用して、スレッドが既に存在するか namespace joins が失敗した場合に `insject` を中止させてください。さもなければ、一部移行されたスレッドがホストとコンテナの PID スペースにまたがったままになる可能性があります。
- 書き込み可能なホストのファイルディスクリプタをまだ保持しているツールを、mount namespace に参加しないままアタッチしてはいけません — さもなければ、PID namespace 内の任意のプロセスがあなたのヘルパーを ptrace し、それらのディスクリプタを再利用してホストのリソースを改ざんすることができます。

## 参考

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}

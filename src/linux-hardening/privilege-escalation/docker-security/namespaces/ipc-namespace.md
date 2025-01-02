# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

IPC（Inter-Process Communication）名前空間は、メッセージキュー、共有メモリセグメント、セマフォなどのSystem V IPCオブジェクトの**隔離**を提供するLinuxカーネルの機能です。この隔離により、**異なるIPC名前空間のプロセスは互いのIPCオブジェクトに直接アクセスしたり、変更したりできない**ため、プロセスグループ間のセキュリティとプライバシーが追加されます。

### 仕組み:

1. 新しいIPC名前空間が作成されると、**完全に隔離されたSystem V IPCオブジェクトのセット**から始まります。これは、新しいIPC名前空間で実行されるプロセスが、デフォルトで他の名前空間やホストシステムのIPCオブジェクトにアクセスしたり干渉したりできないことを意味します。
2. 名前空間内で作成されたIPCオブジェクトは、その名前空間内のプロセスにのみ**表示され、アクセス可能**です。各IPCオブジェクトは、その名前空間内で一意のキーによって識別されます。キーは異なる名前空間で同一である可能性がありますが、オブジェクト自体は隔離されており、名前空間を越えてアクセスすることはできません。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを使用して`CLONE_NEWIPC`フラグで新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたIPCオブジェクトを使用し始めます。

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で孤立したビュー**を持つことが保証されます。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法のためにエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：

- Linux カーネルはプロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、ネームスペースのクリーンアップがトリガーされます。PID 1 は孤児プロセスを引き取る特別な役割を持っています。Linux カーネルはそのネームスペース内での PID 割り当てを無効にします。

2. **結果**：

- 新しいネームスペース内で PID 1 が終了すると、`PIDNS_HASH_ADDING` フラグがクリーニングされます。これにより、新しいプロセスを作成する際に新しい PID を割り当てる `alloc_pid` 関数が失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**：
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションは、`unshare` が新しい PID ネームスペースを作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しいネームスペース内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しいネームスペース内に安全に収容され、PID 1 の早期終了を防ぎ、正常な PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID ネームスペースが正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### すべてのIPCネームスペースを見つける
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### IPCネームスペースに入る
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
また、**ルートでない限り、他のプロセス名前空間に入ることはできません**。そして、**ディスクリプタ**がそれを指していない限り、他の名前空間に**入ることはできません**（例えば、`/proc/self/ns/net`のように）。

### IPCオブジェクトを作成する
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
## 参考文献

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}

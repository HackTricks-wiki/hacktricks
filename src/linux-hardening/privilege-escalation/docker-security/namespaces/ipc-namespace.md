# IPC Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

IPC（Inter-Process Communication）名前空間は、メッセージキュー、共有メモリセグメント、セマフォなどのSystem V IPCオブジェクトの**隔離**を提供するLinuxカーネルの機能です。この隔離により、**異なるIPC名前空間のプロセスは互いのIPCオブジェクトに直接アクセスしたり、変更したりできない**ため、プロセスグループ間のセキュリティとプライバシーの追加層が提供されます。

### 仕組み:

1. 新しいIPC名前空間が作成されると、**完全に隔離されたSystem V IPCオブジェクトのセット**から始まります。これは、新しいIPC名前空間で実行されるプロセスが、デフォルトで他の名前空間やホストシステムのIPCオブジェクトにアクセスしたり干渉したりできないことを意味します。
2. 名前空間内で作成されたIPCオブジェクトは、その名前空間内のプロセスにのみ**可視でアクセス可能**です。各IPCオブジェクトは、その名前空間内で一意のキーによって識別されます。キーは異なる名前空間で同一である可能性がありますが、オブジェクト自体は隔離されており、名前空間を越えてアクセスすることはできません。
3. プロセスは`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを`CLONE_NEWIPC`フラグと共に使用して新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたIPCオブジェクトを使用し始めます。

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウント名前空間がその名前空間に特有のプロセス情報の**正確で隔離されたビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) 名前空間を処理する方法のためにエラーが発生します。重要な詳細と解決策は以下に示されています。

1. **問題の説明**:

- Linux カーネルは、プロセスが `unshare` システムコールを使用して新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間に存在します。
- 新しい名前空間内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤児プロセスを引き取る特別な役割を持っています。Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:

- 新しい名前空間での PID 1 の終了は、`PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションは、`unshare` が新しい PID 名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に収容され、PID 1 の早期終了を防ぎ、正常な PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

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

### IPCオブジェクトの作成
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

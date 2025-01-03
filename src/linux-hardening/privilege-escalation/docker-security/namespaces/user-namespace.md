# ユーザー名前空間

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

ユーザー名前空間は、**ユーザーおよびグループIDマッピングの隔離を提供する**Linuxカーネルの機能であり、各ユーザー名前空間が**独自のユーザーおよびグループIDのセット**を持つことを可能にします。この隔離により、異なるユーザー名前空間で実行されているプロセスは、**同じユーザーおよびグループIDを数値的に共有していても、異なる特権と所有権を持つことができます**。

ユーザー名前空間は特にコンテナ化において有用であり、各コンテナが独自のユーザーおよびグループIDの独立したセットを持つべきであり、これによりコンテナとホストシステム間のセキュリティと隔離が向上します。

### 仕組み:

1. 新しいユーザー名前空間が作成されると、**空のユーザーおよびグループIDマッピングのセットから始まります**。これは、新しいユーザー名前空間で実行されるプロセスが**名前空間の外で特権を持たない状態で初期化されることを意味します**。
2. 新しい名前空間のユーザーおよびグループIDと親（またはホスト）名前空間のIDとの間にIDマッピングを確立できます。これにより、**新しい名前空間のプロセスが親名前空間のユーザーおよびグループIDに対応する特権と所有権を持つことができます**。ただし、IDマッピングは特定の範囲やIDのサブセットに制限でき、これにより新しい名前空間のプロセスに付与される特権を細かく制御できます。
3. ユーザー名前空間内では、**プロセスは名前空間内の操作に対して完全なルート特権（UID 0）を持つことができます**が、名前空間の外では制限された特権を持ちます。これにより、**コンテナはホストシステム上で完全なルート特権を持たずに、自身の名前空間内でルートのような機能を持って実行できます**。
4. プロセスは`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを`CLONE_NEWUSER`フラグと共に使用して新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたユーザーおよびグループIDマッピングを使用し始めます。

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間がその名前空間に特有のプロセス情報の**正確で孤立したビュー**を持つことが保証されます。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) 名前空間を処理する方法のためにエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：

- Linux カーネルは、プロセスが `unshare` システムコールを使用して新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間に存在します。
- 新しい名前空間内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤児プロセスを引き取る特別な役割を持っています。Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**：

- 新しい名前空間内で PID 1 が終了すると、`PIDNS_HASH_ADDING` フラグがクリーニングされます。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**：
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションは、`unshare` が新しい PID 名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に収容され、PID 1 の早期終了を防ぎ、正常な PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
ユーザー名前空間を使用するには、Dockerデーモンを**`--userns-remap=default`**で起動する必要があります（Ubuntu 14.04では、`/etc/default/docker`を変更し、その後`sudo service docker restart`を実行することで行えます）

### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dockerコンテナからユーザーマップを確認することができます:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
ホストからは次のように:
```bash
cat /proc/<pid>/uid_map
```
### すべてのユーザー名前空間を見つける
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### ユーザー名前空間に入る
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
また、**ルートでなければ他のプロセスネームスペースに入ることはできません**。そして、**ディスクリプタ**がそれを指していない限り（例えば `/proc/self/ns/user`）、他のネームスペースに**入ることはできません**。

### 新しいユーザーネームスペースを作成する（マッピング付き）
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### 回復可能性

ユーザー名前空間の場合、**新しいユーザー名前空間が作成されると、その名前空間に入るプロセスにはその名前空間内での完全な権限セットが付与されます**。これらの権限により、プロセスは**ファイルシステムのマウント**、デバイスの作成、ファイルの所有権の変更などの特権操作を実行できますが、**そのユーザー名前空間のコンテキスト内でのみ**実行できます。

例えば、ユーザー名前空間内で`CAP_SYS_ADMIN`権限を持っている場合、ファイルシステムのマウントなど、この権限を通常必要とする操作を実行できますが、あなたのユーザー名前空間のコンテキスト内でのみです。この権限を使用して実行する操作は、ホストシステムや他の名前空間には影響しません。

> [!WARNING]
> したがって、新しいユーザー名前空間内に新しいプロセスを取得することが**すべての権限を取り戻すことになります**（CapEff: 000001ffffffffff）が、実際には**名前空間に関連するもののみを使用できます**（例えばマウント）が、すべてではありません。したがって、これだけではDockerコンテナから脱出するには不十分です。
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#include ../../../../banners/hacktricks-training.md}}

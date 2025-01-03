# CGroup Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

cgroup 名前空間は、**名前空間内で実行されているプロセスのための cgroup 階層の隔離を提供する** Linux カーネルの機能です。cgroups（制御グループの略）は、CPU、メモリ、I/O などの**システムリソースに対する制限を管理および強制するためにプロセスを階層的なグループに整理する**ことを可能にするカーネル機能です。

cgroup 名前空間は、以前に議論した他の名前空間タイプ（PID、マウント、ネットワークなど）とは異なる独立した名前空間タイプではありませんが、名前空間の隔離の概念に関連しています。**Cgroup 名前空間は cgroup 階層のビューを仮想化し**、cgroup 名前空間内で実行されているプロセスは、ホストや他の名前空間で実行されているプロセスとは異なる階層のビューを持ちます。

### 仕組み:

1. 新しい cgroup 名前空間が作成されると、**作成プロセスの cgroup に基づいた cgroup 階層のビューから始まります**。これは、新しい cgroup 名前空間内で実行されるプロセスが、作成プロセスの cgroup に根ざした cgroup サブツリーに制限された、全体の cgroup 階層のサブセットのみを表示することを意味します。
2. cgroup 名前空間内のプロセスは、**自分の cgroup を階層のルートとして見る**ことになります。これは、名前空間内のプロセスの視点から見ると、自分の cgroup がルートとして表示され、他のサブツリー外の cgroup を見ることもアクセスすることもできないことを意味します。
3. cgroup 名前空間はリソースの隔離を直接提供するわけではありません; **cgroup 階層のビューの隔離のみを提供します**。**リソースの制御と隔離は、cgroup** サブシステム（例: cpu、memory など）自体によって強制されます。

CGroups に関する詳細情報は次を確認してください:

{{#ref}}
../cgroups.md
{{#endref}}

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で孤立したビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法のためにエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：

- Linux カーネルはプロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、ネームスペースのクリーンアップがトリガーされます。PID 1 は孤児プロセスを引き取る特別な役割を持っています。Linux カーネルはそのネームスペース内での PID 割り当てを無効にします。

2. **結果**：

- 新しいネームスペース内で PID 1 が終了すると、`PIDNS_HASH_ADDING` フラグがクリーニングされます。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

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
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### すべてのCGroup名前空間を見つける
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### CGroupネームスペースに入る
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
また、**ルートでない限り、他のプロセスネームスペースに入ることはできません**。そして、**ディスクリプタ**がそれを指していない限り、他のネームスペースに**入ることはできません**（例えば、`/proc/self/ns/cgroup`のように）。

## 参考文献

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

{{#include ../../../../banners/hacktricks-training.md}}

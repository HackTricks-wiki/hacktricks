# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

UTS (UNIX Time-Sharing System) 名前空間は、**ホスト名**と**NIS** (Network Information Service) ドメイン名の**2つのシステム識別子の隔離**を提供するLinuxカーネルの機能です。この隔離により、各UTS名前空間は**独自のホスト名とNISドメイン名**を持つことができ、特に各コンテナが独自のホスト名を持つ別々のシステムとして表示されるべきコンテナ化シナリオで便利です。

### 仕組み:

1. 新しいUTS名前空間が作成されると、**親名前空間からホスト名とNISドメイン名のコピー**で始まります。これは、作成時に新しい名前空間が**親と同じ識別子を共有する**ことを意味します。しかし、名前空間内でのホスト名やNISドメイン名へのその後の変更は、他の名前空間には影響しません。
2. UTS名前空間内のプロセスは、`sethostname()`および`setdomainname()`システムコールを使用して**ホスト名とNISドメイン名を変更**できます。これらの変更は名前空間にローカルであり、他の名前空間やホストシステムには影響しません。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを使用して`CLONE_NEWUTS`フラグで新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたホスト名とNISドメイン名を使用し始めます。

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で孤立したビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てできません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法のためにエラーが発生します。重要な詳細と解決策は以下に示されています。

1. **問題の説明**:

- Linux カーネルは、プロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、孤児プロセスを引き取る特別な役割を持つ PID 1 によりネームスペースのクリーンアップがトリガーされます。Linux カーネルはそのネームスペースでの PID 割り当てを無効にします。

2. **結果**:

- 新しいネームスペース内の PID 1 の終了は `PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に新しい PID を割り当てる `alloc_pid` 関数が失敗し、「メモリを割り当てできません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションにより、`unshare` は新しい PID ネームスペースを作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しいネームスペース内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しいネームスペース内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID ネームスペースが正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### すべてのUTS名前空間を見つける
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS ネームスペースに入る
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}

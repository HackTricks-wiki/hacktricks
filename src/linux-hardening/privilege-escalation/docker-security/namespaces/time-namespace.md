# タイムネームスペース

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

Linuxのタイムネームスペースは、システムのモノトニックおよびブートタイムクロックに対する名前空間ごとのオフセットを可能にします。これは、コンテナ内の日付/時刻を変更し、チェックポイントまたはスナップショットから復元した後にクロックを調整するために、Linuxコンテナで一般的に使用されます。

## ラボ:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で孤立したビュー**を持つことが保証されます。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法のためにエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：

- Linux カーネルは、プロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、孤児プロセスを引き取る特別な役割を持つ PID 1 によりネームスペースのクリーンアップがトリガーされます。Linux カーネルはそのネームスペース内での PID 割り当てを無効にします。

2. **結果**：

- 新しいネームスペース内での PID 1 の終了は、`PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**：
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションは、`unshare` が新しい PID ネームスペースを作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しいネームスペース内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しいネームスペース内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID ネームスペースが正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### すべてのタイムネームスペースを見つける
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### タイムネームスペースに入る
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}

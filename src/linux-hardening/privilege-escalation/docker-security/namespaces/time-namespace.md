# タイムネームスペース

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

Linuxのタイムネームスペースは、システムのモノトニックおよびブートタイムクロックに対する名前空間ごとのオフセットを許可します。これは、コンテナ内の日付/時刻を変更し、チェックポイントまたはスナップショットから復元した後にクロックを調整するために、Linuxコンテナで一般的に使用されます。

## ラボ:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で隔離されたビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法によりエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**：

- Linux カーネルはプロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、孤児プロセスを引き取る特別な役割を持つ PID 1 によりネームスペースのクリーンアップがトリガーされます。Linux カーネルはそのネームスペース内での PID 割り当てを無効にします。

2. **結果**：

- 新しいネームスペース内での PID 1 の終了は `PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**：
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションにより、`unshare` は新しい PID ネームスペースを作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しいネームスペース内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しいネームスペース内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID ネームスペースが正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどの名前空間にあるかを確認する
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
## 時間オフセットの操作

Linux 5.6以降、2つの時計が時間名前空間ごとに仮想化できます：

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

それらの名前空間ごとのデルタは、ファイル `/proc/<PID>/timens_offsets` を通じて公開され（および変更可能です）。
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
ファイルには、**ナノ秒**単位のオフセットを持つ2行が含まれています。**CAP_SYS_TIME**を持つプロセスは、_タイムネームスペース_内で値を変更できます：
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
壁時計（`CLOCK_REALTIME`）も変更する必要がある場合、従来のメカニズム（`date`、`hwclock`、`chronyd`など）に依存する必要があります。これは**名前空間化**されていません。

### `unshare(1)` ヘルパーフラグ (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
長いオプションは、名前空間が作成された直後に選択されたデルタを `timens_offsets` に自動的に書き込み、手動の `echo` を省略します。

---

## OCI & Runtime support

* **OCI Runtime Specification v1.1**（2023年11月）は、専用の `time` 名前空間タイプと `linux.timeOffsets` フィールドを追加し、コンテナエンジンがポータブルな方法で時間の仮想化を要求できるようにしました。
* **runc >= 1.2.0** は仕様のその部分を実装しています。最小の `config.json` フラグメントは次のようになります：
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
次に、`runc run <id>` でコンテナを実行します。

>  注意: runc **1.2.6**（2025年2月）は、ハングや潜在的なDoSにつながる可能性のある「プライベートtimensを持つコンテナへのexec」バグを修正しました。 本番環境では、1.2.6以上を使用していることを確認してください。

---

## Security considerations

1. **必要な能力** – プロセスは、オフセットを変更するためにユーザー/時間名前空間内で **CAP_SYS_TIME** が必要です。この能力をコンテナ内で削除する（Docker & Kubernetesのデフォルト）ことで、改ざんを防ぎます。
2. **時計の変更なし** – `CLOCK_REALTIME` はホストと共有されているため、攻撃者はtimensだけでは証明書の有効期限やJWTの期限を偽装できません。
3. **ログ/検出回避** – `CLOCK_MONOTONIC` に依存するソフトウェア（例：稼働時間に基づくレートリミッター）は、名前空間ユーザーがオフセットを調整すると混乱する可能性があります。セキュリティに関連するタイムスタンプには `CLOCK_REALTIME` を優先してください。
4. **カーネル攻撃面** – `CAP_SYS_TIME` が削除されても、カーネルコードにはアクセス可能なままです。ホストをパッチ適用しておいてください。Linux 5.6 → 5.12 は複数のtimensバグ修正（NULL-deref、符号付き問題）を受けました。

### Hardening checklist

* コンテナランタイムのデフォルトプロファイルで `CAP_SYS_TIME` を削除します。
* ランタイムを最新の状態に保ちます（runc ≥ 1.2.6、crun ≥ 1.12）。
* `--monotonic/--boottime` ヘルパーに依存する場合は util-linux ≥ 2.38 を固定します。
* セキュリティクリティカルなロジックのために **uptime** または **CLOCK_MONOTONIC** を読み取るコンテナ内ソフトウェアを監査します。

## References

* man7.org – 時間名前空間マニュアルページ: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: 新しい時間とRDT名前空間"（2023年11月15日）: <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}

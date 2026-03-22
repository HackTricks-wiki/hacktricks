# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

The time namespace virtualizes selected clocks, especially **`CLOCK_MONOTONIC`** and **`CLOCK_BOOTTIME`**. It is a newer and more specialized namespace than mount, PID, network, or user namespaces, and it is rarely the first thing an operator thinks about when discussing container hardening. Even so, it is part of the modern namespace family and worth understanding conceptually.

主な目的は、ホストのグローバルな時刻表示を変更することなく、プロセスが特定のクロックに対する制御されたオフセットを観察できるようにすることです。これは checkpoint/restore workflows、決定論的テスト、そして一部の高度なランタイム挙動で有用です。mount や user namespaces のように目立つ隔離手段であることは多くありませんが、それでもプロセス環境をより自己完結的にするのに寄与します。

## ラボ

If the host kernel and userspace support it, you can inspect the namespace with:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
サポートはカーネルやツールのバージョンによって異なるため、このページは各ラボ環境で常に見られることを期待するというよりも、仕組みを理解するためのものです。

### 時刻オフセット

Linux の time namespaces は `CLOCK_MONOTONIC` と `CLOCK_BOOTTIME` のオフセットを仮想化します。現在のネームスペースごとのオフセットは `/proc/<pid>/timens_offsets` を通じて公開されており、対応するカーネルでは該当ネームスペース内で `CAP_SYS_TIME` を持つプロセスによって変更することもできます:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
ファイルはナノ秒単位の差分を含んでいます。`monotonic` を2日分調整すると、その名前空間内のアップタイムのような観測値がホストの壁時計を変更せずに変わります。

### `unshare` ヘルパーフラグ

最近の `util-linux` バージョンでは、オフセットを自動的に書き込む便利なフラグが提供されています:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
これらのフラグは主に使い勝手の改善ですが、ドキュメントやテストでその機能を認識しやすくするという利点もあります。

## ランタイムでの使用

time 名前空間は、mount や PID 名前空間に比べて新しく、まだ広く利用されているわけではありません。OCI Runtime Specification v1.1 は `time` 名前空間と `linux.timeOffsets` フィールドに対する明示的なサポートを追加しており、新しい `runc` リリースはそのモデルの該当部分を実装しています。最小限の OCI フラグメントは次のようになります:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
This matters because it turns time namespacing from a niche kernel primitive into something that runtimes can request portably.

## Security Impact

他の namespace タイプと比べて、time namespace を中心とした古典的なブレイクアウト事例は少ないです。ここでのリスクは通常、time namespace が直接エスケープを可能にすることではなく、読者がそれを完全に無視してしまい、高度な runtimes がプロセス挙動をどのように形成しているかを見落とす点にあります。特殊な環境では、変更されたクロック表示が checkpoint/restore、observability、またはフォレンジックの想定に影響を与える可能性があります。

## Abuse

ここには通常、直接的なブレイクアウトプリミティブは存在しませんが、変更されたクロック挙動は実行環境を理解したり、高度な runtimes の機能を特定したりするのに依然として有用です：
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
もし2つのプロセスを比較している場合、ここでの差分は異常なタイミング動作、チェックポイント/リストアのアーティファクト、または環境固有のログ不一致を説明するのに役立ちます。

影響:

- ほとんど常に偵察や環境把握
- ログ、稼働時間、またはチェックポイント/リストアの異常を説明するのに有用
- 通常、それ自体で直接のコンテナ脱出手段にはならない

重要な悪用に関するニュアンスは、time namespacesが`CLOCK_REALTIME`を仮想化しないため、それ自体では攻撃者がホストの壁時計を偽造したり、システム全体の証明書有効期限チェックを直接破ったりすることはできない、という点です。主な価値は単調時間ベースのロジックを混乱させること、環境固有のバグを再現すること、または高度なランタイム挙動を理解することにあります。

## チェック

これらのチェックは主に、ランタイムがプライベートなtime namespaceを使用しているかどうかを確認することに関するものです。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
ここで興味深い点:

- 多くの環境では、これらの値が直ちにセキュリティ上の指摘につながることはありませんが、特定のランタイム機能が有効になっているかどうかを示します。
- 2つのプロセスを比較している場合、ここでの差異がタイミングの混乱や checkpoint/restore の挙動の違いを説明することがあります。

ほとんどの container breakouts では、time namespace は最初に調査するコントロールではありません。それでも、time namespace は現代のカーネルモデルの一部であり、高度なランタイムシナリオでは時折重要になるため、完全な container-security セクションでは言及しておくべきです。
{{#include ../../../../../banners/hacktricks-training.md}}

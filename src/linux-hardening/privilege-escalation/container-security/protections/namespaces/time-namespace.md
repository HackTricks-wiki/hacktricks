# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

time namespace は特定のクロック、特に **`CLOCK_MONOTONIC`** と **`CLOCK_BOOTTIME`** を仮想化します。これは mount、PID、network、または user namespaces より新しく、より専門的な namespace であり、container hardening を議論するときにオペレータが最初に思い浮かべることはめったにありません。それでも、現代の namespace ファミリの一部であり、概念的に理解しておく価値があります。

主な目的は、ホストのグローバルな時刻表示を変更せずに、プロセスが特定のクロックに対する制御されたオフセットを観測できるようにすることです。これは checkpoint/restore ワークフロー、決定論的テスト、およびいくつかの高度なランタイム挙動で有用です。通常、mount や user namespaces のような主要な隔離制御として注目されることは少ないですが、それでもプロセス環境をより自己完結的にするのに寄与します。

## ラボ

ホストのカーネルと userspace がこれをサポートしていれば、次のコマンドで namespace を調べることができます：
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
サポートはカーネルやツールのバージョンによって異なるため、このページは各ラボ環境で必ず表示されることを期待するよりも、メカニズムを理解することに重点を置いています。

### 時刻オフセット

Linux の time namespaces は `CLOCK_MONOTONIC` と `CLOCK_BOOTTIME` のオフセットを仮想化します。現在の名前空間ごとのオフセットは `/proc/<pid>/timens_offsets` で公開されており、対応するカーネルでは該当する名前空間内で `CAP_SYS_TIME` を保持するプロセスによって変更することもできます:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
そのファイルにはナノ秒単位の差分が含まれています。`monotonic` を2日分調整すると、ホストの壁時計を変更せずにその名前空間内の uptime に似た観測値が変わります。

### `unshare` のヘルパーフラグ

最近の `util-linux` バージョンでは、オフセットを自動的に書き込む便利なフラグが用意されています：
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
これらのフラグは主に使い勝手の向上を目的としていますが、ドキュメントやテストでこの機能を認識しやすくするという利点もあります。

## ランタイムでの使用

`time` 名前空間は、mount や PID 名前空間よりも新しく、あまり広く利用されていません。OCI Runtime Specification v1.1 は `time` 名前空間と `linux.timeOffsets` フィールドへの明示的なサポートを追加しており、新しい `runc` リリースはモデルのその部分を実装しています。最小限の OCI フラグメントは次のようになります：
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
これは、time namespacing をニッチなカーネルプリミティブから、runtimes がポータブルに要求できるものへと変えるため重要です。

## セキュリティへの影響

他の namespace 種類ほど time namespace を中心とした古典的な breakout ストーリーは多くありません。ここでのリスクは通常、time namespace 自体が直接 escape を可能にすることではなく、読者がそれを完全に無視してしまい、その結果高度な runtimes がプロセスの挙動をどのように形成しているかを見落とすことにあります。特殊な環境では、変更された時計の見え方が checkpoint/restore、observability、またはフォレンジックに関する仮定に影響を与える可能性があります。

## 悪用

ここでは通常、直接的な breakout primitive は存在しませんが、変更された時計の挙動は実行環境を理解し、高度な runtimes の機能を特定するのに依然として有用です：
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
もし 2つのプロセスを比較している場合、ここでの差異は奇妙なタイミング挙動、checkpoint/restore のアーティファクト、または環境固有のログの不一致を説明するのに役立ちます。

影響:

- ほとんどの場合、偵察または環境理解に関連します
- ログ、稼働時間、または checkpoint/restore の異常を説明するのに有用です
- 通常、それ自体で直接的な container-escape 手段にはなりません

重要な悪用上のニュアンスは、time namespaces が `CLOCK_REALTIME` を仮想化しないという点です。したがって、それ単体で攻撃者がホストの実時刻を偽造したり、システム全体の証明書の有効期限チェックを直接破ることはできません。価値があるのは主に、単調時間ベースのロジックを混乱させること、環境固有のバグを再現すること、または高度なランタイム挙動を理解することにあります。

## Checks

これらのチェックは主に、ランタイムがプライベートな time namespace を使用しているかどうかを確認することに関するものです。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
何が興味深いか:

- 多くの環境では、これらの値が直ちにセキュリティ上の指摘につながることはないが、特殊な runtime 機能が使われているかどうかを示す手がかりになる。
- もし二つのプロセスを比較しているなら、ここでの差異がタイミングの違いや checkpoint/restore の挙動の混乱を説明することがある。

ほとんどの container breakouts において、time namespace は最初に調査する制御項目ではない。それでも、完全な container-security セクションではこれに言及しておくべきだ。なぜならそれは modern kernel model の一部であり、高度な runtime シナリオでは時折重要になるからである。

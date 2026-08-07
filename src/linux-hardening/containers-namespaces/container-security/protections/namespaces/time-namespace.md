# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

Time namespace は、host の wall clock ではなく、選択された monotonic-style clock を仮想化します。実際には、**`CLOCK_MONOTONIC`** と **`CLOCK_BOOTTIME`** に対する private offset に加え、密接に関連する **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`**、**`CLOCK_BOOTTIME_ALARM`** の view が対象になります。**`CLOCK_REALTIME`** は仮想化されないため、他の mechanism が干渉しない限り、`date` と certificate-expiry logic は引き続き host の wall clock を参照します。<sup>[[1]](#references)</sup>

主な目的は、host の global time view を変更せずに、process が制御された経過時間の offset を観測できるようにすることです。これは checkpoint/restore workflow、deterministic testing、advanced runtime behavior に役立ちます。mount namespace や user namespace と同様の主要な isolation control になることは通常ありませんが、process environment をより self-contained にすることには寄与します。

offensive point of view では、この namespace は直接的な breakout よりも、通常は **reconnaissance、timer skew、runtime understanding** に関係します。それでも重要なのは、より多くの container runtime と checkpoint/restore workflow が、現在ではこれを明示的に要求できるようになっているためです。

## ラボ

host kernel と userspace が対応している場合、次のコマンドで namespace を確認できます。
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
サポート状況は kernel と tool のバージョンによって異なるため、このページではすべての lab 環境で確認できることを期待するよりも、mechanism を理解することに重点を置いています。重要な点は、`date` は引き続き host の wall clock を反映する一方、nonzero offset が設定されたときに変化するのは monotonic/boottime ベースの値だということです。

### 作成時の注意点

Time namespace は、mount、PID、network namespace と比べてやや特殊です。<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)` は**将来の child**用に新しい time namespace を作成します。
- 呼び出し元の task は現在の time namespace に残ります。
- そのため、runtime の setup を debug するときは、`/proc/<pid>/ns/time` よりも `/proc/<pid>/ns/time_for_children` のほうが興味深いことがよくあります。

write window も特殊です。`/proc/<pid>/timens_offsets` の offset は、新しい time namespace に running task が完全に配置される前に書き込む必要があります。実際には、runtime は namespace の作成から最終的な payload の起動までの狭い setup window 内でこれを行います。task がそこで既に running になっている場合、後続の write は `EACCES` で失敗します。このため、low-level runtime は、既に起動済みの container process の内部から offset を patch しようとするのではなく、time-namespace setup を初期 bootstrap step として処理します。<sup>[[1]](#references)</sup>

### Time Offset

Linux time namespace は、`/proc/<pid>/timens_offsets` を通じて namespace ごとの offset を公開します。形式は、clock の名前または ID と、initial time namespace を基準とした秒/nanosecond 単位の delta の組み合わせです。<sup>[[1]](#references)</sup>

実際には、最も信頼性の高い user-facing workflow は、`unshare` に offset を自動的に書き込ませることです。
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
重要な点は、正確なコマンド構文ではなく、その動作です。container は、host の wall clock を変更せずに、異なる uptime のような表示を観測できます。

### `unshare` Helper Flags

最近の `util-linux` バージョンでは、namespace 作成時に offset を自動的に書き込む便利な flags が提供されています：
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
これらの flags は主に usability の改善ですが、documentation、test harness、runtime wrapper でこの feature を認識しやすくする効果もあります。

## Runtime Usage

Time namespace は mount namespace や PID namespace より新しく、広く使用されているわけではありません。OCI Runtime Specification v1.1 では `time` namespace と `linux.timeOffsets` field の明示的なサポートが追加され、modern runtime ではこのデータを kernel bootstrap flow に反映できるようになっています。最小限の OCI fragment は次のようになります:
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
これは、time namespacingをニッチなkernel primitiveから、runtimeがportableに要求できるものへと変えるため重要です。また、runtimeの内部で明示的な同期ステップが必要な理由も説明しています。つまり、container payloadが新しいnamespaceに完全に入る前に、offsetを`/proc/<pid>/timens_offsets`へ書き込まなければなりません。

CRIUのようなcheckpoint/restore stackは、そもそもこれが存在する主な実用上の理由の1つです。time namespaceがなければ、一時停止していたworkloadをrestoreした際に、monotonic clockとboot-time clockが、workloadのsuspend中に経過した時間分だけ飛んでしまいます。<sup>[[2]](#references)</sup>

## Security Impact

他のnamespace typeと比べると、time namespaceを中心とした典型的なbreakout事例は少数です。ここでのriskは通常、time namespaceが直接escapeを可能にすることではありません。むしろ、読者がこれを完全に無視することで、高度なruntimeがprocessの挙動をどのように変化させているかを見落とすことです。

特殊なenvironmentでは、変更されたmonotonicまたはboottimeのviewが、以下に影響する可能性があります。

- timeoutとretryの挙動
- watchdogとleaseのlogic
- `timerfd`、`nanosleep`、`clock_nanosleep`の挙動
- checkpoint/restoreのforensics
- 経過時間のtelemetryとuptimeベースのheuristics

したがって、これは通常、最初にabuseするnamespaceではありませんが、assessment中に発生する「不可能な」timing behaviorを説明する手がかりにはなり得ます。

## Abuse

通常、ここに直接的なbreakout primitiveはありません。しかし、変更されたclock behaviorは、execution environmentの理解、高度なruntime機能の特定、そしてwall clock timeではなくmonotonic clockを基準に測定されるtimer-based logicの発見に役立ちます。
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
2つのプロセスを比較している場合、ここでの差異は、奇妙なタイミングの挙動、checkpoint/restore のアーティファクト、または環境固有のログの不一致を説明する手がかりになります。

実践的な攻撃者関連の観点：

- monotonic clock を使って実装された backoff、sleep、watchdog ロジックを混乱させる
- `/proc/uptime` と timer-driven な挙動が、ホスト側の wall-clock に基づく期待と一致しない理由を説明する
- CRIU/checkpoint-restore ワークフローや、その他の高度な runtime 機能を認識する
- `nsenter -T -t <pid> -- ...` で対象の time namespace に参加すると、デバッグや post-exploitation のためにコンテナ内の timer 挙動を再現できる環境を見つける

影響：

- ほとんどの場合、reconnaissance または環境の把握
- logging、uptime、checkpoint/restore の異常を説明するのに有用
- monotonic-time-based な sleep、retry、timer の分析に有用
- 通常、それ単独で直接的な container-escape の仕組みになることはない

重要な abuse 上の注意点は、time namespace が `CLOCK_REALTIME` を virtualize しないことです。そのため、攻撃者がホストの wall clock を偽装したり、システム全体で certificate-expiry checks を直接破壊したりすることはできません。主な価値は、monotonic-time-based なロジックを混乱させたり、環境固有のバグを再現したり、高度な runtime の挙動を理解したりすることにあります。

## 確認

これらの確認は主に、runtime が private time namespace を使用しているかどうか、また実際にゼロ以外の offset を設定しているかどうかを確認するためのものです。
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
ここで興味深い点:

- 多くの環境では、これらの値が直ちに security finding につながることはありませんが、specialized runtime feature が使用されているかどうかを示します。
- `time_for_children` が `time` と異なる場合、caller は自身では入っていない、子プロセス専用の time namespace を準備している可能性があります。
- `date` が host と一致している一方で、monotonic/boottime ベースの値が一致しない場合、wall-clock tampering ではなく time namespacing を見ている可能性が高いです。
- 2つのプロセスを比較している場合、これらの差異によって、不可解な timing や checkpoint/restore の挙動を説明できることがあります。

ほとんどの container breakout では、time namespace は最初に調査する control ではありません。それでも、modern kernel model の一部であり、高度な runtime シナリオでは時折重要になるため、完全な container-security セクションでは触れておくべきです。

## References

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}

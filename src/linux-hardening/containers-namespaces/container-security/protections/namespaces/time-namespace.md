# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Time Namespace は、host の wall clock ではなく、選択された monotonic-style clock を仮想化します。実際には、**`CLOCK_MONOTONIC`** と **`CLOCK_BOOTTIME`** に対する private offset に加え、密接に関連する **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`**、**`CLOCK_BOOTTIME_ALARM`** の view が対象になります。**`CLOCK_REALTIME`** は仮想化されないため、他の mechanism が干渉しない限り、`date` や certificate-expiry logic は引き続き host の wall clock を参照します。

主な目的は、host 全体の time view を変更せずに、process が制御された経過時間の offset を参照できるようにすることです。これは checkpoint/restore workflow、deterministic testing、高度な runtime behavior に役立ちます。mount namespace や user namespace と同じような主要な isolation control になることは通常ありませんが、process environment をより self-contained にする役割は果たします。

offensive な観点では、この namespace は直接的な breakout よりも、通常は **reconnaissance、timer skew、runtime understanding** に関係します。それでも重要なのは、より多くの container runtime や checkpoint/restore workflow が、現在ではこれを明示的に要求できるようになっているためです。

## Lab

host kernel と userspace が対応している場合、次のコマンドで namespace を確認できます:
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
サポート状況は kernel と tool のバージョンによって異なるため、このページではすべての lab 環境で確認できることを期待するよりも、mechanism を理解することに重点を置いています。重要な点は、`date` は引き続きホストの wall clock を反映する一方で、nonzero offset が設定されたときに変化するのは monotonic/boottime ベースの値であるということです。

### Creation Nuance

Time namespace は mount、PID、network namespace と比べてやや特殊です。

- `unshare(CLONE_NEWTIME)` は、**future children** 用の新しい time namespace を作成します。
- 呼び出し元の task は現在の time namespace にとどまります。
- そのため、runtime setup の debugging では `/proc/<pid>/ns/time` よりも `/proc/<pid>/ns/time_for_children` のほうが興味深い場合がよくあります。

write window も特殊です。`/proc/<pid>/timens_offsets` の offset は、新しい time namespace に running task が完全に追加される前に書き込む必要があります。実際には、runtime は namespace の作成から最終的な payload の起動までの狭い setup window の間にこれを行います。task がすでにそこで running している場合、後からの write は `EACCES` で失敗します。そのため low-level runtime は、すでに起動済みの container process 内から offset を patch しようとするのではなく、time-namespace setup を early bootstrap step として処理します。

### Time Offsets

Linux の time namespace は、`/proc/<pid>/timens_offsets` を通じて namespace ごとの offset を公開します。形式は、initial time namespace を基準とした second/nanosecond delta と、clock name または ID の組み合わせです。

実際には、最も信頼性の高い user-facing workflow は、`unshare` に offset の write を任せることです。
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
重要なのは正確なコマンド構文ではなく、その挙動です。container は、host の wall clock を変更せずに、異なる uptime に似た表示を観測できます。

### `unshare` Helper Flags

最近の `util-linux` のバージョンには、namespace の作成時に offset を自動的に書き込む convenience flags が用意されています。
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
これらのフラグは主に usability の向上を目的としていますが、documentation、test harnesses、runtime wrappers でこの機能を認識しやすくする効果もあります。

## Runtime Usage

Time namespaces は mount namespace や PID namespace よりも新しく、利用される機会も普遍的ではありません。OCI Runtime Specification v1.1 では、`time` namespace と `linux.timeOffsets` フィールドが明示的にサポートされ、modern runtimes はそのデータを kernel bootstrap flow に渡せるようになっています。最小限の OCI fragment は次のようになります：
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
これは、time namespacingをニッチな kernel primitive から、runtimesがportableに要求できる機能へと変えるため重要です。また、runtimeの内部で明示的な synchronization stepが必要な理由も説明しています。つまり、container payloadが新しいnamespaceに完全に入る前に、offsetを`/proc/<pid>/timens_offsets`へ書き込まなければなりません。

CRIUのようなcheckpoint/restore stacksは、これが実際に存在する主な理由の一つです。time namespacesがなければ、paused workloadをrestoreした際に、monotonic clockとboot-time clockが、workloadがsuspendされていた時間の分だけ大きく進んでしまいます。

## セキュリティへの影響

他のnamespace typesと比べると、time namespaceを中心とした典型的なbreakout事例は少数です。ここでのリスクは通常、time namespaceが直接escapeを可能にすることではありません。むしろ、読者がこれを完全に無視することで、advanced runtimesがprocess behaviorをどのように変化させているかを見落とすことにあります。

特殊な環境では、変更されたmonotonicまたはboottimeのviewが、以下に影響する可能性があります。

- timeoutとretryの動作
- watchdogとlease logic
- `timerfd`、`nanosleep`、`clock_nanosleep`の動作
- checkpoint/restore forensics
- elapsed-time telemetryとuptimeベースのheuristics

そのため、これは通常、最初にabuseするnamespaceではありませんが、assessment中に発生する「不可能な」timing behaviorを確実に説明できる場合があります。

## Abuse

通常、ここに直接的なbreakout primitiveはありません。しかし、変更されたclock behaviorは、execution environmentの理解、advanced runtime featuresの特定、そしてwall clock timeではなくmonotonic clocksを基準に測定されるtimer-based logicの発見に役立ちます。
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
2つのプロセスを比較している場合、ここでの差異は、奇妙なタイミングの挙動、checkpoint/restore によるアーティファクト、または環境固有の logging の不一致を説明するのに役立ちます。

攻撃者に関連する実用的な観点：

- monotonic clock で実装された backoff、sleep、または watchdog ロジックを混乱させる
- `/proc/uptime` と timer-driven な挙動が、host 側の wall-clock に基づく想定と一致しない理由を説明する
- CRIU/checkpoint-restore workflow やその他の高度な runtime 機能を認識する
- `nsenter -T -t <pid> -- ...` で target の time namespace に参加することにより、debugging や post-exploitation のために container-local な timer の挙動を再現できる環境を見つける

影響：

- ほぼ常に reconnaissance または環境の理解に関するもの
- logging、uptime、または checkpoint/restore の異常を説明するのに有用
- monotonic-time-based な sleep、retry、timer の分析に有用
- 通常、それ単独で直接的な container-escape mechanism になることはない

重要な abuse 上の注意点は、time namespace が `CLOCK_REALTIME` を virtualize しないことです。そのため、攻撃者が host の wall clock を偽装したり、システム全体で certificate-expiry check を直接破壊したりすることはできません。その価値の大部分は、monotonic-time-based なロジックを混乱させたり、環境固有のバグを再現したり、高度な runtime の挙動を理解したりすることにあります。

## チェック

これらのチェックは、主に runtime が private な time namespace を実際に使用しているかどうか、また nonzero offset が実際に設定されているかどうかを確認するためのものです。
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

- 多くの環境では、これらの値が直ちに security finding につながることはありません。しかし、specialized runtime feature が有効になっているかどうかは判断できます。
- `time_for_children` が `time` と異なる場合、caller が子プロセス専用の time namespace を準備したものの、自身ではそれに入っていない可能性があります。
- `date` が host と一致する一方で、monotonic/boottime ベースの値が一致しない場合、wall-clock tampering ではなく time namespacing を確認している可能性が高いです。
- 2つのプロセスを比較している場合、これらの差異によって、不可解な timing や checkpoint/restore の動作を説明できることがあります。

ほとんどの container breakout では、time namespace は最初に調査する control ではありません。それでも、現代の kernel model の一部であり、高度な runtime シナリオで重要になる場合があるため、完全な container-security セクションでは触れておくべきです。

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}

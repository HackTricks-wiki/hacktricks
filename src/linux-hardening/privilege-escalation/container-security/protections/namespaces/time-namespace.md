# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

time namespace は、ホストの wall clock ではなく、選択された monotonic 系の clocks を仮想化します。実際には、**`CLOCK_MONOTONIC`** と **`CLOCK_BOOTTIME`** に対する private offsets に加えて、密接に関連する **`CLOCK_MONOTONIC_COARSE`**、**`CLOCK_MONOTONIC_RAW`**、**`CLOCK_BOOTTIME_ALARM`** の view を提供します。**`CLOCK_REALTIME`** は仮想化しないため、`date` や certificate-expiry のロジックは、他の仕組みが干渉しない限り、引き続きホストの wall clock を参照します。

主な目的は、ホストの global time view を変えずに、プロセスが制御された elapsed-time offsets を観測できるようにすることです。これは checkpoint/restore ワークフロー、deterministic testing、advanced runtime behavior に有用です。mount や user namespaces のような意味での主要な isolation control では通常ありませんが、それでもプロセス環境をより self-contained にする助けになります。

攻撃者の観点では、この namespace は通常、直接的な breakout よりも **reconnaissance、timer skew、runtime understanding** に関連します。それでも、より多くの container runtimes や checkpoint/restore ワークフローがこれを明示的に要求できるようになっているため、重要です。

## Lab

ホスト kernel と userspace が対応していれば、次のように namespace を確認できます:
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
カーネルやツールのバージョンによってサポート状況は異なるため、このページは各ラボ環境で必ず見えることを期待するというより、仕組みを理解することに重点を置いています。重要な点は、`date` は引き続き host の wall clock を反映すべきであり、nonzero offsets が設定されたときに変化するのは monotonic/boottime ベースの値だということです。

### Creation Nuance

Time namespaces は mount、PID、network namespaces と比べて少し特殊です:

- `unshare(CLONE_NEWTIME)` は **future children** のために新しい time namespace を作成します。
- 呼び出した task は現在の time namespace のままです。
- そのため、runtime setup をデバッグする際は `/proc/<pid>/ns/time_for_children` のほうが `/proc/<pid>/ns/time` より重要になることがよくあります。

書き込み可能な期間も特殊です。`/proc/<pid>/timens_offsets` の offsets は、新しい time namespace が running tasks で完全に埋まる前に書き込まなければなりません。実際には runtimes は、namespace 作成と最終 payload の起動の間にある狭い setup window の間にこれを行います。そこですでに task が running している場合、後からの書き込みは `EACCES` で失敗します。これが、low-level runtimes が time-namespace setup を、すでに起動済みの container process の内側から offsets をパッチしようとするのではなく、早期の bootstrap step として扱う理由です。

### Time Offsets

Linux time namespaces は `/proc/<pid>/timens_offsets` を通じて namespace ごとの offsets を公開します。形式は、初期 time namespace に対する相対的な秒/nanosecond の差分に、clock 名または ID を組み合わせたものです。

実際には、最も信頼できる user-facing な workflow は、`unshare` にそれらの offsets を書き込ませることです:
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
重要な点は正確なコマンド構文ではなく挙動です。つまり、container は host の wall clock を変更せずに、別の uptime に似た view を観測できます。

### `unshare` Helper Flags

最近の `util-linux` 版では、namespace 作成時に offsets を自動的に書き込む便利な flags が提供されています:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
これらのフラグは主に使い勝手の改善ですが、documentation、test harnesses、runtime wrappers でこの機能を認識しやすくもします。

## Runtime Usage

Time namespaces は mount や PID namespaces ほど一般的に使われておらず、より新しいものです。OCI Runtime Specification v1.1 では `time` namespace と `linux.timeOffsets` フィールドの明示的なサポートが追加され、modern runtimes はそのデータを kernel bootstrap flow にマッピングできます。最小限の OCI fragment は次のようになります:
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
これは重要です。というのも、time namespacing がニッチな kernel の primitive から、runtimes が移植性をもって要求できるものへと変わるからです。また、runtime の内部で明示的な synchronization step が必要になる理由も説明できます。offset は、container payload が新しい namespace に完全に入る前に `/proc/<pid>/timens_offsets` に書き込まれなければなりません。

CRIU のような checkpoint/restore スタックは、これが存在する主な実世界の理由の1つです。time namespaces がなければ、一時停止された workload を復元したとき、monotonic clock と boot-time clock が、workload が suspended されていた時間分だけ跳ね上がってしまいます。

## Security Impact

time namespace を中心とした classic breakout の話は、他の namespace type と比べると少なめです。ここでのリスクは、time namespace が直接 escape を可能にすることというよりも、読者がそれを完全に無視してしまい、その結果、advanced runtimes が process behavior をどのように shaping しているかを見落とすことです。

特殊な環境では、変更された monotonic や boottime の view が以下に影響することがあります:

- timeout と retry の behavior
- watchdogs と lease logic
- `timerfd`, `nanosleep`, `clock_nanosleep` の behavior
- checkpoint/restore forensics
- elapsed-time telemetry と uptime-based heuristics

したがって、これが最初に abuse する namespace であることは稀ですが、assessment 中に「ありえない」タイミングの behavior を十分に説明しうるものです。

## Abuse

ここに直接的な breakout primitive は通常ありませんが、変更された clock behavior は、execution environment の理解、advanced runtime features の特定、そして wall clock time ではなく monotonic clocks を基準に測定される timer-based logic の発見に役立つことがあります:
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
2つのprocessを比較している場合、ここでの差異は、奇妙なtiming behavior、checkpoint/restore artifacts、またはenvironment-specificなlogging mismatchを説明するのに役立ちます。

実用的なattacker-relevantな観点:

- monotonic clocksを使って実装されたbackoff、sleep、またはwatchdog logicを混乱させる
- `/proc/uptime` と timer-driven behavior が host-side の wall-clock expectations と食い違う理由を説明する
- CRIU/checkpoint-restore workflows やその他の advanced runtime features を認識する
- `nsenter -T -t <pid> -- ...` で target の time namespace に join することで、debugging や post-exploitation のために container-local な timer behavior を再現できる環境を見つける

Impact:

- ほとんど常に reconnaissance または environment understanding
- logging、uptime、checkpoint/restore の anomaly を説明するのに有用
- monotonic-time-based な sleeps、retries、timers の分析に有用
- 通常、これ自体が直接の container-escape mechanism になるわけではない

重要なabuse nuanceは、time namespaces は `CLOCK_REALTIME` を virtualize しないため、attacker が host の wall clock を偽装したり、system-wide に certificate-expiry checks を直接壊したりすることはできない、という点です。主な価値は、monotonic-time-based な logic を混乱させること、environment-specific な bugs を再現すること、または advanced runtime behavior を理解することにあります。

## Checks

これらの checks は主に、runtime がそもそも private time namespace を使っているか、そして実際に nonzero offsets を設定しているかを確認することに関するものです。
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
ここで興味深いのは次の点です。

- 多くの環境では、これらの値は即座にセキュリティ上の問題にはなりませんが、specialized runtime feature が使われているかどうかは分かります。
- `time_for_children` が `time` と異なる場合、呼び出し元は child-only の time namespace を用意しているが、自分自身はそこに入っていない可能性があります。
- `date` が host と一致しているのに monotonic/boottime ベースの値が一致しない場合、wall-clock tampering ではなく time namespacing を見ている可能性が高いです。
- 2つの process を比較している場合、ここでの違いが timing の混乱や checkpoint/restore の挙動を説明することがあります。

ほとんどの container breakout では、time namespace は最初に調べる control ではありません。それでも、完全な container-security セクションでは触れておくべきです。なぜなら、これは modern kernel model の一部であり、advanced runtime scenarios では時々重要になるからです。

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}

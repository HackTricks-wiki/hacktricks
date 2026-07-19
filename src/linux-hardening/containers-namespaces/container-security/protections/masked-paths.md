# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths は、特に機密性の高い kernel-facing な filesystem location を、上から bind-mount したり、その他の方法でアクセス不能にしたりすることで、container から隠す runtime 保護機能です。目的は、通常の application が必要としない interface、特に procfs 内の interface と workload が直接やり取りするのを防ぐことです。

これは、多くの container escape や host に影響を与える手法が、`/proc` や `/sys` 配下の特殊な file を読み書きすることから始まるため重要です。これらの location が masked になっている場合、container 内で code execution を取得した後でも、attacker は kernel control surface の有用な部分に直接アクセスできません。

## Operation

Runtime は通常、次のような selected path を mask します。

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

正確な list は runtime と host の configuration によって異なります。重要なのは、host 上には依然として存在していても、container から見た場合、その path がアクセス不能になるか、別のものに置き換えられるという点です。

## Lab

Docker が公開している masked-path configuration を確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
ワークロード内で実際のマウント動作を確認します：
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## セキュリティへの影響

マスキングは主要な isolation boundary を作るものではありませんが、post-exploitation で価値の高いいくつかの標的を取り除きます。マスキングがない場合、侵害されたコンテナから kernel state を調査したり、機密性の高い process や keying の情報を読み取ったり、アプリケーションから決して見えるべきではない procfs/sysfs オブジェクトとやり取りしたりできる可能性があります。

## 設定ミス

主な誤りは、利便性やデバッグのために広範なパスのクラスを unmask することです。Podman では、`--security-opt unmask=ALL` や対象を限定した unmasking として現れることがあります。Kubernetes では、過度に広範な proc の公開が `procMount: Unmasked` によって発生する場合があります。もう1つの深刻な問題は、bind mount を通じてホストの `/proc` や `/sys` を公開することです。これにより、コンテナから見える範囲を縮小するという考え方自体が完全に回避されます。

## Abuse

マスキングが弱い、または存在しない場合は、まず直接到達可能な機密性の高い procfs/sysfs パスを特定します。
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
マスクされているはずのパスにアクセスできる場合は、注意深く調査します：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
これらのコマンドで確認できること：

- `/proc/timer_list` は、ホストのタイマーおよびスケジューラのデータを露出させる可能性があります。これは主に reconnaissance primitive ですが、通常は隠されている kernel-facing information をコンテナから読み取れることを確認できます。
- `/proc/keys` は、はるかに機密性が高い情報を含みます。ホストの設定によっては、keyring エントリ、key の説明、kernel keyring subsystem を使用するホストサービス間の関係が露出する可能性があります。
- `/sys/firmware` は、boot mode、firmware interface、platform の詳細を特定するのに役立ちます。これらは host fingerprinting や、workload が host-level state を認識しているかどうかの把握に有用です。
- `/proc/config.gz` は、実行中の kernel configuration を露出させる可能性があります。これは、public kernel exploit の前提条件との照合や、特定の feature にアクセスできる理由の把握に役立ちます。
- `/proc/sched_debug` は scheduler state を露出させます。また、PID namespace によって無関係な process information が完全に隠されるはずだという直感的な期待を、しばしば覆します。

興味深い結果には、これらのファイルを直接読み取れること、それらのデータが制限されたコンテナビューではなくホストに属していることを示す証拠、またはデフォルトで一般的に mask されている他の procfs/sysfs の場所へアクセスできることが含まれます。

## Checks

これらの checks の目的は、runtime が意図的にどの path を隠したのか、また現在の workload が依然として縮小された kernel-facing filesystem を認識しているかどうかを判断することです。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
ここで注目すべき点:

- 強化された runtime では、長い masked-path リストは通常の状態です。
- 機密性の高い procfs エントリに masking がない場合は、詳しく調査する価値があります。
- 機密性の高い path にアクセスでき、さらに container に強力な capabilities や広範な mounts がある場合、その露出はより重大です。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動による弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker はデフォルトの masked path リストを定義します | host の proc/sys mounts の公開、`--privileged` |
| Podman | デフォルトで有効 | 手動で unmask されない限り、Podman はデフォルトの masked paths を適用します | `--security-opt unmask=ALL`、対象を指定した unmasking、`--privileged` |
| Kubernetes | runtime のデフォルトを継承 | Pod の設定によって proc の露出が弱められない限り、基盤となる runtime の masking 動作を使用します | `procMount: Unmasked`、privileged workload パターン、広範な host mounts |
| Kubernetes 上の containerd / CRI-O | runtime のデフォルト | 通常、上書きされない限り OCI/runtime の masked paths を適用します | runtime の直接的な設定変更、同じ Kubernetes の弱体化パターン |

Masked paths は通常、デフォルトで存在します。主な運用上の問題は runtime に存在しないことではなく、意図的な unmasking や、保護を無効化する host bind mounts です。
{{#include ../../../../banners/hacktricks-training.md}}

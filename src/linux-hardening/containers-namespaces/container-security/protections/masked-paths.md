# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths は、特に機密性の高い kernel-facing filesystem の場所を、bind-mount で上書きしたり、その他の方法でアクセス不能にしたりして、container から隠す runtime の保護機能です。目的は、特に procfs 内にある、通常の application が直接操作する必要のない interface と workload が直接やり取りするのを防ぐことです。

これは、多くの container escape や host に影響を与える手法が、`/proc` または `/sys` 配下の特殊なファイルを読み書きすることから始まるため重要です。これらの場所が masked であれば、attacker は container 内で code execution を取得した後でも、kernel の control surface の有用な部分に直接アクセスできなくなります。

## Operation

Runtime は一般的に、次のような選択された path を mask します。

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

正確なリストは runtime と host の configuration によって異なります。重要なのは、host 上にはその path が存在していても、container から見るとアクセス不能になるか、別のものに置き換えられるという点です。

## Lab

Docker に公開されている masked-path configuration を確認します。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
workload 内部の実際の mount 動作を確認します:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Security Impact

Masking は主要な isolation boundary を作るものではありませんが、価値の高い post-exploitation targets を複数排除します。Masking がなければ、侵害された container から kernel state を調査したり、機密性の高い process 情報や keying information を読み取ったり、本来 application から見えてはならない procfs/sysfs オブジェクトを操作したりできる可能性があります。

## Misconfigurations

主な問題は、利便性や debugging のために広範な path 群の mask を解除することです。Podman では、`--security-opt unmask=ALL` や対象を限定した unmasking として現れることがあります。Kubernetes では、過度に広範な proc exposure が `procMount: Unmasked` によって発生する場合があります。もう1つの深刻な問題は、bind mount を通じて host の `/proc` や `/sys` を公開することです。これにより、container view を縮小するという考え方そのものが完全に回避されます。

## Abuse

Masking が弱い、または存在しない場合は、まず直接到達可能な機密性の高い procfs/sysfs path を特定します。
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
マスクされているはずのパスにアクセスできる場合は、慎重に調査する：
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
これらのコマンドで明らかになること：

- `/proc/timer_list` は、ホストの timer および scheduler データを露出させる可能性があります。これは主に reconnaissance primitive ですが、通常は隠されている kernel-facing information を container から読み取れることを確認できます。
- `/proc/keys` は、はるかに機密性が高い情報を扱います。ホストの設定によっては、keyring entries、key descriptions、および kernel keyring subsystem を使用するホストサービス間の関係が明らかになる可能性があります。
- `/sys/firmware` は、boot mode、firmware interfaces、platform details の特定に役立ちます。これらは host fingerprinting や、workload が host-level state を認識しているかどうかの確認に有用です。
- `/proc/config.gz` は、実行中の kernel configuration を明らかにする可能性があります。これは、公開されている kernel exploit の前提条件との照合や、特定の feature にアクセスできる理由の把握に役立ちます。
- `/proc/sched_debug` は scheduler state を露出させます。また、PID namespace によって無関係な process information が完全に隠されるはずだという直感的な想定を覆すこともあります。

興味深い結果には、これらのファイルから直接読み取れる情報、データが制限された container view ではなく host に属していることを示す証拠、またはデフォルトで一般的に mask されている他の procfs/sysfs locations へのアクセスが含まれます。

## Checks

これらの checks の目的は、runtime がどの paths を意図的に隠しているか、また現在の workload が reduced kernel-facing filesystem を依然として認識しているかを確認することです。
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
ここで注目すべき点：

- 強化された runtime では、長い masked-path リストは通常のものです。
- 機密性の高い procfs エントリに masking がない場合は、詳しく調査する価値があります。
- 機密性の高いパスにアクセス可能で、さらにコンテナに強力な capabilities や広範な mounts がある場合、その exposure はより重要になります。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker はデフォルトの masked path リストを定義する | host の proc/sys mounts の公開、`--privileged` |
| Podman | デフォルトで有効 | Podman は手動で unmask されない限り、デフォルトの masked paths を適用する | `--security-opt unmask=ALL`、対象を指定した unmasking、`--privileged` |
| Kubernetes | runtime のデフォルトを継承 | Pod の設定によって proc の exposure が弱められない限り、基盤となる runtime の masking 動作を使用する | `procMount: Unmasked`、privileged workload パターン、広範な host mounts |
| containerd / CRI-O under Kubernetes | runtime のデフォルト | 通常、上書きされない限り OCI/runtime の masked paths を適用する | runtime の直接的な設定変更、Kubernetes における同様の弱体化経路 |

Masked paths は通常、デフォルトで存在します。主な運用上の問題は runtime に存在しないことではなく、意図的な unmasking や、保護を無効化する host bind mounts です。

{{#include ../../../../banners/hacktricks-training.md}}

# マスクされたパス

{{#include ../../../../banners/hacktricks-training.md}}

マスクされたパスは、ランタイムの保護機構で、特に機密性の高いカーネルに面したファイルシステム上の場所をコンテナから隠すもので、これらを上書きするためにbind-mountingしたり、その他の方法でアクセス不能にします。目的は、ワークロードが通常のアプリケーションが必要としないインターフェイスと直接やり取りするのを防ぐことで、特にprocfs内での操作を想定しています。

## 動作

ランタイムは一般的に次のような選択されたパスをマスクします:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

正確なリストはランタイムやホストの設定によります。重要なのは、そのパスがホスト上には存在していても、コンテナ側から見るとアクセス不能になったり置き換えられたりする点です。

## ラボ

Docker が公開する masked-path 設定を確認する:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
ワークロード内での実際のマウント挙動を確認する:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## セキュリティへの影響

マスキングは主要な隔離境界を作るものではありませんが、いくつかの価値の高い post-exploitation targets を排除します。マスキングがなければ、侵害されたコンテナはカーネルの状態を調査したり、機密のプロセスや鍵情報を読み取ったり、アプリケーションから決して見えてはならない procfs/sysfs オブジェクトとやり取りすることができる可能性があります。

## 誤設定

主な誤りは、利便性やデバッグのために広範なパスをアンマスクすることです。Podman ではこれは `--security-opt unmask=ALL` やターゲットを限定したアンマスクとして現れることがあります。Kubernetes では、過度に広い proc の露出が `procMount: Unmasked` を介して現れることがあります。もう一つ深刻な問題は、ホストの `/proc` や `/sys` を bind mount で公開することで、これは縮小されたコンテナビューという考えを完全に回避してしまいます。

## 悪用

マスキングが弱いか存在しない場合、まず直接アクセス可能な機密性の高い procfs/sysfs パスを特定することから始めます:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
本来マスクされているはずのパスにアクセスできる場合は、注意深く調査してください:
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## Checks

The point of these checks is to determine which paths the runtime intentionally hid and whether the current workload still sees a reduced kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
What is interesting here:

- 厳格化されたランタイムでは長い masked-path リストが通常である。
- 敏感な procfs エントリに対するマスキングが欠けている場合は詳しく調査すべきである。
- 敏感なパスにアクセス可能で、かつコンテナが強い capabilities や広範なマウントを持つ場合、その露出はより重大になる。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker はデフォルトの masked path リストを定義する | ホストの proc/sys マウントを露出させること、 `--privileged` |
| Podman | デフォルトで有効 | Podman は手動で unmask されない限りデフォルトの masked paths を適用する | `--security-opt unmask=ALL`、ターゲットを絞った unmask、 `--privileged` |
| Kubernetes | ランタイムのデフォルトを継承 | Pod の設定が proc の露出を弱めない限り、基盤となるランタイムのマスキング挙動を利用する | `procMount: Unmasked`、privileged なワークロードパターン、広範なホストマウント |
| containerd / CRI-O under Kubernetes | ランタイムのデフォルト | 上書きされない限り通常は OCI/ランタイムの masked paths を適用する | ランタイム設定の直接変更、Kubernetes と同様の弱体化経路 |

Masked paths は通常デフォルトで存在する。主要な運用上の問題はランタイムに存在しないことではなく、意図的な unmask や保護を無効化するホストの bind mounts である。

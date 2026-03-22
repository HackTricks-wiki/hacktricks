# マスクされたパス

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths はランタイムの保護機能で、特にカーネルに面した機密性の高いファイルシステムの場所をコンテナから隠すために、それらを上書きする bind-mounting を行ったり、その他の方法でアクセス不能にします。目的は、特に procfs 内で、通常のアプリケーションが必要としないインターフェイスにワークロードが直接アクセスするのを防ぐことです。

これは、多くの container escapes やホストに影響を与える手法が `/proc` や `/sys` 以下の特殊なファイルを読み書きすることから始まるため重要です。これらの場所がマスクされていると、コンテナ内でコード実行を得た後でも、攻撃者はカーネルの制御面の有用な部分へ直接アクセスできなくなります。

## 動作

ランタイムは一般に次のようなパスをマスクします:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

正確な一覧はランタイムやホストの設定によって異なります。重要なのは、そのパスがホスト上には存在していても、コンテナの観点からはアクセス不能になったり置き換えられたりする点です。

## ラボ

Docker が公開する masked-path 設定を確認する:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
ワークロード内で実際のマウント動作を確認する:
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## セキュリティへの影響

マスキングは主要な隔離境界を作るものではありませんが、ポストエクスプロイテーションで価値の高い複数のターゲットを取り除きます。マスキングがないと、侵害されたコンテナはカーネル状態を調べたり、機密のプロセス情報や鍵情報を読み取ったり、アプリケーションに見えてはならない procfs/sysfs オブジェクトとやり取りしたりできる可能性があります。

## 誤設定

主なミスは、利便性やデバッグ目的で広範なパスの unmasking を行うことです。Podman ではこれが `--security-opt unmask=ALL` のように、または特定の unmasking として現れることがあります。Kubernetes では、過度に広い proc の公開が `procMount: Unmasked` によって現れることがあります。もう一つの深刻な問題は、ホストの `/proc` や `/sys` を bind mount 経由で公開することで、これは縮小されたコンテナのビューという考え方を完全に回避します。

## 悪用

マスキングが弱い、または存在しない場合は、まずどの敏感な procfs/sysfs パスが直接到達可能かを特定することから始めます:
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
マスクされたはずのパスにアクセスできる場合は、注意深く確認してください:
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
興味深い点:

- ハードニングされたランタイムでは長いマスクされたパス一覧は通常である。
- 敏感な procfs エントリにマスキングがない場合は、より詳しく調査する価値がある。
- もし敏感なパスがアクセス可能で、かつコンテナが強い capabilities または広範なマウントを持っている場合、露出の重要度は増す。

## ランタイムのデフォルト

| ランタイム / プラットフォーム | デフォルト状態 | デフォルトの動作 | よくある手動の弱体化方法 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker はデフォルトのマスクされたパス一覧を定義する | ホストの proc/sys マウントを公開すること、`--privileged` |
| Podman | デフォルトで有効 | Podman は手動でマスク解除されない限りデフォルトのマスクされたパスを適用する | `--security-opt unmask=ALL`, ターゲットを絞ったマスク解除, `--privileged` |
| Kubernetes | ランタイムのデフォルトを継承 | Pod の設定が proc の露出を弱めない限り、基盤のランタイムのマスキング動作を使用する | `procMount: Unmasked`, 特権ワークロードパターン、広範なホストマウント |
| containerd / CRI-O（Kubernetes下） | ランタイムのデフォルト | 通常は上書きされない限りOCI/ランタイムのマスクされたパスを適用する | ランタイム設定の直接変更、Kubernetes と同様の弱体化手段 |

マスクされたパスは通常デフォルトで存在する。運用上の主要な問題はランタイムからの欠如ではなく、意図的なマスク解除や保護を無効にするホストのバインドマウントである。
{{#include ../../../../banners/hacktricks-training.md}}

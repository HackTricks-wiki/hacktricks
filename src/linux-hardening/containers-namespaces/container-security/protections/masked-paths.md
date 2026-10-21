# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths は、特に機密性の高いカーネル向けファイルシステムの場所を、bind mount で覆ったり、その他の方法でアクセス不能にしたりして、コンテナから隠すランタイム保護機能です。OCI runtime specification では、`maskedPaths` をコンテナ内から読み取りできないようにする絶対パスとして定義しています。 <sup>[[1]](#references)</sup>

これは、多くのコンテナエスケープやホストに影響を与える手法が、`/proc` や `/sys` 配下にある特殊ファイルの読み書きから始まるため重要です。これらの場所がマスクされていれば、攻撃者はコンテナ内でコード実行を得た後でも、カーネル制御面の有用な領域に直接アクセスできません。

## 動作

ランタイムは、一般的に次のようなパスを選択してマスクします。

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

正確なリストは、ランタイムとホストの設定によって異なります。重要なのは、ホスト上には引き続き存在していても、コンテナから見るとそのパスにアクセスできないか、別のものに置き換わるという点です。

## ラボ

Docker が公開する masked-path の設定を確認します。

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

ワークロード内で実際のマウント動作を確認します:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

一覧にあるパスが必ずしも読み取り可能とは限りません。runc はファイルを `/dev/null` の bind mount で、ディレクトリを読み取り専用の空の tmpfs でマスクできます。`ls` が成功するかどうかだけでなく、正確なマウントポイントを確認してください。 <sup>[[4]](#references)</sup>

## Security Impact

マスキングは主要な分離境界を作るものではありませんが、侵害後の標的として価値の高いパスをいくつか利用できなくします。マスキングがなければ、侵害されたコンテナからカーネルの状態を調べたり、機密性の高いプロセス情報や鍵情報を読み取ったり、アプリケーションに決して公開すべきでない procfs/sysfs オブジェクトにアクセスしたりできる可能性があります。

## Misconfigurations

主な誤りは、利便性やデバッグのために広範なパスをマスク解除することです。Podman では、`--security-opt unmask=ALL` や対象を指定したマスク解除がこれに当たります。 <sup>[[2]](#references)</sup> Kubernetes では、広範な proc の公開が `procMount: Unmasked` として設定されている場合があります。現在の Kubernetes では、この設定に `spec.hostUsers: false`（ユーザー名前空間）が必須ですが、バージョン 1.12～1.29 ではこの要件は適用されていませんでした。 <sup>[[3]](#references)</sup> もうひとつの重大な問題は、ホストの `/proc` や `/sys` を bind mount で公開することです。これにより、コンテナ内で見える範囲を縮小するという考え方が完全に無効になります。

## Abuse

マスキングが不十分、または存在しない場合は、まず機密性の高い procfs/sysfs パスのうち、直接アクセスできるものを特定します。

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

マスクされているはずのパスにアクセスできる場合は、慎重に調査してください:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

これらのコマンドで明らかになること:

- `/proc/timer_list` は、ホストのタイマーおよびスケジューラのデータを露出する可能性があります。主に偵察の手段ですが、通常は隠されているカーネル関連情報をコンテナから読み取れることを確認できます。
- `/proc/keys` は、LSM のチェックに従い、読み取り側に **view** 権限があるキーのメタデータのみを一覧表示します。キーの種類や説明が明らかになる可能性はありますが、キーのペイロードは出力しません。 <sup>[[6]](#references)</sup>
- `/sys/firmware` は、ホストのフィンガープリント取得に役立つ起動モード、ファームウェアインターフェース、プラットフォームの詳細を特定するのに役立ちます。また、ワークロードからホストレベルの状態が見えているかどうかを把握する手がかりにもなります。
- `/proc/config.gz` から実行中のカーネル設定が明らかになる場合があります。これは、公開されているカーネル exploit の前提条件との照合や、特定の機能にアクセスできる理由の把握に役立ちます。
- `/proc/sched_debug` はスケジューラの状態を露出し、PID namespace によって無関係なプロセス情報が完全に隠されるという直感的な想定を覆すことがよくあります。

注目すべき結果として、これらのファイルを直接読み取れること、制限されたコンテナ内のビューではなくホストのデータであることを示す証拠、または通常はデフォルトでマスクされている他の procfs/sysfs の場所にアクセスできることが挙げられます。

### コンテナ起動時のマスク元の race

脆弱な runc 実装では、ファイルのマスクにコンテナの `/dev/null` inode が使われます。parallel BuildKit steps を含む、共有マウントを使ったコンテナを同時に起動できる攻撃者は、起動時に race を発生させ、runc が `/dev/null` をマスク対象の procfs ファイルに bind する前に削除できます。その結果、ランタイムはマスク先が存在しないかのように、存在しない **ソース** を扱い、これらのファイルマスクを黙ってスキップします。この問題はランタイムのセットアップ中に race が発生するかどうかに依存します。起動後に `/dev/null` を削除しても、すでに設定されたマスクは解除されません。 <sup>[[4]](#references)</sup>

制御されたテストの後、新しいコンテナ内で、要求したマスクリストと正確なマウントポイントを照合してください。 <sup>[[4]](#references)</sup> `findmnt -M` は親マウントにフォールバックせず、指定されたマウントポイントを確認します。`findmnt` がない場合は、`/proc/self/mountinfo` を調べてください。 <sup>[[5]](#references)</sup> `ls` が成功することや `cat` の出力が空であることは、マスクが存在しない証明にはなりません。 <sup>[[4]](#references)</sup>

[以下のチェック](#checks)を使って、要求したマスクと新しいコンテナ内の正確なマウントを照合してください。

ファイルマスクがスキップされると、通常の権限と LSM ポリシーが許可する範囲で procfs のデータが露出する可能性があります。これだけで `/proc/sys` が書き込み可能になるわけではありません。これは別個の[read-only-path](read-only-paths.md)制御です。bind mount を書き込み可能な procfs の対象にリダイレクトできる、別個の `/dev/null` symlink substitution については、[PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs)で説明しています。 <sup>[[4]](#references)</sup>

## チェック

これらのチェックの目的は、ランタイムが意図的に隠したパスと、現在のワークロードからカーネル関連ファイルシステムの制限されたビューが依然として見えているかどうかを確認することです。

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

正確な mount チェックを使用してください。masked file が存在していても、読み取り結果が `/dev/null` からの空の結果になることがあります。mountpoint が存在しない場合は調査すべき検出事項ですが、それだけでホストデータを読み取れる証拠にはなりません。 <sup>[[4]](#references)[[5]](#references)</sup>

ここで注目すべき点:

- hardened runtime では、マスク済みパスのリストが長いのは通常です。
- 機密性の高い procfs エントリのマスキングが欠けている場合は、詳しく調査する必要があります。
- 機密パスにアクセスでき、コンテナに強力な capabilities や広範な mount もある場合、露出の重要性はさらに高まります。

## Runtime Defaults

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | Docker がデフォルトのマスク済みパスリストを定義 | ホストの proc/sys mount の公開、`--privileged` |
| Podman | デフォルトで有効 | 手動で unmask しない限り、Podman はデフォルトのマスク済みパスを適用 | `--security-opt unmask=ALL`、特定パスの unmask、`--privileged` |
| Kubernetes | runtime のデフォルトを継承 | Pod 設定で proc の露出を弱めない限り、基盤となる runtime のマスキング動作を使用 | `procMount: Unmasked`（現行リリースでは `hostUsers: false` が必要）、privileged workload のパターン、広範なホスト mount |
| Kubernetes 上の containerd / CRI-O | runtime のデフォルト | 通常、上書きされない限り OCI/runtime のマスク済みパスを適用 | runtime の設定を直接変更、同じ Kubernetes の弱体化手段 |

マスク済みパスは通常、デフォルトで設定されています。運用上の主な問題は runtime での設定漏れではなく、意図的な unmask や、保護を無効化するホスト bind mount です。

## References

- [1] [Open Container Initiative - Linux コンテナ設定: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman ドキュメント - `podman run` のセキュリティオプション](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes ドキュメント - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc アドバイザリ: masked-path mount source race](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) マニュアル](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) マニュアル](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}

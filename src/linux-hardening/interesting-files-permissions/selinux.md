# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinuxは**ラベルベースの強制アクセス制御（MAC）**システムです。実際には、DACの権限、グループ、Linux capabilitiesがある操作に十分に見えても、要求されたクラス／権限で**ソースコンテキスト**から**ターゲットコンテキスト**へのアクセスが許可されていない場合、カーネルがその操作を拒否することがあります。<sup>[[1]](#references)</sup>

コンテキストは通常、次のような形式です。<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

privesc の観点では、`type`（プロセスでは domain、オブジェクトでは type）が通常、最も重要なフィールドです。<sup>[[1]](#references)</sup>

- プロセスは、`unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` などの **domain** で実行される
- ファイルやソケットは、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` などの **type** を持つ
- ポリシーによって、ある domain が別の domain や type に対して読み取り、書き込み、実行、遷移できるかが決まる

## 迅速な列挙

SELinux が有効な場合は、早い段階で列挙しましょう。一般的な Linux の privesc 経路が失敗する理由や、「無害な」SELinux ツールをラップする特権付き wrapper が実際には重要である理由を説明できるからです。<sup>[[1]](#references)</sup>

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

有用な追加確認事項:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>

```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```

興味深い調査結果:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` または `Permissive` モードでは、境界としての SELinux の価値の大部分が失われます。
- `unconfined_t` は通常、SELinux が有効でも、そのプロセスを実質的に制限していないことを意味します。
- `default_t`、`file_t`、またはカスタムパスに付いた明らかに不適切なラベルは、ラベル設定の誤りやデプロイの不備を示していることがよくあります。
- `file_contexts.local` のローカルオーバーライドはポリシーのデフォルトより優先されるため、慎重に確認してください。

## ポリシー分析

次の2つの問いに答えられると、SELinux への攻撃やバイパスがはるかに容易になります。

1. **現在のドメインから何にアクセスできるか？**
2. **どのドメインへ遷移できるか？**

この分析に最も役立つツールは、`sepolicy` と **SETools** (`seinfo`、`sesearch`、`sedta`) です:<sup>[[2]](#references)[[9]](#references)</sup>

```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```

これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**制限されたユーザー**を使用している場合に特に役立ちます。その場合は、次を確認してください:<sup>[[3]](#references)</sup>

- `semanage login -l` によるユーザーマッピング
- `semanage user -l` で許可されているロール
- `sysadm_t`、`secadm_t`、`webadm_t` など、到達可能な管理者ドメイン
- `ROLE=` または `TYPE=` を使用する `sudoers` エントリ

`sudo -l` に次のようなエントリが含まれている場合、SELinux は権限境界の一部です:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

また、`newrole` が利用可能かどうかも確認してください:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` と `newrole` は自動的に悪用可能なわけではありませんが、特権ラッパーや `sudoers` ルールによって、より有利な role/type を選択できる場合は、価値の高い権限昇格プリミティブになります。<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### 書き込み可能な遷移エントリーポイントを監査する

遷移グラフは、ポリシーを調査する手がかりにすぎません。これを攻撃経路にするには、より有用なドメインに入る実行ファイルの type を特定し、そのラベルが付いた実行ファイルを変更できるか、親ディレクトリ経由で置き換えられるかを確認します。<sup>[[9]](#references)[[20]](#references)</sup> 自動的な `execve` 遷移には、適用可能な `type_transition` ルール、ソースドメインの execute アクセス、ターゲットドメインの `entrypoint` アクセス、およびドメイン間の遷移権限が必要です。<sup>[[20]](#references)</sup> ターゲットドメインで SELinux のアクセス権が得られることはありますが、実行によって Linux UID 自体が変わるわけではありません。[SUID/SGID and ACLs](suid-sgid-and-acl-triage.md) は別途確認してください。<sup>[[20]](#references)[[21]](#references)</sup>

報告された entrypoint type を使って関連ルールを確認し、次にパスとその親ディレクトリに書き込みアクセスがあるかを調べます。<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

エントリポイントの type を実際の実行可能ファイルのパスと関連付けます。ポリシー上のエッジが到達可能と判断する前に、DAC、ACL、ファイルまたは親ディレクトリへの SELinux の書き込み権限、ファイルのラベル、条件付き boolean を確認してください。<sup>[[20]](#references)[[22]](#references)</sup> パスがその場で編集されず置き換えられる場合は、新しい inode のコンテキストを確認してください。ファイルシステムのラベルは拡張属性として保存されるため、置き換えたファイルにはエントリポイントの type が引き継がれないことがあります。<sup>[[21]](#references)</sup> SELinux 対応プログラムは `setexeccon` で遷移を要求できるため、自動的な `type_transition` ルールがないからといって、あらゆる遷移が不可能とは限りません。<sup>[[20]](#references)</sup>

## ファイル、ラベルの再設定、価値の高い設定ミス

一般的な SELinux ツールのうち、運用上もっとも重要な違いは次のとおりです。<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: 特定のパスのラベルを一時的に変更
- `semanage fcontext`: パスとラベルの対応ルールを永続化
- `restorecon` / `setfiles`: ポリシーのデフォルトラベルを再適用

これは privesc の際に非常に重要です。**ラベルの再設定は単なる見た目の変更ではありません**。ファイルを「ポリシーによってブロックされている」状態から、「特権を持つ制限付きサービスが読み取り・実行できる」状態に変える可能性があります。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

ローカルのラベル再設定ルールと、ラベルのずれを確認してください。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

微妙ですが有用な点が1つあります。通常の `restorecon` では、疑わしいラベルが常に完全に元に戻るとは限りません。対象の type が `customizable_types` に含まれている場合、完全にリセットするには `-F` が必要になることがあります。攻撃者の視点では、これが、通常とは異なる `chcon` が「すでに restorecon を実行した」という簡単なクリーンアップの後も残ることがある理由です。<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

`sudo -l`、root wrapper、automation script、または file capabilities で探す価値の高いコマンド:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

いずれかの MAC capability が見つかった場合は、[Linux capabilities page](linux-capabilities.md) も確認してください。Linux capabilities のドキュメントでは、`cap_mac_admin` と `cap_mac_override` は Smack 固有と説明されています。そのため、名前だけを見て SELinux をバイパスできると考えないでください。<sup>[[5]](#references)</sup>

特に注目すべきもの:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: パスに付与するラベルを永続的に変更する
- `restorecon` / `setfiles`: その変更を大規模に再適用する
- `semodule -i`: カスタムポリシーモジュールを読み込む
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに、1つのドメインを permissive にする
- `setsebool -P`: ポリシーの boolean を永続的に変更する
- `load_policy`: アクティブなポリシーを再読み込みする

これらは、多くの場合、単独で root を取得できる exploit ではなく、**補助的なプリミティブ**です。これらを使うと、次のことができます:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- 標的ドメインを permissive にする
- 自分のドメインと保護された type 間のアクセスを拡大する
- 攻撃者が制御するファイルのラベルを変更し、特権サービスが読み取りまたは実行できるようにする
- 既存のローカルのバグを悪用できる程度まで、制限されたサービスの保護を弱める

確認例:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

rootとしてポリシーモジュールをロードできれば、通常はSELinuxの境界を制御できます:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

そのため、post-exploitation 中は `audit2allow`、`semodule`、`semanage permissive` を機密性の高い管理者向けインターフェースとして扱うべきです。これらを使うと、従来の UNIX 権限を変更せずに、ブロックされていた一連の処理を気付かれないまま実行可能にできるためです。<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 隠れた拒否とモジュールの抽出

攻撃側がよく直面する厄介な問題として、予想される AVC 拒否ログが出ず、単純な `EACCES` だけで一連の処理が失敗することがあります。`dontaudit` ルールによって、必要な権限が正確に隠されている可能性があります。`sudo` や別の特権ラッパーを介して `semodule` を実行できる場合は、一時的に `dontaudit` を無効化することで、何も手掛かりのない失敗を、ポリシーを特定するための明確な手掛かりに変えられます。<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

これは、ローカル管理者がすでに加えた変更を確認する際にも役立ちます。小規模なカスタムモジュールや、特定のドメインに対する permissive ルールが、対象サービスの挙動をベースポリシーから想定されるよりも大幅に緩くしていることはよくあります。<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## 監査の手がかり

AVC denial は、防御上のノイズにとどまらず、攻撃に役立つ手がかりとなることがよくあります。次のことが分かります。<sup>[[1]](#references)[[15]](#references)</sup>

- アクセスした対象オブジェクト／タイプ
- 拒否された権限
- 現在制御しているドメイン
- 小さなポリシー変更で攻撃チェーンが成立するかどうか

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

ローカル exploit や永続化の試みが、root に見える DAC 権限があるにもかかわらず `EACCES` や奇妙な「permission denied」エラーで失敗し続ける場合、その経路を諦める前に SELinux を確認する価値があります。<sup>[[1]](#references)</sup>

## SELinux ユーザー

通常の Linux ユーザーに加えて、SELinux ユーザーも存在します。ポリシーの一部として各 Linux ユーザーが SELinux ユーザーにマッピングされるため、システムはアカウントごとに異なるロールやドメインの許可を適用できます。<sup>[[3]](#references)</sup>

簡単な確認方法:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

多くの主流システムでは、ユーザーは `unconfined_u` にマッピングされており、ユーザーの confinement による実際の影響は小さくなっています。しかし、hardening された環境では、confined user にとって `sudo`、`su`、`newrole`、`runcon` がはるかに重要になることがあります。これは、**権限昇格の経路が UID 0 になることだけでなく、より適切な SELinux role/type に入ることに依存する場合がある**ためです。また、policy で基盤となる setuid の遷移が明示的に許可されていない限り、confined user は `sudo` や `su` を実行できない場合があることにも注意してください。そのため、`staff_u` + `sysadm_r` を使うホストでは、一見軽微な `sudo ROLE=` / `TYPE=` ルールが実際の権限境界になり得ます。<sup>[[3]](#references)</sup>

## コンテナ内の SELinux

コンテナ runtime は、一般的に workload を `container_t` などの confined domain で起動し、コンテナのコンテンツに `container_file_t` のラベルを付けます。コンテナのプロセスが脱出しても、コンテナのラベルが維持されていれば、ラベルの境界が保たれているため、ホストへの書き込みに失敗する場合があります。<sup>[[1]](#references)[[17]](#references)</sup>

簡単な例:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

`c647,c780` の部分は装飾ではありません。多くの container デプロイメントでは、runtime が MCS category を動的に割り当てるため、`container_t` として実行される2つの process も互いに分離されます。escape によって host namespace に入っても、元の category set が維持されている場合、category の不一致が原因で一部の host path が読み取り不可または書き込み不可のままになることがあります。<sup>[[17]](#references)</sup>

注目すべき最新の container 運用:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` は container の SELinux label による分離を無効にします
- `:z` / `:Z` を付けた bind mount は、共有または非共有の container 利用に合わせて host path の label を変更します
- host コンテンツを広範囲に relabel すると、それ自体がセキュリティ上の問題になる可能性があります

このページでは重複を避けるため、container の内容を簡潔にしています。container 固有の abuse case と runtime の例については、以下を確認してください。

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat docs: SELinux の使用](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux のポリシー分析ツール](https://github.com/SELinuxProject/setools)
- [3] [制限付きユーザーと非制限ユーザーの管理 - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run のドキュメント](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux container で Multi-Category Security を使うべき理由](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top のドキュメント](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux Notebook: Domain と Object の遷移](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: SELinux の使用](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) マニュアル](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

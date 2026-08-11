# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux は **label-based Mandatory Access Control (MAC)** システムです。実際には、DAC permissions、groups、Linux capabilities がある操作に十分に見える場合でも、**source context** が要求された class/permission で **target context** にアクセスすることを許可されていなければ、kernel はその操作を拒否できます。<sup>[[1]](#references)</sup>

context は通常、次のようになります。<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
権限昇格の観点では、`type`（プロセスの場合は domain、オブジェクトの場合は type）が通常、最も重要なフィールドです：<sup>[[1]](#references)</sup>

- プロセスは、`unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` などの **domain** で実行されます
- ファイルとソケットには、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` などの **type** があります
- Policy により、一方の domain が他方の domain へ read/write/execute/transition できるかどうかが決まります

## 迅速な列挙

SELinux が有効な場合は、早い段階で列挙してください。一般的な Linux 権限昇格パスが失敗する理由や、"無害な" SELinux tool をラップした特権 wrapper が実際には重要である理由を説明できるためです：<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
役立つ追加チェック:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
興味深い findings:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` または `Permissive` mode では、boundary としての SELinux の価値の大部分が失われます。
- `unconfined_t` は通常、SELinux が存在していても、その process を実質的に制約していないことを意味します。
- custom paths 上の `default_t`、`file_t`、または明らかに誤った labels は、誤った labeling や不完全な deployment を示していることがよくあります。
- `file_contexts.local` 内の local overrides は policy defaults より優先されるため、慎重に確認してください。

## Policy Analysis

SELinux は、次の2つの質問に答えられる場合、attack または bypass がはるかに容易になります。

1. **現在の domain は何に access できるか？**
2. **どの domain に transition できるか？**

これらに最も役立つ tools は、`sepolicy` と **SETools**（`seinfo`、`sesearch`、`sedta`）です:<sup>[[2]](#references)[[9]](#references)</sup>
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
これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**confined users** を使用している場合に特に有用です。その場合は、以下を確認します。<sup>[[3]](#references)</sup>

- `semanage login -l` による user mappings
- `semanage user -l` による許可された roles
- `sysadm_t`、`secadm_t`、`webadm_t` などの到達可能な admin domains
- `ROLE=` または `TYPE=` を使用する `sudoers` entries

`sudo -l` に次のような entries が含まれている場合、SELinux は privilege boundary の一部です。<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能かどうかも確認します:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的に exploit 可能というわけではありませんが、privileged wrapper または `sudoers` ルールによって、より適切な role/type を選択できる場合、高価値な escalation primitive になります。<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files、Relabeling、および High-Value Misconfigurations

一般的な SELinux tools における最も重要な運用上の違いは次のとおりです:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: 特定の path に対する一時的な label 変更
- `semanage fcontext`: 永続的な path-to-label rule
- `restorecon` / `setfiles`: policy/default label を再度適用

これは privesc 中に非常に重要です。なぜなら、**relabeling は単なる見た目上の変更ではない**からです。これにより、ファイルを「policy によって blocked」な状態から「privileged な confined service によって readable/executable」な状態へ変更できます。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

local relabel rules と relabel drift を確認します:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
微妙ですが有用な点が1つあります。通常の `restorecon` では、疑わしいラベルが**常に完全に元へ戻るとは限りません**。対象のタイプが `customizable_types` に含まれている場合、完全なリセットを強制するために `-F` が必要になることがあります。攻撃者の視点では、これは、通常の「すでに restorecon を実行した」というクリーンアップを行っても、通常とは異なる `chcon` が残る場合がある理由を説明します。<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、または file capabilities 内で探索すべき高価値コマンド:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
いずれかの MAC capability が見つかった場合は、[Linux capabilities page](linux-capabilities.md) も照合してください。Linux capabilities のドキュメントでは、`cap_mac_admin` と `cap_mac_override` は Smack 固有のものとして説明されているため、名前だけを根拠に SELinux を bypass できると判断しないでください。<sup>[[5]](#references)</sup>

特に注目すべきもの:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: パスが受け取るべきラベルを永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: custom policy module を読み込む
- `semanage permissive -a <domain_t>`: ホスト全体を切り替えずに、1つの domain を permissive にする
- `setsebool -P`: policy boolean を永続的に変更する
- `load_policy`: active policy を再読み込みする

これらは多くの場合、単独で root exploit になるものではなく、**helper primitives** です。その価値は、次のことを可能にする点にあります:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- target domain を permissive にする
- 自分の domain と protected type の間の access を広げる
- attacker-controlled files にラベルを付け直し、privileged service がそれらを読み取る、または実行できるようにする
- confined service を十分に弱体化し、既存の local bug を exploit 可能にする

確認例:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
rootとしてpolicy moduleをロードできる場合、通常はSELinux境界を制御できます:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
そのため、`audit2allow`、`semodule`、`semanage permissive` は、post-exploitation における機密性の高い管理者向けサーフェスとして扱うべきです。これらは、従来の UNIX permissions を変更せずに、ブロックされていた chain を動作するものへ密かに変換できます。<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 隠れた Denial と Module の抽出

攻撃側が非常によく遭遇する苛立たしい状況は、期待される AVC denial が表示されないまま、曖昧な `EACCES` で chain が失敗することです。`dontaudit` rules によって、必要な正確な permission が隠されている可能性があります。`sudo` または別の privileged wrapper 経由で `semodule` を実行できる場合、`dontaudit` を一時的に無効化することで、silent failure を正確な policy の手がかりに変えられます。<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
これは、ローカル管理者がすでに変更した内容を確認する際にも役立ちます。小規模なカスタムモジュールや、単一ドメインに対する permissive ルールが、base policy から想定されるよりも target service の動作を大幅に緩くしている理由であることがよくあります。<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denial は、単なる防御側のノイズではなく、攻撃側の手がかりになることがよくあります。次の情報が得られます。<sup>[[1]](#references)[[15]](#references)</sup>

- hit した target object/type
- 拒否された permission
- 現在 control している domain
- 小さな policy 変更によって chain が機能するかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
ローカル exploit や persistence の試行が `EACCES` や不可解な「permission denied」エラーで何度も失敗し、root に見える DAC permissions がある場合でも、vector を諦める前に SELinux を確認する価値があります。<sup>[[1]](#references)</sup>

## SELinux ユーザー

通常の Linux ユーザーに加えて、SELinux ユーザーが存在します。各 Linux ユーザーは policy の一部として SELinux ユーザーにマッピングされ、システムはアカウントごとに異なる許可された role と domain を適用できます。<sup>[[3]](#references)</sup>

簡単な確認方法:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
多くの mainstream systems では、ユーザーは `unconfined_u` にマッピングされており、ユーザー confinement の実際の影響が小さくなっています。ただし、hardened deployment では、confined user にとって `sudo`、`su`、`newrole`、`runcon` がより重要になる可能性があります。これは、**escalation path が UID 0 になることだけでなく、より適切な SELinux role/type に入ることに依存する場合があるためです**。また、一部の confined user は、policy が基盤となる setuid transition を明示的に許可しない限り、`sudo`/`su` をまったく実行できない点にも注意してください。そのため、`staff_u` + `sysadm_r` を使用する host では、一見すると軽微な `sudo ROLE=` / `TYPE=` rule が、実際の privilege boundary になる可能性があります。<sup>[[3]](#references)</sup>

## Container における SELinux

Container runtime は通常、`container_t` などの confined domain で workload を起動し、container content に `container_file_t` の label を付けます。Container process が escape しても container label のまま実行されている場合、label boundary が維持されているため、host への write は依然として失敗する可能性があります。<sup>[[1]](#references)[[17]](#references)</sup>

簡単な例:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` の部分は装飾ではありません。多くのコンテナ deployment では、runtime が MCS categories を動的に割り当てるため、`container_t` として実行されている 2 つの process も相互に分離されます。escape によって host namespace に入った場合でも、元の category set が維持されていると、category の不一致によって、一部の host path が読み取り不可または書き込み不可のままである理由を説明できることがあります。<sup>[[17]](#references)</sup>

注目すべき modern container operations:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` は container の SELinux label separation を無効化します
- `:z` / `:Z` を付けた bind mount は、shared/private container use のために host path の relabeling を発生させます
- host content の広範な relabeling 自体が security issue になる可能性があります

このページでは、重複を避けるため container content を短くしています。container 固有の abuse cases と runtime examples については、以下を確認してください。

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: SELinux の使用](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux の policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [confined users と unconfined users の管理 - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run documentation](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Linux containers で Multi-Category Security を使用すべき理由](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top documentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}

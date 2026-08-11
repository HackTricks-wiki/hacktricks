# SELinux

SELinuxは**ラベルベースの Mandatory Access Control (MAC)**システムです。実際には、DACの権限、グループ、またはLinux capabilitiesがある操作に十分に見えていても、要求されたクラス/権限で**source context**が**target context**へのアクセスを許可されていない場合、kernelはその操作を拒否できます。<sup>[[1]](#references)</sup>

contextは通常、次のようになります:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
権限昇格の観点では、`type`（プロセスでは domain、オブジェクトでは type）が通常、最も重要なフィールドです:<sup>[[1]](#references)</sup>

- プロセスは `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` などの **domain** で実行されます
- ファイルとソケットには、`admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` などの **type** があります
- Policy により、ある domain が別の domain または type に対して read/write/execute/transition できるかどうかが決まります

## Fast Enumeration

SELinux が有効な場合は、早い段階で enumerate してください。一般的な Linux の権限昇格経路が失敗する理由や、"harmless" な SELinux tool の周囲にある privileged wrapper が実際には重要である理由を説明できるためです:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
有用な追加チェック:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
- `unconfined_t` は通常、SELinux が存在していても、そのプロセスを実質的に制約していないことを意味します。
- カスタムパスに `default_t`、`file_t`、または明らかに誤ったラベルが付いている場合、ラベル付けの誤りやデプロイの不完全さを示していることがよくあります。
- `file_contexts.local` のローカル上書きはポリシーのデフォルトより優先されるため、慎重に確認してください。

## Policy Analysis

次の2つの質問に答えられる場合、SELinux への攻撃やバイパスははるかに容易になります。

1. **現在のドメインは何にアクセスできるか？**
2. **どのドメインへ遷移できるか？**

これに最も役立つツールは、`sepolicy` と **SETools**（`seinfo`、`sesearch`、`sedta`）です:<sup>[[2]](#references)[[9]](#references)</sup>
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
これは、ホストが全員を `unconfined_u` にマッピングするのではなく、**confined users** を使用している場合に特に有用です。その場合は、以下を確認します:<sup>[[3]](#references)</sup>

- `semanage login -l` による user mappings
- `semanage user -l` による許可された roles
- `sysadm_t`、`secadm_t`、`webadm_t` などの到達可能な admin domains
- `ROLE=` または `TYPE=` を使用する `sudoers` entries

`sudo -l` に次のような entries が含まれている場合、SELinux は privilege boundary の一部です:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
また、`newrole` が利用可能かどうかも確認します:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` と `newrole` は自動的に exploit 可能というわけではありませんが、特権ラッパーや `sudoers` ルールによって、より有利な role/type を選択できる場合、高価値な権限昇格プリミティブになります。<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Files, Relabeling, and High-Value Misconfigurations

一般的な SELinux ツール間における、運用上最も重要な違いは次のとおりです。<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: 特定のパスに対する一時的な label 変更
- `semanage fcontext`: 永続的なパスと label のルール
- `restorecon` / `setfiles`: policy/default label を再度適用

これは privesc の際に非常に重要です。なぜなら、**relabeling は単なる外観上の変更ではない**からです。これにより、ファイルを「policy によってブロックされている状態」から「特権を持つ confined service によって readable/executable な状態」へ変更できます。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

ローカルの relabel ルールと relabel のずれを確認します。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
微妙ですが有用な点が1つあります。通常の `restorecon` では、疑わしいラベルが**必ずしも完全には元に戻りません**。対象の type が `customizable_types` に含まれている場合、完全にリセットするには `-F` が必要になることがあります。攻撃側の観点では、これにより、通常の「すでに restorecon を実行した」という簡単なクリーンアップ後も、通常とは異なる `chcon` が残ることがある理由が説明できます。<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
`sudo -l`、root wrappers、automation scripts、または file capabilities で調査すべき高価値な commands:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
いずれかの MAC capability が表示された場合は、[Linux capabilities page](linux-capabilities.md) も照合してください。Linux capabilities のドキュメントでは、`cap_mac_admin` と `cap_mac_override` は Smack 固有として説明されているため、名前だけを根拠に SELinux を bypass できると判断しないでください。<sup>[[5]](#references)</sup>

特に注目すべきもの:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: パスが受け取るべき label を永続的に変更する
- `restorecon` / `setfiles`: それらの変更を大規模に再適用する
- `semodule -i`: custom policy module を読み込む
- `semanage permissive -a <domain_t>`: host 全体を切り替えずに、1つの domain を permissive にする
- `setsebool -P`: policy boolean を永続的に変更する
- `load_policy`: active policy を再読み込みする

これらは、多くの場合、単独で root exploit になるものではなく、**helper primitives** です。価値があるのは、次のことを可能にする点です:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- target domain を permissive にする
- 自分の domain と保護された type 間の access を広げる
- privileged service が読み取りまたは実行できるよう、attacker-controlled files を relabel する
- confined service を十分に弱体化し、既存の local bug を exploit 可能にする

確認例:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
rootとしてpolicy moduleをロードできるなら、通常はSELinuxの境界を制御できます:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
そのため、`audit2allow`、`semodule`、`semanage permissive` は、post-exploitation における機密性の高い管理サーフェスとして扱うべきです。これらは、従来の UNIX permissions を変更せずに、ブロックされていた chain を動作するものへと、気付かれないまま変換できます。<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 隠れた Denials と Module の抽出

非常によくある offensive 上の苛立ちは、想定される AVC denial がまったく表示されないまま、曖昧な `EACCES` で chain が失敗することです。`dontaudit` rules によって、必要な exact permission が隠されている可能性があります。`sudo` または別の privileged wrapper を通じて `semodule` を実行できる場合、`dontaudit` を一時的に無効化することで、silent failure を正確な policy clue に変えられます。<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
これは、ローカル管理者がすでに変更した内容を確認する際にも役立ちます。小規模なカスタムモジュールや、特定の1つのdomainに対するpermissive ruleが、対象サービスの動作をベースポリシーから想定されるよりもはるかに緩くしている原因であることがよくあります。<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC denialsは、単なる防御側のノイズではなく、攻撃側にとって有用なシグナルとなることがよくあります。次の情報が得られます:<sup>[[1]](#references)[[15]](#references)</sup>

- どのtarget object/typeにアクセスしたか
- どのpermissionが拒否されたか
- 現在どのdomainを制御しているか
- 小さなpolicy変更によってchainが機能するかどうか
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
ローカル exploit や persistence の試行が `EACCES` または奇妙な「permission denied」エラーで繰り返し失敗し、root に見える DAC 権限がある場合でも、vector を破棄する前に SELinux を確認する価値があります。<sup>[[1]](#references)</sup>

## SELinux Users

通常の Linux ユーザーに加えて、SELinux ユーザーが存在します。各 Linux ユーザーは policy の一部として SELinux ユーザーにマッピングされ、システムはアカウントごとに異なる許可された role と domain を適用できます。<sup>[[3]](#references)</sup>

簡単な確認方法:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
多くの主流システムでは、ユーザーは `unconfined_u` にマッピングされているため、ユーザーの confinement による実際の影響は小さくなります。しかし、hardened な環境では、confined user にとって `sudo`、`su`、`newrole`、`runcon` がはるかに興味深いものになります。これは、**escalation path が UID 0 になることだけでなく、より権限の高い SELinux role/type に入ることに依存する場合があるためです**。また、policy が基盤となる setuid transition を明示的に許可していない限り、一部の confined user は `sudo`/`su` をまったく実行できないことにも注意してください。そのため、`staff_u` + `sysadm_r` を使用するホストでは、一見些細な `sudo ROLE=` / `TYPE=` ルールが、実際の privilege boundary になる可能性があります。<sup>[[3]](#references)</sup>

## コンテナ内の SELinux

Container runtime は通常、`container_t` などの confined domain で workload を起動し、container content に `container_file_t` のラベルを付けます。Container process が escape しても、container label のまま実行されている場合、label boundary が維持されているため、host への書き込みは依然として失敗する可能性があります。<sup>[[1]](#references)[[17]](#references)</sup>

簡単な例:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` の部分は装飾ではありません。多くの container デプロイメントでは、runtime が MCS category を動的に割り当てるため、`container_t` として実行されている2つのプロセスも互いに分離された状態になります。escape によって host namespace に入った場合でも、元の category set が維持されていると、category の不一致によって一部の host path が読み取りまたは書き込みできない理由を説明できる場合があります。<sup>[[17]](#references)</sup>

注目すべき現代の container 操作:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` は container の SELinux label separation を無効にします
- `:z` / `:Z` を付けた bind mount は、shared/private container 用に host path の relabeling を引き起こします
- host content の広範な relabeling 自体が security issue になる可能性があります

このページでは重複を避けるため、container に関する内容を短くまとめています。container 固有の abuse case と runtime の例については、以下を確認してください:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat docs: SELinux の使用](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: SELinux の Policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [Confined user と unconfined user の管理 - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
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
- [17] [Linux container に Multi-Category Security を使用すべき理由](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top documentation](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}

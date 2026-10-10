# ユーザー、セッション、認証情報の痕跡

{{#include ../../banners/hacktricks-training.md}}

現在のシェルを所有するIDから始め、他のユーザー、グループ、アクティブなセッション、認証情報ストアを列挙します。[実ユーザーID、有効ユーザーID、保存ユーザーID](euid-ruid-suid.md)のページでは、プロセスの有効な権限がログインアカウントと異なる場合がある理由を説明しています。

## IDとグループベースのアクセスを列挙する

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` には、`/etc/passwd` を直接読み取るだけでは見つからないディレクトリバックのアカウントも含まれます。UID 0 のアカウント、ログインシェル、ホームディレクトリ、補助グループ、そして設定上、予期せず対話型ログインが許可されているアカウントを確認してください。[注意すべきグループ](interesting-groups-linux-pe/README.md)のページでは、`sudo`、`docker`、`disk`、`shadow` などの委譲アクセスを扱っています。グループ名だけを見て権限があると判断せず、実際のファイルシステム ACL とローカルポリシーを確認してください。

[NSS が `passwd`、`group`、または `shadow` の検索をデータベースにマッピングしている場合](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)、データベースバックのIDを評価する前に、アクティブなプロバイダーとその設定パスを確認してください。PostgreSQL NSS の環境では、`/etc/nss-pgsql.conf` と `/etc/nss-pgsql-root.conf` はパスだけを手掛かりにしてください。接続設定に認証情報が含まれている可能性があります。データベースロールが意味を持つのは、アクティブな NSS プロバイダーが実際に返すレコードを変更でき、かつアカウントがその情報を使って認証できる場合に限られます。プライマリ GID が 0 の場合は root グループに属するということであり、UID 0 という意味ではありません。sudo グループへのマッピングには、有効な [sudoers グループルール](https://man7.org/linux/man-pages/man5/sudoers.5.html)と、必要に応じて認証が必要です。UID 0 のマッピングは、別のID境界です。受動的な列挙中に接続文字列を表示したり、アカウントレコードを変更したりしないでください。

また、ローカルアカウント名間で数値 UID が重複していないか確認してください。[`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) 内の2つの名前が同じ Unix ファイルIDを指していても、ログイン認証情報は異なる場合があります。そのため、認証に成功すれば、新たに追加された非ゼロ UID のエイリアスから別ユーザーのファイルやプロセスにアクセスできる可能性があります。ただし、その UID 自体または別の権限昇格経路がない限り、root 権限は得られません。UID の共有が意図的な場合もあります。アカウントソース（`/etc/passwd` と NSS のどちらか）、作成履歴、シェルとホームディレクトリ、実際の認証ポリシー、そしてアカウント間でIDを共有する権限があるかを確認してください。ローカルのみを対象とする重複チェックでは、ディレクトリバックのエイリアスを除外できません。

## アクティブおよび最近のセッションを確認する

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` または `tmux` の socket は、権限が許可していれば、現在のユーザーが attach できる既存の shell を公開する可能性があります。アクセスを試みる前に、所有者と socket のモードを確認してください。他のユーザーのセッションに自動的に attach できるわけではありません。有効な sudo timestamp や SSH agent socket も関係する場合がありますが、それらを再利用できるかどうかは、ユーザー ID、権限、ポリシーによって異なります。agent forwarding の悪用については、[SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) を参照してください。

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) は `SSH_AUTH_SOCK` とは別のものです。`ControlMaster` と `ControlPath` を使うと、後続の SSH クライアントが既存の認証済み接続を共有できます。また、`ControlPersist` を使うと、最初のセッション終了後も master を利用可能な状態に保てます。現在のユーザーの `.ssh/config` と、`.ssh` 内の浅い階層にある socket パスを調べ、所有者と権限も確認してください。socket のファイル名だけでは、master が稼働中であること、現在のユーザーが接続できること、接続先のリモートアカウントがどれかは証明できません。

## ユーザーのアーティファクトを確認する

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history、startup files、SSH keys、application configuration、GPG keyrings、Kerberos cachesから、認証情報や書き込み可能な永続化ポイントが見つかることがあります。より高い権限を持つアカウントの`authorized_keys`やshell startup fileが書き込み可能な場合は、確認が必要です。[post-exploitation page](../post-exploitation/README.md)では、GPG homedirの移動と認証情報の探索を扱っています。[Linux Active Directory](linux-active-directory.md)では、Kerberos cacheとkeytabの再利用を扱っています。[PAM page](../software-information/pam-pluggable-authentication-modules.md)では、認証ポリシーのリスクを説明しています。
{{#include ../../banners/hacktricks-training.md}}

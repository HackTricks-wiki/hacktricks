# ユーザー、セッション、認証情報の痕跡

{{#include ../../banners/hacktricks-training.md}}

まず、現在の shell を所有する ID を確認し、続いて他のユーザー、グループ、アクティブなセッション、認証情報ストアを列挙します。[実ユーザー ID、有効ユーザー ID、保存ユーザー ID](euid-ruid-suid.md) のページでは、プロセスの有効な権限がログインアカウントと異なる場合がある理由を説明しています。

## ID とグループベースのアクセスを列挙する

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` には、`/etc/passwd` を単純に読み取るだけでは見つからない、ディレクトリサービス上のアカウントも含まれます。UID 0 のアカウント、ログインシェル、ホームディレクトリ、補助グループ、および設定上予期せず対話型ログインが許可されているアカウントを確認してください。[興味深いグループ](interesting-groups-linux-pe/README.md)のページでは、`sudo`、`docker`、`disk`、`shadow` などを介した委任アクセスについて説明しています。グループ名だけで特権があると判断せず、実際のファイルシステム ACL とローカルポリシーを確認してください。

[NSS が `passwd`、`group`、`shadow` の検索先をデータベースにマッピングしている](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)場合、データベース由来の ID を評価する前に、有効なプロバイダーとその設定パスを確認してください。PostgreSQL NSS の構成では、`/etc/nss-pgsql.conf` と `/etc/nss-pgsql-root.conf` はパスを確認するための手掛かりにとどめてください。接続設定に認証情報が含まれている可能性があるためです。データベースロールが意味を持つのは、有効な NSS プロバイダーが実際に返すレコードを変更でき、かつアカウントがそのレコードを使って認証できる場合に限られます。プライマリ GID が 0 なら root グループのメンバーになりますが、UID 0 になるわけではありません。sudo グループへのマッピングには、有効な [sudoers グループルール](https://man7.org/linux/man-pages/man5/sudoers.5.html)と、必要な認証が求められます。UID 0 へのマッピングは、これとは異なる ID 境界です。受動的な列挙中に接続文字列を表示したり、アカウントレコードを変更したりしないでください。

また、ローカルのアカウント名間で数値 UID を比較してください。[`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) 内の異なる2つの名前が、同じ Unix ファイル ID を指している場合がありますが、それぞれのログイン認証レコードは異なる可能性があります。そのため、認証に成功すると、新たに追加された、共有 UID を持つ別名アカウントから他のユーザーのファイルやプロセスにアクセスできることがあります。ただし、その UID 自体または別の権限経路がない限り、root 権限が得られるわけではありません。UID の共有は意図的な場合もあります。アカウントのソース（`/etc/passwd` または NSS）、作成履歴、シェルとホームディレクトリ、実際の認証ポリシー、および各アカウントがその ID を共有する権限を持つかどうかを確認してください。ローカルアカウントだけを対象とした重複チェックでは、ディレクトリサービス上の別名アカウントを除外できません。

## アクティブなセッションと最近のセッションを確認する

```bash
who -a
w
last -a | head
loginctl list-sessions 2>/dev/null
ps -eo user,pid,ppid,tty,cmd --sort=user | head -80
screen -ls 2>/dev/null
tmux ls 2>/dev/null
```

`screen` または `tmux` のソケットは、権限上、現在のユーザーが接続できる場合、既存のシェルを露出させる可能性があります。アクセスを試みる前に、所有者とソケットのモードを確認してください。他のユーザーのセッションに自動的に接続できるわけではありません。有効な sudo timestamp や SSH agent socket も関係する場合がありますが、再利用できるかどうかはユーザー ID、権限、ポリシーによります。agent forwarding の悪用については、[SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) を参照してください。

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) は `SSH_AUTH_SOCK` とは別のものです。`ControlMaster` と `ControlPath` を使うと、後続の SSH クライアントが既存の認証済み接続を共有できます。また、`ControlPersist` を使うと、最初のセッション終了後も master を利用可能な状態に保てます。現在のユーザーの `.ssh/config` と、浅い階層にある `.ssh` 内のソケットパスを、所有者と権限も含めて確認してください。ソケットファイル名だけでは、master が稼働中であること、現在のユーザーが接続できること、接続先のリモートアカウントを証明できません。

## ユーザーアーティファクトを確認する

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell の履歴、起動ファイル、SSH keys、アプリケーションの設定、GPG keyring、Kerberos キャッシュから、認証情報や書き込み可能な永続化ポイントが見つかることがあります。より高い権限を持つアカウントの `authorized_keys` や shell 起動ファイルが書き込み可能な場合は、確認が必要です。[post-exploitation ページ](../post-exploitation/README.md)では、GPG homedir の移動と認証情報の探索を扱っています。[Linux Active Directory](linux-active-directory.md)では、Kerberos キャッシュと keytab の再利用を扱っています。[PAM ページ](../software-information/pam-pluggable-authentication-modules.md)では、認証ポリシーに関するリスクを説明しています。
{{#include ../../banners/hacktricks-training.md}}

# ユーザー、セッション、認証情報の痕跡

{{#include ../../banners/hacktricks-training.md}}

まず、現在のシェルを所有するユーザーを特定し、他のユーザー、グループ、アクティブなセッション、認証情報ストアを列挙します。[実ユーザー ID、有効ユーザー ID、保存ユーザー ID](euid-ruid-suid.md)のページでは、プロセスの実効権限がログインアカウントと異なる場合がある理由を説明しています。

## IDとグループベースのアクセスを列挙する

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent` には、`/etc/passwd` を単純に読み取るだけでは見つからないディレクトリ連携アカウントも含まれます。UID 0 のアカウント、ログインシェル、ホームディレクトリ、補助グループ、対話型ログインが予期せず許可されているアカウントを確認してください。[興味深いグループ](interesting-groups-linux-pe/README.md)のページでは、`sudo`、`docker`、`disk`、`shadow` などによる委任アクセスを扱っています。グループ名だけで権限があると判断せず、実際のファイルシステム ACL とローカルポリシーを確認してください。

[NSS が `passwd`、`group`、`shadow` の検索をデータベースにマッピングしている](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)場合は、データベース連携 ID を評価する前に、有効なプロバイダーとその設定パスを確認してください。PostgreSQL NSS の環境では、`/etc/nss-pgsql.conf` と `/etc/nss-pgsql-root.conf` はパスのみを調査の手掛かりとしてください。接続設定に認証情報が含まれる場合があるためです。データベースロールが重要なのは、有効な NSS プロバイダーが実際に返すレコードを変更でき、かつアカウントがその情報を使って認証できる場合に限られます。プライマリ GID が 0 であれば root グループへの所属を意味しますが、UID 0 を意味するものではありません。sudo グループへのマッピングには、有効な [sudoers のグループルール](https://man7.org/linux/man-pages/man5/sudoers.5.html)と、必要に応じて認証が必要です。UID 0 のマッピングは別の ID 境界です。パッシブな列挙中に接続文字列を表示したり、アカウントレコードを変更したりしないでください。

ローカルアカウント名間で数値 UID も比較してください。[`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html) 内の 2 つの名前が、同じ Unix ファイル ID を指している場合がありますが、それぞれのログイン認証レコードは異なることがあります。そのため、認証に成功した後、新しく追加された非ゼロ UID の別名から別ユーザーのファイルやプロセスにアクセスできる可能性があります。ただし、その UID 自体または別の権限経路がない限り、root 権限は得られません。UID の共有は意図的な場合もあります。アカウントのソース（`/etc/passwd` と NSS のどちらか）、作成履歴、シェルとホーム、実際の認証ポリシー、アカウント間で ID を共有する権限があるかを確認してください。ローカルのみの重複チェックでは、ディレクトリ連携の別名を除外できません。

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

`screen` または `tmux` の socket は、権限があれば現在のユーザーが attach して既存の shell にアクセスできる場合があります。アクセスを試みる前に、所有者と socket の mode を確認してください。他のユーザーのセッションに自動的に attach できるわけではありません。有効な sudo timestamp や SSH agent socket も関係する場合がありますが、再利用できるかどうかはユーザー ID、権限、ポリシーによって異なります。agent forwarding の悪用については、[SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) を参照してください。

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) は `SSH_AUTH_SOCK` とは別のものです。`ControlMaster` と `ControlPath` を使うと、後続の SSH client が既存の認証済み接続を共有できます。また、`ControlPersist` を使うと、最初のセッション終了後も master を利用可能な状態に保てます。現在のユーザーの `.ssh/config` と `.ssh` 内の浅い階層にある socket path を、所有者と権限も含めて調べてください。socket のファイル名だけでは、master が稼働中であること、現在のユーザーが接続できること、接続先のリモートアカウントがどれかは判断できません。

## ユーザーのアーティファクトを確認する

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell の履歴、起動ファイル、SSH keys、アプリケーション設定、GPG keyring、Kerberos cache から、認証情報や書き込み可能な永続化ポイントが見つかることがあります。より高い権限を持つアカウントの `authorized_keys` や shell 起動ファイルが書き込み可能な場合は、詳しく調査してください。[post-exploitation page](../post-exploitation/README.md) では、GPG homedir の移動と認証情報の探索について説明しています。[Linux Active Directory](linux-active-directory.md) では、Kerberos cache と keytab の再利用について説明しています。[PAM page](../software-information/pam-pluggable-authentication-modules.md) では、認証ポリシーに関するリスクについて説明しています。
{{#include ../../banners/hacktricks-training.md}}

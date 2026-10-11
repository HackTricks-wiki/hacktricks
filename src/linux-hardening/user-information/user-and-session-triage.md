# ユーザー、セッション、認証情報の痕跡

{{#include ../../banners/hacktricks-training.md}}

まず、現在のシェルを所有するユーザーを特定し、次に他のユーザー、グループ、アクティブなセッション、認証情報ストアを列挙します。[real、effective、saved user ID](euid-ruid-suid.md)のページでは、プロセスの実効権限がログインアカウントと異なる場合がある理由を説明しています。

## IDとグループベースのアクセスを列挙する

```bash
id
getent passwd
getent group
whoami
stat -c '%A %U:%G %n' /etc/passwd /etc/shadow /etc/group
```

`getent`には、`/etc/passwd`を単純に読み取るだけでは見落とす可能性のある、ディレクトリバックエンドのアカウントも含まれます。UID 0のアカウント、ログインシェル、ホームディレクトリ、補助グループ、および設定上、予期せず対話型ログインが許可されているアカウントを確認してください。[興味深いグループ](interesting-groups-linux-pe/README.md)のページでは、`sudo`、`docker`、`disk`、`shadow`などによる委任アクセスを取り上げています。グループ名だけで権限があると判断する前に、実際のファイルシステムACLとローカルポリシーを確認してください。

[NSSが`passwd`、`group`、`shadow`の検索をデータベースにマッピングしている](https://man7.org/linux/man-pages/man5/nsswitch.conf.5.html)場合は、データベースに基づくIDを評価する前に、有効なプロバイダーとその設定パスを確認してください。PostgreSQL NSSを使用している環境では、`/etc/nss-pgsql.conf`と`/etc/nss-pgsql-root.conf`はパスの手掛かりとしてのみ扱ってください。接続設定に認証情報が含まれている可能性があります。データベースロールが重要なのは、有効なNSSプロバイダーが実際に返すレコードを変更でき、かつアカウントがその情報を使って認証できる場合に限られます。プライマリGIDが0の場合、rootグループに所属しますが、UID 0になるわけではありません。sudoグループへのマッピングが有効になるには、実効的な[sudoersのグループルール](https://man7.org/linux/man-pages/man5/sudoers.5.html)と、必要に応じて認証が必要です。UID 0のマッピングは、これとは異なるID境界です。受動的な列挙中に接続文字列を出力したり、アカウントレコードを変更したりしないでください。

また、ローカルアカウント名の間で数値UIDを比較してください。[`/etc/passwd`](https://man7.org/linux/man-pages/man5/passwd.5.html)内の2つの名前が同じUnixファイルIDを指していても、それぞれのログイン認証レコードは異なる可能性があります。そのため、共有UIDを持つ新たに追加されたエイリアスは、認証に成功すると別のユーザーのファイルやプロセスへのアクセスにつながる可能性があります。ただし、そのUID自体または別の権限昇格経路がなければ、root権限は得られません。UIDの共有は意図的な場合もあります。アカウントのソース（`/etc/passwd`かNSSか）、作成履歴、シェルとホームディレクトリ、実際の認証ポリシー、および各アカウントでIDを共有する権限があるかを確認してください。ローカルのみの重複チェックでは、ディレクトリバックエンドのエイリアスがないことを確認できません。

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

`screen` または `tmux` のソケットは、権限によって現在のユーザーがアタッチできる場合、既存の shell を公開する可能性があります。アクセスを試みる前に、所有者とソケットのモードを確認してください。他のユーザーのセッションに自動的にアタッチできるわけではありません。有効な sudo timestamp や SSH agent socket も関係する場合がありますが、再利用できるかどうかはユーザー ID、権限、ポリシーによって異なります。agent forwarding の悪用については、[SSH forwarding agent exploitation](ssh-forward-agent-exploitation.md) を参照してください。

[OpenSSH multiplex control socket](https://man.openbsd.org/ssh_config#ControlMaster) は `SSH_AUTH_SOCK` とは別のものです。`ControlMaster` と `ControlPath` を使うと、後続の SSH クライアントが既存の認証済み接続を共有できます。また、`ControlPersist` を使うと、最初のセッション終了後も master を利用可能な状態にできます。現在のユーザーの `.ssh/config` と `.ssh` 内の浅い階層にあるソケットパスを調べ、所有者と権限も確認してください。ソケットのファイル名だけでは、master が稼働中であること、現在のユーザーが接続できること、接続先でどのアカウントが使われるかは確認できません。

## ユーザーのアーティファクトを確認

```bash
find /home -maxdepth 3 -type f \( -name 'authorized_keys' -o -name 'id_*' -o -name '*history' -o -name '.netrc' -o -name '.git-credentials' \) -ls 2>/dev/null
find /home -maxdepth 3 -type f \( -name '.bashrc' -o -name '.profile' -o -name '.zshrc' \) -ls 2>/dev/null
printenv SSH_AUTH_SOCK KRB5CCNAME GNUPGHOME 2>/dev/null
```

Shell history、startup file、SSH key、application configuration、GPG keyring、Kerberos cacheから、認証情報や書き込み可能な永続化ポイントが見つかることがあります。より高い権限を持つアカウントの`authorized_keys`やshell startup fileが書き込み可能な場合は、確認が必要です。[post-exploitation page](../post-exploitation/README.md)では、GPG homedirの移動と認証情報の探索を解説しています。[Linux Active Directory](linux-active-directory.md)では、Kerberos cacheとkeytabの再利用を扱っています。[PAM page](../software-information/pam-pluggable-authentication-modules.md)では、認証ポリシーのリスクを解説しています。
{{#include ../../banners/hacktricks-training.md}}

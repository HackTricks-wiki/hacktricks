# ユーザー情報

{{#include ../../banners/hacktricks-training.md}}

ユーザーID、グループメンバーシップ、委任された認証情報によって、プロセスがアクセスできるリソースが決まります。以下のアクセス経路を調査する前に、実効ユーザーIDと補助グループを確認してください。

- [ユーザー、セッション、認証情報の痕跡](user-and-session-triage.md)では、アカウントの列挙、アクティブなログイン、SSH とシェルの痕跡、認証情報ストアについて説明します。
- [実ユーザーID、実効ユーザーID、保存ユーザーID](euid-ruid-suid.md)では、SUID プログラムやプロセス実行時のユーザーIDの変更について説明します。
- [Linux の権限昇格に役立つグループ](interesting-groups-linux-pe/README.md)では、LXD/LXC を含む、グループによって付与されるアクセス権について説明します。
- [SSH forwarding agent の悪用](ssh-forward-agent-exploitation.md)では、転送された SSH 認証情報のリスクについて調査します。
- [Linux Active Directory](linux-active-directory.md)では、AD 環境に参加しているホストについて説明します。

{{#include ../../banners/hacktricks-training.md}}

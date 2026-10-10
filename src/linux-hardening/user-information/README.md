# ユーザー情報

{{#include ../../banners/hacktricks-training.md}}

ユーザーID、グループメンバーシップ、委任された認証情報によって、プロセスがアクセスできるリソースが決まります。以下のアクセス経路を調査する前に、実効ユーザーIDと補助グループを確認してください。

- [ユーザー、セッション、認証情報のアーティファクト](user-and-session-triage.md)では、アカウントの列挙、アクティブなログイン、SSHやシェルのアーティファクト、認証情報ストアについて説明します。
- [実ユーザーID、実効ユーザーID、保存ユーザーID](euid-ruid-suid.md)では、SUIDプログラムやプロセス実行時のID変更について説明します。
- [Linuxの権限昇格に利用できる興味深いグループ](interesting-groups-linux-pe/README.md)では、LXD/LXCを含む、グループによって許可されるアクセスについて説明します。
- [SSH転送エージェントの悪用](ssh-forward-agent-exploitation.md)では、転送されたSSH認証情報のリスクについて検証します。
- [Linux Active Directory](linux-active-directory.md)では、AD環境に参加しているホストについて説明します。

{{#include ../../banners/hacktricks-training.md}}

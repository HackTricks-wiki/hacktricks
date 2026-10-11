# ユーザー情報

{{#include ../../banners/hacktricks-training.md}}

ユーザーID、グループメンバーシップ、委任された認証情報によって、プロセスがアクセスできるリソースが決まります。以下のアクセス経路を調査する前に、実効IDと補助グループを確認してください。

- [ユーザー、セッション、認証情報の痕跡](user-and-session-triage.md)では、アカウントの列挙、アクティブなログイン、SSHとシェルの痕跡、認証情報ストアを扱います。
- [実ID、実効ID、保存ユーザーID](euid-ruid-suid.md)では、SUIDプログラムやプロセス実行時のID変更について説明します。
- [Linuxの権限昇格で注目すべきグループ](interesting-groups-linux-pe/README.md)では、LXD/LXCを含む、グループによって付与されるアクセス権を扱います。
- [SSH転送エージェントの悪用](ssh-forward-agent-exploitation.md)では、転送されたSSH認証情報のリスクについて検証します。
- [Linux Active Directory](linux-active-directory.md)では、AD環境に参加しているホストを扱います。
{{#include ../../banners/hacktricks-training.md}}

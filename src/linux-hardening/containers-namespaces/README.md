# コンテナとNamespace

{{#include ../../banners/hacktricks-training.md}}

コンテナとは、隔離設定と権限設定が適用された状態で実行されるLinuxプロセスです。ランタイム、マウントされたホストリソース、付与されたcapabilities、Namespaceの設定をあわせて評価してください。[コンテナセキュリティの概要](container-security/README.md)では、これらのレイヤーについて説明し、それぞれの制御項目へのリンクを掲載しています。

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md)では、containerdの管理インターフェースへのアクセスに焦点を当てています。
- [RunC privilege escalation](runc-privilege-escalation.md)では、ランタイム固有の権限昇格に関する情報を扱っています。
- [コンテナセキュリティ](container-security/README.md)では、ランタイム、公開されたAPI、イメージのリスク、機密性の高いマウント、特権コンテナ、評価方法、およびNamespace、seccomp、強制アクセス制御などの保護策について説明しています。
{{#include ../../banners/hacktricks-training.md}}

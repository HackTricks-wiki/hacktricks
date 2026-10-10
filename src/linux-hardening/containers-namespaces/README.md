# Containers and Namespaces

{{#include ../../banners/hacktricks-training.md}}

コンテナは、隔離設定と権限設定を適用して実行される Linux プロセスです。ランタイム、マウントされたホストリソース、付与された capability、namespace の設定をまとめて評価します。[コンテナセキュリティの概要](container-security/README.md)では、これらのレイヤーを説明し、各制御へのリンクを紹介しています。

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md)では、containerd の管理インターフェースへのアクセスに焦点を当てています。
- [RunC privilege escalation](runc-privilege-escalation.md)では、ランタイム固有の privilege escalation に関する情報を扱っています。
- [コンテナセキュリティ](container-security/README.md)では、ランタイム、公開された API、イメージのリスク、機密性の高いマウント、特権コンテナ、評価、および namespace、seccomp、強制アクセス制御などの保護策について説明しています。
{{#include ../../banners/hacktricks-training.md}}

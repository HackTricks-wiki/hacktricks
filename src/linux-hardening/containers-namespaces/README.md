# コンテナと Namespaces

{{#include ../../banners/hacktricks-training.md}}

コンテナは、分離と権限の設定を適用して実行される Linux プロセスです。ランタイム、マウントされたホストリソース、付与された capabilities、namespace の設定を合わせて評価してください。[コンテナセキュリティの概要](container-security/README.md)では、これらのレイヤーについて説明し、各制御へのリンクを掲載しています。

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md)では、containerd の管理インターフェースへのアクセスに焦点を当てています。
- [RunC privilege escalation](runc-privilege-escalation.md)では、ランタイム固有の権限昇格に関する内容を扱います。
- [コンテナセキュリティ](container-security/README.md)では、ランタイム、公開された API、イメージのリスク、機密性の高いマウント、特権コンテナ、評価、namespace、seccomp、mandatory access control などの保護策について説明しています。
{{#include ../../banners/hacktricks-training.md}}

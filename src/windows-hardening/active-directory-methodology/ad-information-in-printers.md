{{#include ../../banners/hacktricks-training.md}}

インターネット上には、**デフォルト/弱い**ログイン資格情報でLDAPが設定されたプリンターの危険性を**強調する**いくつかのブログがあります。\
これは、攻撃者がプリンターを**不正なLDAPサーバーに対して認証させる**ことができるためです（通常、`nc -vv -l -p 444`で十分です）し、プリンターの**資格情報を平文でキャプチャ**することができます。

また、いくつかのプリンターには**ユーザー名を含むログ**があり、ドメインコントローラーから**すべてのユーザー名をダウンロード**できる場合もあります。

これらの**機密情報**と一般的な**セキュリティの欠如**は、攻撃者にとってプリンターを非常に興味深いものにします。

このトピックに関するいくつかのブログ：

- [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
- [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## プリンター設定

- **場所**: LDAPサーバーのリストは、`Network > LDAP Setting > Setting Up LDAP`にあります。
- **動作**: インターフェースは、資格情報を再入力せずにLDAPサーバーの変更を許可し、ユーザーの利便性を目指していますが、セキュリティリスクを引き起こします。
- **エクスプロイト**: エクスプロイトは、LDAPサーバーのアドレスを制御されたマシンにリダイレクトし、「接続テスト」機能を利用して資格情報をキャプチャすることを含みます。

## 資格情報のキャプチャ

**詳細な手順については、元の[ソース](https://grimhacker.com/2018/03/09/just-a-printer/)を参照してください。**

### 方法1: Netcatリスナー

シンプルなnetcatリスナーで十分かもしれません：
```bash
sudo nc -k -v -l -p 386
```
しかし、この方法の成功は異なります。

### 方法2: 完全なLDAPサーバーとSlapd

より信頼性の高いアプローチは、完全なLDAPサーバーを設定することです。なぜなら、プリンターは資格情報バインディングを試みる前に、ヌルバインドを実行し、その後クエリを行うからです。

1. **LDAPサーバーのセットアップ**: ガイドは[このソース](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)の手順に従います。
2. **重要なステップ**:
- OpenLDAPをインストールします。
- 管理者パスワードを設定します。
- 基本スキーマをインポートします。
- LDAP DBにドメイン名を設定します。
- LDAP TLSを構成します。
3. **LDAPサービスの実行**: セットアップが完了したら、LDAPサービスは次のように実行できます:
```bash
slapd -d 2
```
## 参考文献

- [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

{{#include ../../banners/hacktricks-training.md}}

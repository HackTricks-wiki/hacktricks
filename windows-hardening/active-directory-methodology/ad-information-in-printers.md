<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする。
* **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>


インターネットには、**デフォルト/弱いログオン資格情報を使用してLDAPで構成されたプリンタを放置する危険性を強調する**ブログがいくつかあります。\
これは、攻撃者がプリンタを**ルージュLDAPサーバに認証させる**（通常、`nc -vv -l -p 444`が十分）ことができ、プリンタの**資格情報を平文でキャプチャ**する可能性があるためです。

また、いくつかのプリンタには**ユーザ名のログ**が含まれているか、ドメインコントローラから**すべてのユーザ名をダウンロード**できる場合があります。

このような**機密情報**と**セキュリティの欠如**が、プリンタを攻撃者にとって非常に興味深いものにしています。

このトピックに関するいくつかのブログ：

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## プリンタの構成
- **場所**: LDAPサーバリストは、`ネットワーク > LDAP設定 > LDAPの設定`で見つかります。
- **動作**: インターフェースは、資格情報を再入力せずにLDAPサーバを変更できるようにしていますが、ユーザの利便性を狙っており、セキュリティリスクを引き起こしています。
- **エクスプロイト**: エクスプロイトは、LDAPサーバアドレスを制御されたマシンにリダイレクトし、「接続のテスト」機能を利用して資格情報をキャプチャすることです。

## 資格情報のキャプチャ

**詳細な手順については、元の[ソース](https://grimhacker.com/2018/03/09/just-a-printer/)を参照してください。**

### 方法1: Netcatリスナー
単純なnetcatリスナーが十分かもしれません:
```bash
sudo nc -k -v -l -p 386
```
### 方法2: Slapdを使用した完全なLDAPサーバー
より信頼性の高いアプローチは、プリンターが資格情報バインディングを試みる前に、ヌルバインドに続いてクエリを実行するため、完全なLDAPサーバーを設定することです。

1. **LDAPサーバーのセットアップ**: このガイドは、[このソース](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)の手順に従います。
2. **主なステップ**:
- OpenLDAPをインストールします。
- 管理者パスワードを構成します。
- 基本スキーマをインポートします。
- LDAP DBにドメイン名を設定します。
- LDAP TLSを構成します。
3. **LDAPサービスの実行**: セットアップが完了すると、LDAPサービスは次のように実行できます:
```bash
slapd -d 2
```
## 参考文献
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)


<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

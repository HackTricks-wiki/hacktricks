<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする。
* **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出してください。

</details>


インターネットには、**LDAPで構成されたプリンターをデフォルト/弱いログオン資格情報のままにしておく危険性を強調する**ブログがいくつかあります。\
これは、攻撃者がプリンターを**ルージュLDAPサーバーに認証させる**（通常、`nc -vv -l -p 444`が十分）ことができ、プリンターの**クリアテキストでの資格情報をキャプチャ**する可能性があるためです。

また、いくつかのプリンターには**ユーザー名の記録**が含まれているか、ドメインコントローラーから**すべてのユーザー名をダウンロード**できる場合もあります。

これらの**機密情報**と**セキュリティの欠如**がプリンターを攻撃者にとって非常に興味深いものにしています。

このトピックに関するいくつかのブログ：

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

## プリンターの構成
- **場所**: LDAPサーバーリストは、`ネットワーク > LDAP設定 > LDAPの設定`で見つかります。
- **動作**: インターフェースは、資格情報を再入力せずにLDAPサーバーを変更できるようにしていますが、ユーザーの利便性を狙っており、セキュリティリスクを引き起こしています。
- **エクスプロイト**: エクスプロイトには、LDAPサーバーアドレスを制御されたマシンにリダイレクトし、「接続をテスト」機能を利用して資格情報をキャプチャする必要があります。

## 資格情報のキャプチャ

### 方法1: Netcatリスナー
単純なnetcatリスナーが十分かもしれません:
```bash
sudo nc -k -v -l -p 386
```
### 方法2: Slapdを使用した完全なLDAPサーバー
より信頼性の高いアプローチは、プリンターが資格情報のバインディングを試みる前に、ヌルバインドに続いてクエリを実行するため、完全なLDAPサーバーをセットアップすることです。

1. **LDAPサーバーのセットアップ**: このガイドは、[このソース](https://www.server-world.info/en/note?os=Fedora_26&p=openldap)の手順に従います。
2. **主なステップ**:
- OpenLDAPをインストールします。
- 管理者パスワードを構成します。
- 基本スキーマをインポートします。
- LDAP DBにドメイン名を設定します。
- LDAP TLSを構成します。
3. **LDAPサービスの実行**: セットアップが完了すると、LDAPサービスは次のコマンドを使用して実行できます:
```
slapd -d 2
```

**詳細な手順については、元の[ソース](https://grimhacker.com/2018/03/09/just-a-printer/)を参照してください。**

# 参考文献
* [https://grimhacker.com/2018/03/09/just-a-printer/](https://grimhacker.com/2018/03/09/just-a-printer/)

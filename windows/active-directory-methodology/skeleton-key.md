# Skeleton Key

## **Skeleton Key**

**From:** [**https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/**](https://blog.stealthbits.com/unlocking-all-the-doors-to-active-directory-with-the-skeleton-key-attack/)\*\*\*\*

There are several methods for compromising Active Directory accounts that attackers can use to elevate privileges and create persistence once they have established themselves in your domain. The Skeleton Key is a particularly scary piece of malware targeted at Active Directory domains to make it alarmingly easy to hijack any account. This malware **injects itself into LSASS and creates a master password that will work for any account in the domain**. Existing passwords will also continue to work, so it is very difficult to know this attack has taken place unless you know what to look for.

Not surprisingly, this is one of the many attacks that is packaged and very easy to perform using [Mimikatz](https://github.com/gentilkiwi/mimikatz). Let’s take a look at how it works.

#### Requirements for the Skeleton Key Attack

In order to perpetrate this attack, **the attacker must have Domain Admin rights**. This attack must be **performed on each and every domain controller for complete compromise, but even targeting a single domain controller can be effective**. **Rebooting** a domain controller **will remove this malware** and it will have to be redeployed by the attacker.

#### Performing the Skeleton Key Attack

Performing the attack is very straightforward to do. It only requires the following **command to be run on each domain controller**: `misc::skeleton`. After that, you can authenticate as any user with the default password of Mimikatz.

![Injecting a skeleton key using the misc::skeleton into a domain controller with Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/1-3.png)

Here is an authentication for a Domain Admin member using the skeleton key as a password to get administrative access to a domain controller: 

![Using the skeleton key as a password with the misc::skeleton command to get administrative access to a domain controller with the default password of Mimikatz](https://blog.stealthbits.com/wp-content/uploads/2017/07/2-5.png)

Note: If you do get a message saying, “System error 86 has occurred. The specified network password is not correct”, just try using the domain\account format for the username and it should work. 

![Using the domain\account format for the username if you get a message saying System error 86 has occurred The specified network password is not correct](https://blog.stealthbits.com/wp-content/uploads/2017/07/3-3.png)

If lsass was **already patched** with skeleton, then this **error** will appear:

![](../../.gitbook/assets/image%20%28267%29.png)

### Mitigations

Skeleton Key

* Events:
  * System Event ID 7045 - A service was installed in the system. \(Type Kernel Mode driver\)
  * Security Event ID 4673 – Sensitive Privilege Use \("Audit privilege use" must be enabled\)
  * Event ID 4611 – A trusted logon process has been registered with the Local Security Authority \("Audit privilege use" must be enabled\)
* `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "`_`Kernel Mode Driver"}`_
* This only detect mimidrv `Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$`_`.message -like "Kernel Mode Driver" -and $`_`.message -like "`_`mimidrv`_`"}`
* Mitigation:
  * Run lsass.exe as a protected process, it forces an attacker to load a kernel mode driver
  * `New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name RunAsPPL -Value 1 -Verbose`
  * Verify after reboot: `Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "`_`protected process"}`_


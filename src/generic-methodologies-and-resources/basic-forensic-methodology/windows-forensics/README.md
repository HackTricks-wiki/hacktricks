# Windows Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Generic Windows Artifacts

### Windows 10 Notifications

The per-user notification database is under `%LOCALAPPDATA%\Microsoft\Windows\Notifications` (for example, `C:\Users\<username>\AppData\Local\Microsoft\Windows\Notifications`). Early Windows 10 releases used `appdb.dat`; the Anniversary Update (1607) introduced `wpndatabase.db`. The SQLite database includes a `Notification` table with notification payloads and timing fields, although retention and available data vary by release and cleanup policy.<sup>[[3]](#references)</sup>

### Timeline

Windows Timeline is an activity-history feature that can contain records for supported applications, documents, and other user activity; its coverage depends on the application and Windows version.<sup>[[4]](#references)</sup>

The database resides at `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. It can be opened with SQLite or parsed with [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd), whose output can be reviewed with [**Timeline Explorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[4]](#references)[[5]](#references)</sup>

### ADS (Alternate Data Streams)

Files downloaded from outside the local trust boundary may contain the **`Zone.Identifier` alternate data stream**, which records zone information and can include origin metadata such as a URL. Its presence and fields depend on the producer and system policy.<sup>[[6]](#references)</sup>

## **File Backups**

### Recycle Bin

On Vista and later, the **Recycle Bin** can be found in the folder **`$Recycle.bin`** in the root of the drive (for example, `C:\$Recycle.bin`).\
When a file is deleted in this folder 2 specific files are created:

- `$I{id}`: File information, including the deletion time and original path
- `$R{id}`: Content of the file

![File Backups - Recycle Bin: $R{id}: Content of the file](<../../../images/image (1029).png>)

Having these files, you can use [**Rifiuti2**](https://github.com/abelcheung/rifiuti2) to extract the original path and deletion time (use the version appropriate for the target Windows release).<sup>[[7]](#references)</sup>

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![File Backups - Recycle Bin: rifiuti-vista.exe C: Users student Desktop Recycle](<../../../images/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Volume Shadow Copy Service (VSS) can create point-in-time shadow copies of volumes while files are in use; a shadow copy is not a substitute for a forensic image.<sup>[[8]](#references)</sup>

The copy metadata is normally associated with `\System Volume Information` at the volume root, with identifiers that vary by system:

![Recycle Bin - Volume Shadow Copies: These backups are usually located in the System Volume Information from the root of the file system and the name is composed of UIDs shown in the...](<../../../images/image (94).png>)

After mounting an image with a suitable forensic mounter, [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow_copy_view.html) can enumerate available VSS snapshots and browse or copy files from them.<sup>[[9]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: Mounting the forensics image with the ArsenalImageMounter , the tool ShadowCopyView can be used to inspect a shadow copy and even extract the files...](<../../../images/image (576).png>)

The VSS registry writer configuration includes `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore`, which can specify files and keys excluded from backup:<sup>[[10]](#references)[[11]](#references)</sup>

![Recycle Bin - Volume Shadow Copies: The registry entry HKEY LOCAL MACHINE SYSTEM CurrentControlSet Control BackupRestore contains the files and keys to not backup](<../../../images/image (254).png>)

The `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` key also contains VSS service configuration.<sup>[[8]](#references)</sup>

### Office AutoSaved Files

AutoRecover locations vary by Office application, version, and configuration. For Word, Microsoft documents `%APPDATA%\Microsoft\Word` as the default location; check the application settings for the active path.<sup>[[12]](#references)</sup>

## Shell Items

A shell item is an item that contains information about how to access another file.

### Recent Documents (LNK)

Windows commonly creates recent-item shortcuts when a user opens or otherwise accesses an item:

- Win7-Win10: `%APPDATA%\Microsoft\Windows\Recent\`
- Office: `%APPDATA%\Microsoft\Office\Recent\`

Folder access may also create links for the folder and related parent folders.

These link files can contain the target type, target MAC times, volume information, and target path. That metadata may help identify a removed target, but the artifact is not itself proof that the target was opened by a particular user.<sup>[[13]](#references)[[14]](#references)</sup>

The LNK's own filesystem timestamps and its embedded target timestamps are distinct. Do not interpret link creation as the first use or link modification as the last use without corroborating artifacts; the format stores target timestamps separately from the link file's timestamps.<sup>[[13]](#references)[[14]](#references)</sup>

The existing [**LinkParser**](http://4discovery.com/our-tools/) link is retained as a historical option, but its documentation was unavailable during review. For a documented command-line parser, use [**LECmd**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

These tools commonly expose two sets of timestamps:

- **Target timestamps:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
- **Link-file timestamps:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

The first set refers to the target; the second set refers to the LNK file itself. Interpret both with the parser's documentation and filesystem context.<sup>[[14]](#references)[[15]](#references)</sup>

You can get the same information running the Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd).<sup>[[15]](#references)</sup>

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In this case, the information is going to be saved inside a CSV file.

### Jumplists

Jump Lists are per-application lists of recent or task-specific items and can be automatic or custom.<sup>[[13]](#references)</sup>

Automatic Jump Lists are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` and use names such as `{id}.automaticDestinations-ms`, where the ID identifies the application.

Custom Jump Lists are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\`; the application controls which task or item entries it creates.

The filesystem created and modified times describe the Jump List file, not automatically the first and last access to every listed target. Correlate parsed entries with the file's timestamps and other artifacts.<sup>[[13]](#references)</sup>

You can inspect the Jump Lists using [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)</sup>

![Recent Documents (LNK) - Jumplists: You can inspect the jumplists using JumplistExplorer](<../../../images/image (168).png>)

(_Note that the timestamps provided by JumplistExplorer are related to the jumplist file itself_)

### Shellbags

[**Follow this link to learn what are the shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Use of Windows USBs

USB use can sometimes be corroborated by artifacts created when files are accessed from removable media, including:

- Windows Recent Folder
- Microsoft Office Recent Folder
- Jumplists

Tools such as [**USBDetective**](https://usbdetective.com) correlate these artifacts with USB device records, but artifact availability depends on the Windows version and application.<sup>[[18]](#references)</sup>

In testing documented for Windows XP and Windows 7 MTP workflows, some LNKs pointed to a `WPDNSE` folder rather than the original path.<sup>[[16]](#references)</sup>

![Shellbags - Use of Windows USBs: Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder](<../../../images/image (218).png>)

That study observed copies under `%LOCALAPPDATA%\Temp\WPDNSE\{FolderGUID}`; the temporary contents did not survive a restart in its tests, and the GUID could be correlated with shellbag data. Treat this as an OS-, device-, and application-dependent behavior rather than a universal rule.<sup>[[16]](#references)</sup>

### Registry Information

[Check this page to learn](interesting-windows-registry-keys.md#usb-information) which registry keys contain interesting information about USB connected devices.

### setupapi

On Vista and later, inspect `C:\Windows\inf\setupapi.dev.log` for device-installation activity. Section headers include `Section start` timestamps; they document setup processing and should be correlated with other connection evidence rather than treated as an exact physical insertion time.<sup>[[17]](#references)</sup>

![Registry Information - setupapi: Check the file C: Windows inf setupapi.dev.log to get the timestamps about when the USB connection was produced (search for Section start)](<../../../images/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (14) (2).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) can be used to obtain information about the USB devices that have been connected to an image.<sup>[[18]](#references)</sup>

![setupapi - USB Detective: USBDetective can be used to obtain information about the USB devices that have been connected to an image](<../../../images/image (452).png>)

### Plug and Play Cleanup

The scheduled task known as `Plug and Play Cleanup` removes outdated driver versions. A Windows 10 task definition documented by Adam Harrison also targets drivers inactive for 30 days, so removable-device driver evidence may be cleaned up; confirm the local task definition and Windows build before generalizing this behavior.<sup>[[1]](#references)</sup>

The task is located at the following path: `C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup`.

![XML definition of the Windows Plug and Play Cleanup scheduled task](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

**Key Components and Settings of the Task:**

- **pnpclean.dll**: This DLL is responsible for the actual cleanup process.
- **UseUnifiedSchedulingEngine**: Set to `TRUE`, indicating the use of the generic task scheduling engine.
- **MaintenanceSettings**:
  - **Period ('P1M')**: Directs the Task Scheduler to initiate the cleanup task monthly during regular Automatic maintenance.
  - **Deadline ('P2M')**: Instructs the Task Scheduler, if the task fails for two consecutive months, to execute the task during emergency Automatic maintenance.

This configuration schedules regular maintenance and retries after consecutive failures; the exact XML and behavior are version-dependent.<sup>[[1]](#references)</sup>

**For more information check:** [**https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html).<sup>[[1]](#references)</sup>

## Emails

Emails contain **2 interesting parts: The headers and the content** of the email. In the **headers** you can find information like:

- **Who** sent the emails (email address, IP, mail servers that have redirected the email)
- **When** was the email sent

Also, the `References` and `In-Reply-To` headers can carry message IDs used to associate replies with a conversation.<sup>[[76]](#references)</sup>

![Plug and Play Cleanup - Emails: When was the email sent](<../../../images/image (593).png>)

### Windows Mail App

This application saves email content in auxiliary text or HTML files under paths such as `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`; the exact numbered folder and file layout can vary by artifact.<sup>[[75]](#references)</sup>

The **metadata** of the emails and the **contacts** can be found inside the **ESE database** `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`.<sup>[[75]](#references)</sup>

`store.vol` uses the Extensible Storage Engine (ESE) format. Work on a copy and use an ESE parser such as [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html); if a tool requires an `.edb` suffix, rename only the copy, and verify the table schema before relying on a `Message` table.<sup>[[19]](#references)[[75]](#references)</sup>

### Microsoft Outlook

When inspecting Outlook MAPI properties, canonical properties include:

- `PidTagClientSubmitTime`: the UTC time at which the client submitted the message.
- `PidTagConversationIndex`: the message's relative position in a conversation thread.
- `PidTagEntryId`: an identifier for the message object.
- `PidTagMessageFlags`: status flags such as submitted, read, unread, or having attachments.
- `PidTagLastVerbExecuted`: the last operation recorded for the message, such as open, reply, or forward.<sup>[[20]](#references)[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Outlook data-file locations vary by version and account type. Microsoft documents these common locations for PST/OST files:

- `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
- `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

The registry path `HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` may identify the Outlook profile and associated data-file configuration.

PST files can contain messages, contacts, calendar data, and other Outlook items. You can inspect a copy with [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).<sup>[[25]](#references)[[67]](#references)</sup>

![Windows Mail App - Microsoft Outlook: You can open the PST file using the tool Kernel PST Viewer](<../../../images/image (498).png>)

### Microsoft Outlook OST Files

An **OST file** is a local cache for Exchange or Microsoft 365 accounts; Cached Exchange Mode does not apply to POP or IMAP accounts. The offline period is configurable and is often 12 months by default, while PST/OST size limits are separate configurable settings. To view an OST file, the [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html) can be utilized.<sup>[[26]](#references)[[27]](#references)[[28]](#references)[[68]](#references)</sup>

### Retrieving Attachments

Lost attachments might be recoverable from:

- For legacy Outlook/IE configurations: `%LOCALAPPDATA%\Temporary Internet Files\Content.Outlook`
- For newer Outlook/IE11 configurations: `%LOCALAPPDATA%\Microsoft\Windows\INetCache\Content.Outlook`.<sup>[[65]](#references)</sup>

### Thunderbird MBOX Files

**Thunderbird** stores profile data under `%APPDATA%\Thunderbird\Profiles`; mail folders commonly use extensionless mbox files under account-specific `Mail` or `ImapMail` directories.<sup>[[29]](#references)[[30]](#references)</sup>

### Image Thumbnails

- **Windows XP**: Thumbnail previews were commonly stored in per-folder `thumbs.db` files.
- **Network folders**: A `thumbs.db` file may still be created for a UNC folder when the relevant thumbnail behavior is enabled; do not assume that every Windows version or policy creates one.
- **Windows Vista and newer**: The system thumbnail cache is centralized under `%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer` with files such as **thumbcache_xxx.db**. [**Thumbsviewer**](https://thumbsviewer.github.io) can parse legacy `Thumbs.db`, while [**ThumbCache Viewer**](https://thumbcacheviewer.github.io) can parse modern thumbnail-cache databases.<sup>[[31]](#references)[[32]](#references)[[33]](#references)</sup>

### Windows Registry Information

The Windows Registry, storing system and user configuration data, is contained within hive files in:

- `%WINDIR%\System32\Config` for the machine hives backing various `HKEY_LOCAL_MACHINE` subkeys.
- `%USERPROFILE%\NTUSER.DAT` for a user's `HKEY_CURRENT_USER` hive.
- Some older Windows installations contain copies in `%WINDIR%\System32\Config\RegBack\`; Windows 10 version 1803 and later do not automatically populate this directory unless periodic backup is enabled.<sup>[[34]](#references)[[35]](#references)</sup>
- Per-user shell and class-registration data is also commonly stored in `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` on modern Windows.<sup>[[34]](#references)[[66]](#references)</sup>

### Tools

Some tools are useful to analyze registry hives; confirm each tool's supported hive formats and version before relying on an output:

- **Registry Editor**: It's installed in Windows. It's a GUI to navigate through the Windows registry of the current session.
- [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): It allows you to load the registry file and navigate through them with a GUI. It also contains Bookmarks highlighting keys with interesting information.
- [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Again, it has a GUI that allows to navigate through the loaded registry and also contains plugins that highlight interesting information inside the loaded registry.
- [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Another GUI application capable of extracting information from a loaded registry hive.<sup>[[5]](#references)[[36]](#references)[[37]](#references)</sup>

### Recovering Deleted Element

Deleted hive cells may remain until their space is reused, but recovery depends on the hive state and parser; treat recovered deleted keys as evidence requiring validation rather than guaranteed records.

### Last Write Time

Registry keys carry a last-write timestamp; Windows exposes it for the key or any of its value entries, so a value does not necessarily have its own independent modification timestamp.<sup>[[69]](#references)</sup>

### SAM

The **SAM** hive contains local user and group account data, including password hashes protected by the system's boot-key material.<sup>[[38]](#references)[[39]](#references)</sup>

In `SAM\Domains\Account\Users` you can obtain account identifiers and some logon and policy fields. Offline hash extraction also requires the `SYSTEM` hive to recover the relevant boot-key material.<sup>[[38]](#references)[[39]](#references)</sup>

### Interesting entries in the Windows Registry


{{#ref}}
interesting-windows-registry-keys.md
{{#endref}}

## Programs Executed

### Basic Windows Processes

An existing [post on common Windows processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d) is retained as additional reading; corroborate any process-behavior claims with current Windows documentation and local evidence.<sup>[[2]](#references)</sup>

### Windows Recent APPs

On Windows 10 versions that expose it, `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` contains per-application subkeys with fields such as a last-used time and launch count; the artifact was removed from later releases, so validate the target build.<sup>[[64]](#references)</sup>

### BAM (Background Activity Moderator)

On systems that expose the Background Activity Moderator, inspect `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` or the newer `...\bam\State\UserSettings\{SID}` path. Values are keyed by user SID and can contain tracked executable paths and FILETIME-like execution data; the artifact is version-dependent and should be corroborated with other evidence.<sup>[[63]](#references)</sup>

### Windows Prefetch

Prefetching caches resources and launch metadata so programs can start more quickly.

Prefetch files are stored as `.pf` files in `C:\Windows\Prefetch`; format, retention, and file-count limits vary by Windows version. Microsoft documents retention of the last eight execution times and up to 1024 files on Windows 8 and later, so older fixed-limit summaries should not be generalized.<sup>[[13]](#references)</sup>

The filename commonly uses `{program_name}-{hash}.pf`, with the hash derived from execution context such as path and arguments; Windows 10 and later may compress the file. Presence is useful execution evidence, but it is not by itself proof of a user's execution and should be correlated with other artifacts.<sup>[[13]](#references)</sup>

To inspect these files you can use [**PECmd.exe**](https://github.com/EricZimmerman/PECmd), which documents directory parsing, CSV/HTML output, and decompression support for applicable Windows 10 Prefetch files.<sup>[[40]](#references)</sup>

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![BAM (Background Activity Moderator) - Windows Prefetch: PECmd.exe -d C: Users student Desktop Prefetch --html "C: Users student Desktop out folder"](<../../../images/image (315).png>)

### Superprefetch

**Superfetch/SysMain** complements Prefetch by using historical usage patterns to improve loading. On systems that generate them, its database files are commonly found as `C:\Windows\Prefetch\Ag*.db`; the format and presence are version-dependent.<sup>[[41]](#references)</sup>

These databases may contain application names, usage counts, accessed files or volumes, paths, and time ranges, but they should not be treated as an exact execution log.<sup>[[41]](#references)</sup>

The existing [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) link is retained as a possible parser; verify its current availability and supported output against the tool's documentation before use.

### SRUM

**System Resource Usage Monitor** (SRUM) records resource use by applications and users. It was introduced in Windows 8 and stores data in the ESE database `C:\Windows\System32\sru\SRUDB.dat`.<sup>[[13]](#references)</sup>

It gives the following information:

- AppID and Path
- User/SID associated with the record
- Sent Bytes
- Received Bytes
- Network Interface
- Connection duration
- Process duration

The collection cadence and retention are implementation-dependent; do not assume that every record represents an exact 60-minute execution interval.<sup>[[13]](#references)</sup>

You can extract and review data with [**srum_dump**](https://github.com/MarkBaggett/srum-dump), using the options documented by the current tool version.<sup>[[42]](#references)</sup>

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -o C:\Users\student\Desktop\srum --NO_CONFIRM
```

### AppCompatCache (ShimCache)

The **AppCompatCache**, also known as **ShimCache**, is part of Windows application-compatibility infrastructure and records file metadata for compatibility decisions. The hive path, record format, retained capacity, and fields vary by Windows release; on modern Windows, ShimCache alone cannot prove that a user executed a file. Parse the relevant `SYSTEM` hive with the [**AppCompatCacheParser** tool](https://github.com/EricZimmerman/AppCompatCacheParser) and corroborate its output with execution artifacts.<sup>[[13]](#references)[[43]](#references)</sup>

![SRUM - AppCompatCache (ShimCache): To parse the stored information, the AppCompatCacheParser tool is recommended for use](<../../../images/image (75).png>)

### Amcache

The **Amcache.hve** file is a registry hive that inventories applications and files observed by Windows. It is typically found at `C:\Windows\AppCompat\Programs\Amcache.hve`.

It can contain associated and unassociated file entries, paths, and SHA1 values, but its presence is inventory evidence and does not by itself prove that a process executed.<sup>[[13]](#references)[[44]](#references)</sup>

To extract and analyze **Amcache.hve**, use the [**AmcacheParser**](https://github.com/EricZimmerman/AmcacheParser) tool. This command parses the hive and writes CSV output.<sup>[[44]](#references)</sup>

For example:

```bash
AmcacheParser.exe -f C:\Users\genericUser\Desktop\Amcache.hve --csv C:\Users\genericUser\Desktop\outputFolder
```

Among the generated CSV files, `Amcache_Unassociated file entries` can be useful when investigating files that are not associated with a recognized program.<sup>[[44]](#references)</sup>

### RecentFileCache

On Windows 7 systems, `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` may contain information about recently observed binaries; availability and semantics are version-dependent.

You can use [**RecentFileCacheParser**](https://github.com/EricZimmerman/RecentFileCacheParser) to parse the file.<sup>[[45]](#references)</sup>

### Scheduled tasks

Scheduled-task evidence may be found in `C:\Windows\System32\Tasks` for modern tasks and `C:\Windows\Tasks` with `.job` files for legacy tasks; inspect the task definition format appropriate to the OS.<sup>[[73]](#references)[[74]](#references)</sup>

### Services

The Service Control Manager database is under `SYSTEM\CurrentControlSet\Services` (for an offline SYSTEM hive, inspect the corresponding control-set key); it contains service and driver configuration such as executable paths and start types.<sup>[[72]](#references)</sup>

### **Windows Store**

Installed Windows Store applications may be represented under `\ProgramData\Microsoft\Windows\AppRepository\`, including the database **`StateRepository-Machine.srd`**. The schema and paths vary by Windows release.<sup>[[71]](#references)</sup>

The database can contain application identifiers, package numbers, and display names. Gaps in identifiers are not, by themselves, proof that an application was uninstalled; corroborate with package and registry state.

Package registrations can also appear under `HKLM\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`. Microsoft documents a version-specific `Deprovisioned` subkey for removed provisioned apps; do not assume that a `Deleted` subkey exists on every build.<sup>[[70]](#references)</sup>

## Windows Events

Depending on the provider, Windows events can contain:

- What happened
- A `TimeCreated` timestamp that must be interpreted with the event schema and host time context
- Users involved
- Hosts involved (hostname, IP)
- Assets accessed (files, folders, printers, or services).<sup>[[49]](#references)</sup>

Before Windows Vista, event logs generally used the legacy binary format under `C:\Windows\System32\config`; Vista and later use the Windows Event Log format, normally under `C:\Windows\System32\winevt\Logs`, with `.evtx` files containing XML-rendered event data.<sup>[[46]](#references)[[47]](#references)</sup>

The SYSTEM registry stores channel configuration under **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**, including the configured file path and retention settings.<sup>[[47]](#references)</sup>

They can be viewed with Windows Event Viewer (**`eventvwr.msc`**) or tools such as [**Event Log Explorer**](https://eventlogxp.com) and [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md).<sup>[[5]](#references)[[48]](#references)[[61]](#references)</sup>

## Understanding Windows Security Event Logging

On Vista and later, the Security channel is commonly stored at `C:\Windows\System32\winevt\Logs\Security.evtx`. Its maximum size and retention policy are configurable; with circular logging, older records can be overwritten when the file reaches its limit. The channel can record authentication, logoff, privilege, audit-policy, and object-access events when the relevant auditing is enabled.<sup>[[46]](#references)[[47]](#references)</sup>

### Key Event IDs for User Authentication:

- **Event ID 4624**: A successful account logon.<sup>[[50]](#references)</sup>
- **Event ID 4625**: A failed account logon.<sup>[[51]](#references)</sup>
- **Event ID 4634**: A logon session was terminated.<sup>[[52]](#references)</sup>
- **Event ID 4647**: A user initiated a logoff.<sup>[[53]](#references)</sup>
- **Event ID 4672**: Special privileges were assigned to a new logon; this is common for system and administrator accounts, so it is not by itself proof of malicious activity.<sup>[[54]](#references)</sup>

#### Logon types commonly recorded in 4624, 4625, 4634, and 4647:

- **Interactive (2)**: An interactive local logon.
- **Network (3)**: Access to a shared resource.
- **Batch (4)**: A batch-process logon.
- **Service (5)**: A service logon.
- **Unlock (7)**: A workstation unlock.
- **NetworkCleartext (8)**: A network logon that supplies credentials in cleartext to the authentication package.
- **NewCredentials (9)**: A logon using supplied alternate credentials for outbound connections.
- **RemoteInteractive (10)**: Remote Desktop or Terminal Services logon.
- **CachedInteractive (11)**: An interactive logon using cached domain credentials.
- **CachedRemoteInteractive (12)**: A cached remote-interactive logon.
- **CachedUnlock (13)**: An unlock using cached credentials.<sup>[[50]](#references)[[51]](#references)</sup>

#### Status and Sub Status Codes for EventID 4625:

- **0xC0000064**: No such user.
- **0xC000006A**: Correct user name but wrong password.
- **0xC0000234**: Account locked out.
- **0xC0000072**: Account disabled.
- **0xC000006F**: Logon outside allowed hours.
- **0xC0000070**: Workstation restriction violation.
- **0xC0000193**: Account expired.
- **0xC0000071**: Password expired.
- **0xC0000133**: The client and server time difference is too large.
- **0xC0000224**: The account must change its password.
- **0xC0000225**: `STATUS_NOT_FOUND`; the code alone does not identify a system bug or an attack.
- **0xC000015B**: The requested logon type is not granted to the account.<sup>[[51]](#references)[[55]](#references)</sup>

#### EventID 4616:

- **Time Change**: The system time was changed. Many events reflect routine time-service correction, so correlate the actor and time source before treating it as tampering.<sup>[[56]](#references)</sup>

#### Event IDs 12, 13, 1074, 6005, 6006, 6008, and 6009:

- **Power and service context**: Event 12 records OS start, 13 records OS shutdown, 1074 records a planned shutdown or restart, 6008 indicates an unexpected shutdown, and 6009 records the Windows version at boot. Events 6005 and 6006 indicate that the Event Log service started and stopped, respectively; they are not themselves proof of OS startup and shutdown.<sup>[[57]](#references)[[58]](#references)</sup>

#### EventID 1102:

- **Log Deletion**: Event 1102 records that the Security audit log was cleared; investigate the actor and surrounding events rather than assuming intent from this event alone.<sup>[[62]](#references)</sup>

#### EventIDs for USB Device Tracking:

- **20001 / 20003**: `UserPnp` device-installation events that can help establish first-use or installation activity.
- **10000 / 10100**: `DriverFrameworks-UserMode` events that may accompany device activity.
- **Event ID 112**: `DeviceSetupManager/Admin` activity that can provide insertion-related timestamps.
- Provider, channel, and event semantics vary by Windows version; inspect the provider name and event payload before assigning meaning.<sup>[[59]](#references)</sup>

For practical examples on logon types and their associated credential material, see [Altered Security's detailed guide](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them).<sup>[[60]](#references)</sup>

Event details, including the logon type, status, substatus, source address, and process fields, provide context for Event ID 4625; a status code or repeated failure pattern is an investigative lead, not a conclusion.<sup>[[51]](#references)[[55]](#references)</sup>

### Recovering Windows Events

Because event logs are commonly circular, records overwritten by the logger may be unrecoverable. Preserve a forensic image or working copy before interacting with a live system; use a validated parser or carver such as **Bulk_extractor** only after confirming that the tool version supports the target `.evtx` data, and do not unplug a running system solely to try to recover events.<sup>[[46]](#references)</sup>

### Identifying Common Attacks via Windows Events

For a practical event-ID reference, see the existing [Red Team Recipe](https://redteamrecipe.com/event-codes/) link and validate its examples against the provider documentation above.

#### Brute Force Attacks

Correlate repeated Event ID 4625 failures with a later 4624 success, logon type, status, source, and account context; the sequence is an indicator for investigation, not proof of an attack.<sup>[[50]](#references)[[51]](#references)</sup>

#### Time Change

Event ID 4616 records system-time changes, which can complicate timeline analysis; compare it with time-service and host evidence.<sup>[[56]](#references)</sup>

#### USB Device Tracking

USB event IDs are provider-specific; correlate `UserPnp` 20001/20003, `DriverFrameworks-UserMode` 10000/10100, and `DeviceSetupManager/Admin` 112 with SetupAPI and registry artifacts.<sup>[[17]](#references)[[59]](#references)</sup>

#### System Power Events

Use 12/13/1074/6008/6009 for OS start, shutdown, restart, and unexpected-power context; 6005/6006 mark Event Log service start/stop.<sup>[[57]](#references)[[58]](#references)</sup>

#### Log Deletion

Security Event ID 1102 records that the Security audit log was cleared and should be correlated with the responsible account and process.<sup>[[62]](#references)</sup>

## References

- [1] [Windows Plug and Play Cleanup](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)
- [2] [jonahacks.medium.com - Investigating Common Windows Processes](https://jonahacks.medium.com/investigating-common-windows-processes-18dee5f97c1d)
- [3] [A Digital Forensic View of Windows 10 Notifications](https://iconline.ipleiria.pt/server/api/core/bitstreams/833e160a-e382-46b4-82ad-fb2c8c995d62/content)
- [4] [WxTCmd](https://github.com/EricZimmerman/WxTCmd)
- [5] [Eric Zimmerman forensic tools](https://ericzimmerman.github.io/#!index.md)
- [6] [Zone.Identifier and Alternate Data Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/6e3f7352-d11c-4d76-8c39-2516a9df36e8)
- [7] [Rifiuti2](https://github.com/abelcheung/rifiuti2)
- [8] [Volume Shadow Copy Service](https://learn.microsoft.com/en-us/windows/server/storage/file-server/volume-shadow-copy-service)
- [9] [ShadowCopyView](https://www.nirsoft.net/utils/shadow_copy_view.html)
- [10] [Registry backup and restore operations under VSS](https://learn.microsoft.com/en-us/windows/win32/vss/registry-backup-and-restore-operations-under-vss)
- [11] [Registry keys for backup and restore](https://learn.microsoft.com/en-us/windows/win32/backup/registry-keys-for-backup-and-restore)
- [12] [Word performance issue on AutoRecover location](https://learn.microsoft.com/en-us/previous-versions/troubleshoot/microsoft-365/microsoft-365-apps/word/performance-issue-on-autorecover-location)
- [13] [Incident Response Guidebook](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/final/en-us/microsoft-brand/documents/IR-Guidebook-Final.pdf)
- [14] [MS-SHLLINK: Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15)
- [15] [LECmd](https://github.com/EricZimmerman/LECmd)
- [16] [USB MTP Forensics: Identifying Data Exfiltration Artifacts](https://studylib.net/doc/8690663/usb-devices-and-media-transfer-protocol)
- [17] [SetupAPI device installation log entries](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupapi-device-installation-log-entries)
- [18] [USB Detective](https://usbdetective.com)
- [19] [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)
- [20] [PidTagClientSubmitTime](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/ca98145f-7f87-42b4-b0ef-124c6c6f8d83)
- [21] [PidTagConversationIndex](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/57f8de0f-5f53-423a-8947-7943dd959997)
- [22] [EntryID and Related Types](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/57e8bcbf-11d0-40fe-8833-5558bb9c0c89)
- [23] [PidTagMessageFlags](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/a0c52fe2-3014-43a7-942d-f43f6f91c366)
- [24] [PidTagLastVerbExecuted](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxomsg/87a8b6b8-59a4-4859-9dcd-8b0f36e3d729?redirectedfrom=MSDN)
- [25] [Find and transfer Outlook data files](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another)
- [26] [Turn on Cached Exchange Mode](https://support.microsoft.com/en-us/outlook/turn-on-cached-exchange-mode)
- [27] [Only a subset of items is synchronized](https://learn.microsoft.com/en-us/troubleshoot/outlook/user-interface/only-subset-items-synchronized)
- [28] [Configure size limits for Outlook data files](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/data-files/configure-size-limit-outlook-data-files)
- [29] [Profiles - Where Thunderbird stores user data](https://support.mozilla.org/bm/kb/profiles-where-thunderbird-stores-user-data)
- [30] [Thunderbird account settings and mbox directories](https://support.mozilla.org/en-US/kb/dangerous-directories-Thunderbird-account-settings)
- [31] [IThumbnailCache interface](https://learn.microsoft.com/en-us/windows/win32/api/thumbcache/nn-thumbcache-ithumbnailcache)
- [32] [Thumbs Viewer](https://thumbsviewer.github.io)
- [33] [Thumbcache Viewer](https://thumbcacheviewer.github.io)
- [34] [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)
- [35] [System registry not backed up to RegBack](https://learn.microsoft.com/en-gb/troubleshoot/windows-client/installing-updates-features-roles/system-registry-no-backed-up-regback-folder)
- [36] [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [37] [Windows Registry Recovery](https://www.mitec.cz/wrr.html)
- [38] [Remotely edit the registry](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/remotely-edit-the-registry)
- [39] [Passwords technical overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/passwords-technical-overview)
- [40] [PECmd](https://github.com/EricZimmerman/PECmd)
- [41] [Superfetch evidence](https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/superfetch)
- [42] [srum-dump](https://github.com/MarkBaggett/srum-dump)
- [43] [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [44] [AmcacheParser](https://github.com/EricZimmerman/AmcacheParser)
- [45] [RecentFileCacheParser](https://github.com/EricZimmerman/RecentFileCacheParser)
- [46] [Event Log File Format](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-file-format)
- [47] [Eventlog registry key](https://learn.microsoft.com/en-us/windows/win32/eventlog/eventlog-key)
- [48] [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [49] [TimeCreated event property](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-timecreated-systempropertiestype-element)
- [50] [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [51] [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- [52] [Event 4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- [53] [Event 4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647)
- [54] [Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [55] [MS-ERREF: NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
- [56] [Event 4616](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616)
- [57] [Troubleshoot unexpected reboots using system event logs](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [58] [Troubleshoot shutdown in process](https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-error-shutdown-in-process)
- [59] [USB Storage Device Forensics for Windows 10](https://www.researchgate.net/publication/318514858_USB_Storage_Device_Forensics_for_Windows_10)
- [60] [Fantastic Windows Logon Types](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)
- [61] [Event Log Explorer](https://eventlogxp.com)
- [62] [Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
- [63] [Background activity moderator](https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html)
- [64] [Registry - RecentApps](https://artefacts.help/windows_registry_recentapps.html)
- [65] [Quick Print stops printing PDF attachments in Outlook Desktop](https://support.microsoft.com/en-gb/office/quick-print-stops-printing-pdf-attachments-in-outlook-desktop-512fdeb0-6a88-4e6c-9285-cf957290aad2)
- [66] [Windows Registry files](https://winreg-kb.readthedocs.io/en/latest/sources/windows-registry/Files.html)
- [67] [Kernel PST Viewer](https://www.nucleustechnologies.com/es/visor-de-pst.html)
- [68] [Kernel OST Viewer](https://www.nucleustechnologies.com/ost-viewer.html)
- [69] [RegQueryInfoKeyA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya)
- [70] [Keep removed apps from returning during an update](https://learn.microsoft.com/en-us/windows/application-management/remove-provisioned-apps-during-update)
- [71] [NIST CFTT: FTK and Registry Viewer Test Results](https://www.dhs.gov/sites/default/files/publications/test_results_nist_windows_registry_forensic_tool_ftk_7.0.0.163_registry_viewer_2.0.0.7_april_2019.pdf)
- [72] [Database of Installed Services](https://learn.microsoft.com/en-us/windows/win32/services/database-of-installed-services)
- [73] [Tasks](https://learn.microsoft.com/en-us/windows/win32/taskschd/tasks)
- [74] [Scheduled Tasks Fail with Error Task Scheduler Service Is Not Available](https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/task-schedular-service-is-not-available)
- [75] [Navigating the Windows Mail database](https://eprints.whiterose.ac.uk/133161/1/Navigating_the_Windows_Mail_database_accepted.pdf)
- [76] [RFC 5322: Internet Message Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4)

{{#include ../../../banners/hacktricks-training.md}}

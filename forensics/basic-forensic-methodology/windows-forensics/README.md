# Windows Artifacts

## Windows Artifacts

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Generic Windows Artifacts

### Windows 10 Notifications

In the path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` you can find the database `appdb.dat` (before Windows anniversary) or `wpndatabase.db` (after Windows Anniversary).

Inside this SQLite database, you can find the `Notification` table with all the notifications (in XML format) that may contain interesting data.

### Timeline

Timeline is a Windows characteristic that provides **chronological history** of web pages visited, edited documents, and executed applications.

The database resides in the path `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`. This database can be opened with an SQLite tool or with the tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) **which generates 2 files that can be opened with the tool** [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

### ADS (Alternate Data Streams)

Files downloaded may contain the **ADS Zone.Identifier** indicating **how** it was **downloaded** from the intranet, internet, etc. Some software (like browsers) usually put even **more** **information** like the **URL** from where the file was downloaded.

## **File Backups**

### Recycle Bin

In Vista/Win7/Win8/Win10 the **Recycle Bin** can be found in the folder **`$Recycle.bin`** in the root of the drive (`C:\$Recycle.bin`).\
When a file is deleted in this folder 2 specific files are created:

* `$I{id}`: File information (date of when it was deleted}
* `$R{id}`: Content of the file

![](<../../../.gitbook/assets/image (486).png>)

Having these files you can use the tool [**Rifiuti**](https://github.com/abelcheung/rifiuti2) to get the original address of the deleted files and the date it was deleted (use `rifiuti-vista.exe` for Vista – Win10).

```
.\rifiuti-vista.exe C:\Users\student\Desktop\Recycle
```

![](<../../../.gitbook/assets/image (495) (1) (1) (1).png>)

### Volume Shadow Copies

Shadow Copy is a technology included in Microsoft Windows that can create **backup copies** or snapshots of computer files or volumes, even when they are in use.

These backups are usually located in the `\System Volume Information` from the root of the file system and the name is composed of **UIDs** shown in the following image:

![](<../../../.gitbook/assets/image (520).png>)

Mounting the forensics image with the **ArsenalImageMounter**, the tool [**ShadowCopyView**](https://www.nirsoft.net/utils/shadow\_copy\_view.html) can be used to inspect a shadow copy and even **extract the files** from the shadow copy backups.

![](<../../../.gitbook/assets/image (521).png>)

The registry entry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BackupRestore` contains the files and keys **to not backup**:

![](<../../../.gitbook/assets/image (522).png>)

The registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSS` also contains configuration information about the `Volume Shadow Copies`.

### Office AutoSaved Files

You can find the office autosaved files in: `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

A shell item is an item that contains information about how to access another file.

### Recent Documents (LNK)

Windows **automatically** **creates** these **shortcuts** when the user **open, uses or creates a file** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

When a folder is created, a link to the folder, to the parent folder, and the grandparent folder is also created.

These automatically created link files **contain information about the origin** like if it's a **file** **or** a **folder**, **MAC** **times** of that file, **volume information** of where is the file stored and **folder of the target file**. This information can be useful to recover those files in case they were removed.

Also, the **date created of the link** file is the first **time** the original file was **first** **used** and the **date** **modified** of the link file is the **last** **time** the origin file was used.

To inspect these files you can use [**LinkParser**](http://4discovery.com/our-tools/).

In this tools you will find **2 sets** of timestamps:

* **First Set:**
  1. FileModifiedDate
  2. FileAccessDate
  3. FileCreationDate
* **Second Set:**
  1. LinkModifiedDate
  2. LinkAccessDate
  3. LinkCreationDate.

The first set of timestamp references the **timestamps of the file itself**. The second set references the **timestamps of the linked file**.

You can get the same information running the Windows CLI tool: [**LECmd.exe**](https://github.com/EricZimmerman/LECmd)

```
LECmd.exe -d C:\Users\student\Desktop\LNKs --csv C:\Users\student\Desktop\LNKs
```

In this case, the information is going to be saved inside a CSV file.

### Jumplists

These are the recent files that are indicated per application. It's the list of **recent files used by an application** that you can access on each application. They can be created **automatically or be custom**.

The **jumplists** created automatically are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. The jumplists are named following the format `{id}.autmaticDestinations-ms` where the initial ID is the ID of the application.

The custom jumplists are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` and they are created by the application usually because something **important** has happened with the file (maybe marked as favorite)

The **created time** of any jumplist indicates the **the first time the file was accessed** and the **modified time the last time**.

You can inspect the jumplists using [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

![](<../../../.gitbook/assets/image (474).png>)

(_Note that the timestamps provided by JumplistExplorer are related to the jumplist file itself_)

### Shellbags

[**Follow this link to learn what are the shellbags.**](interesting-windows-registry-keys.md#shellbags)

## Use of Windows USBs

It's possible to identify that a USB device was used thanks to the creation of:

* Windows Recent Folder
* Microsoft Office Recent Folder
* Jumplists

Note that some LNK file instead of pointing to the original path, points to the WPDNSE folder:

![](<../../../.gitbook/assets/image (476).png>)

The files in the folder WPDNSE are a copy of the original ones, then won't survive a restart of the PC and the GUID is taken from a shellbag.

### Registry Information

[Check this page to learn](interesting-windows-registry-keys.md#usb-information) which registry keys contain interesting information about USB connected devices.

### setupapi

Check the file `C:\Windows\inf\setupapi.dev.log` to get the timestamps about when the USB connection was produced (search for `Section start`).

![](<../../../.gitbook/assets/image (477) (2) (2) (2) (2) (2) (2) (2) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (14).png>)

### USB Detective

[**USBDetective**](https://usbdetective.com) can be used to obtain information about the USB devices that have been connected to an image.

![](<../../../.gitbook/assets/image (483).png>)

### Plug and Play Cleanup

The 'Plug and Play Cleanup' scheduled task is responsible for **clearing** legacy versions of drivers. It would appear (based upon reports online) that it also picks up **drivers which have not been used in 30 days**, despite its description stating that "the most current version of each driver package will be kept". As such, **removable devices which have not been connected for 30 days may have their drivers removed**.

The scheduled task itself is located at ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, and its content is displayed below:

![](https://2.bp.blogspot.com/-wqYubtuR\_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

The task references 'pnpclean.dll' which is responsible for performing the cleanup activity additionally we see that the ‘UseUnifiedSchedulingEngine’ field is set to ‘TRUE’ which specifies that the generic task scheduling engine is used to manage the task. The ‘Period’ and ‘Deadline’ values of 'P1M' and 'P2M' within ‘MaintenanceSettings’ instruct Task Scheduler to execute the task once every month during regular Automatic maintenance and if it fails for 2 consecutive months, to start attempting the task during the emergency Automatic maintenance. **This section was copied from** [**here**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**.**

## Emails

Emails contain **2 interesting parts: The headers and the content** of the email. In the **headers** you can find information like:

* **Who** sent the emails (email address, IP, mail servers that have redirected the email)
* **When** was the email sent

Also, inside the `References` and `In-Reply-To` headers you can find the ID of the messages:

![](<../../../.gitbook/assets/image (484).png>)

### Windows Mail App

This application saves emails in HTML or text. You can find the emails inside subfolders inside `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. The emails are saved with the `.dat` extension.

The **metadata** of the emails and the **contacts** can be found inside the **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Change the extension** of the file from `.vol` to `.edb` and you can use the tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese\_database\_view.html) to open it. Inside the `Message` table you can see the emails.

### Microsoft Outlook

When Exchange servers or Outlook clients are used there are going to be some MAPI headers:

* `Mapi-Client-Submit-Time`: Time of the system when the email was sent
* `Mapi-Conversation-Index`: Number of children messages of the thread and timestamp of each message of the thread
* `Mapi-Entry-ID`: Message identifier.
* `Mappi-Message-Flags` and `Pr_last_Verb-Executed`: Information about the MAPI client (message read? no read? responded? redirected? out of the office?)

In the Microsoft Outlook client, all the sent/received messages, contacts data, and calendar data are stored in a PST file in:

* `%USERPROFILE%\Local Settings\Application Data\Microsoft\Outlook` (WinXP)
* `%USERPROFILE%\AppData\Local\Microsoft\Outlook`

The registry path `HKEY_CURRENT_USER\Software\Microsoft\WindowsNT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook` indicates the file that is being used.

You can open the PST file using the tool [**Kernel PST Viewer**](https://www.nucleustechnologies.com/es/visor-de-pst.html).

![](<../../../.gitbook/assets/image (485).png>)

### Outlook OST

When Microsoft Outlook is configured **using** **IMAP** or using an **Exchange** server, it generates an **OST** file that stores almost the same info as the PST file. It keeps the file synchronized with the server for the **last 12 months**, with a **max file-size of 50GB** and in the **same folder as the PST** file is saved. You can inspect this file using [**Kernel OST viewer**](https://www.nucleustechnologies.com/ost-viewer.html).

### Recovering Attachments

You may be able to find them in the folder:

* `%APPDATA%\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook` -> IE10
* `%APPDATA%\Local\Microsoft\InetCache\Content.Outlook` -> IE11+

### Thunderbird MBOX

**Thunderbird** stores the information in **MBOX** **files** in the folder `\Users\%USERNAME%\AppData\Roaming\Thunderbird\Profiles`

## Thumbnails

When a user accesses a folder and organised it using thumbnails, then a `thumbs.db` file is created. This db **stores the thumbnails of the images** of the folder even if they are deleted. In WinXP and Win 8-8.1 this file is created automatically. In Win7/Win10, it's created automatically if it's accessed via a UNC path (\IP\folder...).

It is possible to read this file with the tool [**Thumbsviewer**](https://thumbsviewer.github.io).

### Thumbcache

Beginning with Windows Vista, **thumbnail previews are stored in a centralized location on the system**. This provides the system with access to images independent of their location and addresses issues with the locality of Thumbs.db files. The cache is stored at **`%userprofile%\AppData\Local\Microsoft\Windows\Explorer`** as several files with the label **thumbcache\_xxx.db** (numbered by size); as well as an index used to find thumbnails in each sized database.

* Thumbcache\_32.db -> small
* Thumbcache\_96.db -> medium
* Thumbcache\_256.db -> large
* Thumbcache\_1024.db -> extra large

You can read this file using [**ThumbCache Viewer**](https://thumbcacheviewer.github.io).

## Windows Registry

The Windows Registry Contains a lot of **information** about the **system and the actions of the users**.

The files containing the registry are located in:

* %windir%\System32\Config\*_SAM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SECURITY\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SYSTEM\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_SOFTWARE\*_: `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\*_DEFAULT\*_: `HKEY_LOCAL_MACHINE`
* %UserProfile%{User}\*_NTUSER.DAT\*_: `HKEY_CURRENT_USER`

From Windows Vista and Windows 2008 Server upwards there are some backups of the `HKEY_LOCAL_MACHINE` registry files in **`%Windir%\System32\Config\RegBack\`**.

Also from these versions, the registry file **`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** is created saving information about program executions.

### Tools

Some tools are useful to analyze the registry files:

* **Registry Editor**: It's installed in Windows. It's a GUI to navigate through the Windows registry of the current session.
* [**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): It allows you to load the registry file and navigate through them with a GUI. It also contains Bookmarks highlighting keys with interesting information.
* [**RegRipper**](https://github.com/keydet89/RegRipper3.0): Again, it has a GUI that allows to navigate through the loaded registry and also contains plugins that highlight interesting information inside the loaded registry.
* [**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Another GUI application capable of extracting the important information from the registry loaded.

### Recovering Deleted Element

When a key is deleted it's marked as such, but until the space it's occupying is needed it won't be removed. Therefore, using tools like **Registry Explorer** it's possible to recover these deleted keys.

### Last Write Time

Each Key-Value contains a **timestamp** indicating the last time it was modified.

### SAM

The file/hive **SAM** contains the **users, groups and users passwords** hashes of the system.

In `SAM\Domains\Account\Users` you can obtain the username, the RID, last login, last failed logon, login counter, password policy and when the account was created. To get the **hashes** you also **need** the file/hive **SYSTEM**.

### Interesting entries in the Windows Registry

{% content-ref url="interesting-windows-registry-keys.md" %}
[interesting-windows-registry-keys.md](interesting-windows-registry-keys.md)
{% endcontent-ref %}

## Programs Executed

### Basic Windows Processes

On the following page you can learn about the basic Windows processes to detect suspicious behaviours:

{% content-ref url="windows-processes.md" %}
[windows-processes.md](windows-processes.md)
{% endcontent-ref %}

### Windows Recent APPs

Inside the registry `NTUSER.DAT` in the path `Software\Microsoft\Current Version\Search\RecentApps` you can subkeys with information about the **application executed**, **last time** it was executed, and **number of times** it was launched.

### BAM (Background Activity Moderator)

You can open the `SYSTEM` file with a registry editor and inside the path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` you can find the information about the **applications executed by each user** (note the `{SID}` in the path) and at **what time** they were executed (the time is inside the Data value of the registry).

### Windows Prefetch

Prefetching is a technique that allows a computer to silently **fetch the necessary resources needed to display content** that a user **might access in the near future** so resources can be accessed quicker.

Windows prefetch consists of creating **caches of the executed programs** to be able to load them faster. These caches as created as `.pf` files inside the path: `C:\Windows\Prefetch`. There is a limit of 128 files in XP/VISTA/WIN7 and 1024 files in Win8/Win10.

The file name is created as `{program_name}-{hash}.pf` (the hash is based on the path and arguments of the executable). In W10 these files are compressed. Do note that the sole presence of the file indicates that **the program was executed** at some point.

The file `C:\Windows\Prefetch\Layout.ini` contains the **names of the folders of the files that are prefetched**. This file contains **information about the number of the executions**, **dates** of the execution and **files** **open** by the program.

To inspect these files you can use the tool [**PEcmd.exe**](https://github.com/EricZimmerman/PECmd):

```bash
.\PECmd.exe -d C:\Users\student\Desktop\Prefetch --html "C:\Users\student\Desktop\out_folder"
```

![](<../../../.gitbook/assets/image (487).png>)

### Superprefetch

**Superprefetch** has the same goal as prefetch, **load programs faster** by predicting what is going to be loaded next. However, it doesn't substitute the prefetch service.\
This service will generate database files in `C:\Windows\Prefetch\Ag*.db`.

In these databases you can find the **name** of the **program**, **number** of **executions**, **files** **opened**, **volume** **accessed**, **complete** **path**, **timeframes** and **timestamps**.

You can access this information using the tool [**CrowdResponse**](https://www.crowdstrike.com/resources/community-tools/crowdresponse/).

### SRUM

**System Resource Usage Monitor** (SRUM) **monitors** the **resources** **consumed** **by a process**. It appeared in W8 and it stores the data in an ESE database located in `C:\Windows\System32\sru\SRUDB.dat`.

It gives the following information:

* AppID and Path
* User that executed the process
* Sent Bytes
* Received Bytes
* Network Interface
* Connection duration
* Process duration

This information is updated every 60 mins.

You can obtain the date from this file using the tool [**srum\_dump**](https://github.com/MarkBaggett/srum-dump).

```bash
.\srum_dump.exe -i C:\Users\student\Desktop\SRUDB.dat -t SRUM_TEMPLATE.xlsx -o C:\Users\student\Desktop\srum
```

### AppCompatCache (ShimCache)

**Shimcache**, also known as **AppCompatCache**, is a component of the **Application Compatibility Database**, which was created by **Microsoft** and used by the operating system to identify application compatibility issues.

The cache stores various file metadata depending on the operating system, such as:

* File Full Path
* File Size
* **$Standard\_Information** (SI) Last Modified time
* ShimCache Last Updated time
* Process Execution Flag

This information can be found in the registry in:

* `SYSTEM\CurrentControlSet\Control\SessionManager\Appcompatibility\AppcompatCache`
  * XP (96 entries)
* `SYSTEM\CurrentControlSet\Control\SessionManager\AppcompatCache\AppCompatCache`
  * Server 2003 (512 entries)
  * 2008/2012/2016 Win7/Win8/Win10 (1024 entries)

You can use the tool [**AppCompatCacheParser**](https://github.com/EricZimmerman/AppCompatCacheParser) to parse this information.

![](<../../../.gitbook/assets/image (488).png>)

### Amcache

The **Amcache.hve** file is a registry file that stores the information of executed applications. It's located in `C:\Windows\AppCompat\Programas\Amcache.hve`

**Amcache.hve** records the recent processes that were run and list the path of the files that are executed which can then be used to find the executed program. It also records the SHA1 of the program.

You can parse this information with the tool [**Amcacheparser**](https://github.com/EricZimmerman/AmcacheParser)

```bash
AmcacheParser.exe -f C:\Users\student\Desktop\Amcache.hve --csv C:\Users\student\Desktop\srum
```

The most interesting CVS file generated is the `Amcache_Unassociated file entries`.

### RecentFileCache

This artifact can only be found in W7 in `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` and it contains information about the recent execution of some binaries.

You can use the tool [**RecentFileCacheParse**](https://github.com/EricZimmerman/RecentFileCacheParser) to parse the file.

### Scheduled tasks

You can extract them from `C:\Windows\Tasks` or `C:\Windows\System32\Tasks` and read them as XML.

### Services

You can find them in the registry under `SYSTEM\ControlSet001\Services`. You can see what is going to be executed and when.

### **Windows Store**

The installed applications can be found in `\ProgramData\Microsoft\Windows\AppRepository\`\
This repository has a **log** with **each application installed** in the system inside the database **`StateRepository-Machine.srd`**.

Inside the Application table of this database, it's possible to find the columns: "Application ID", "PackageNumber", and "Display Name". These columns have information about pre-installed and installed applications and it can be found if some applications were uninstalled because the IDs of installed applications should be sequential.

It's also possible to **find installed application** inside the registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`\
And **uninstalled** **applications** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Windows Events

Information that appears inside Windows events are:

* What happened
* Timestamp (UTC + 0)
* Users involved
* Hosts involved (hostname, IP)
* Assets accessed (files, folder, printer, services)

The logs are located in `C:\Windows\System32\config` before Windows Vista and in `C:\Windows\System32\winevt\Logs` after Windows Vista. Before Windows Vista, the event logs were in binary format and after it, they are in **XML format** and use the **.evtx** extension.

The location of the event files can be found in the SYSTEM registry in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

They can be visualized from the Windows Event Viewer (**`eventvwr.msc`**) or with other tools like [**Event Log Explorer**](https://eventlogxp.com) **or** [**Evtx Explorer/EvtxECmd**](https://ericzimmerman.github.io/#!index.md)**.**

### Security

This registers the access events and gives information about the security configuration which can be found in `C:\Windows\System32\winevt\Security.evtx`.

The **max size** of the event file is configurable, and it will start overwriting old events when the maximum size is reached.

Events that are registered as:

* Login/Logoff
* Actions of the user
* Access to files, folders and shared assets
* Modification of the security configuration

Events related to user authentication:

| EventID   | Description                  |
| --------- | ---------------------------- |
| 4624      | Successful authentication    |
| 4625      | Authentication error         |
| 4634/4647 | log off                      |
| 4672      | Login with admin permissions |

Inside the EventID 4634/4647 there are interesting sub-types:

* **2 (interactive)**: The login was interactive using the keyboard or software like VNC or `PSexec -U-`
* **3 (network)**: Connection to a shared folder
* **4 (Batch)**: Process executed
* **5 (service)**: Service started by the Service Control Manager
* **6 (proxy):** Proxy Login
* **7 (Unlock)**: Screen unblocked using password
* **8 (network cleartext)**: User authenticated sending clear text passwords. This event used to come from the IIS
* **9 (new credentials)**: It's generated when the command `RunAs` is used or the user access a network service with different credentials.
* **10 (remote interactive)**: Authentication via Terminal Services or RDP
* **11 (cache interactive)**: Access using the last cached credentials because it wasn't possible to contact the domain controller
* **12 (cache remote interactive)**: Login remotely with cached credentials (a combination of 10 and 11).
* **13 (cached unlock)**: Unlock a locked machine with cached credentials.

In this post, you can find how to mimic all these types of login and in which of them you will be able to dump credentials from memory: [https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them)

The Status and sub status information of the events can indicate more details about the causes of the event. For example, take a look at the following Status and Sub Status Codes of the Event ID 4625:

![](<../../../.gitbook/assets/image (455).png>)

### Recovering Windows Events

It's highly recommended to turn off the suspicious PC by **unplugging it** to maximize the probability of recovering the Windows Events. In case they were deleted, a tool that can be useful to try and recover them is [**Bulk\_extractor**](../partitions-file-systems-carving/file-data-carving-recovery-tools.md#bulk-extractor) indicating the **evtx** extension.

## Identifying Common Attacks with Windows Events

### Brute Force Attack

A brute force attack can be easily identifiable because **several EventIDs 4625 will appear**. If the attack was **successful**, after the EventIDs 4625, **an EventID 4624 will appear**.

### Time Change

This is awful for the forensics team as all the timestamps will be modified. This event is recorded by the EventID 4616 inside the Security Event log.

### USB devices

The following System EventIDs are useful:

* 20001 / 20003 / 10000: First time it was used
* 10100: Driver update

The EventID 112 from DeviceSetupManager contains the timestamp of each USB device inserted.

### Turn Off / Turn On

The ID 6005 of the "Event Log" service indicates the PC was turned On. The ID 6006 indicates it was turned Off.

### Logs Deletion

The Security EventID 1102 indicates the logs were deleted.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

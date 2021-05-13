# Windows Forensics

## Windows 10 Notifications

In the path `\Users\<username>\AppData\Local\Microsoft\Windows\Notifications` you can find the database `appdb.dat` \(before Windows anniversary\)  or `wpndatabase.db` \(after Windows Anniversary\).

Inside this SQLite database you can find the `Notification` table with all the notifications \(in xml format\) that may contain interesting data.

## Timeline

Timeline is a Windows characteristic that provides **chronological history** of web pages visited, edited documents, executed applications...  
The database resides in the path `\Users\<username>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db`  
This database can be open with a SQLite tool or with the tool [**WxTCmd**](https://github.com/EricZimmerman/WxTCmd) ****which generates 2 files that can be opened with the tool [**TimeLine Explorer**](https://ericzimmerman.github.io/#!index.md).

## Windows RecentAPPs

Inside the registry `NTUSER.DAT` in the path `Software\Microsoft\Current Version\Search\RecentApps` you can subkeys with information about the **application executed**, **last time** it was executed, and **number of times** it was launched.

## BAM

You can open the `SYSTEM` file with a registry editor and inside the path `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}` you can find the information about the **applications executed by each user** \(note the `{SID}` in the path\) and at **what time** they were executed \(the time is inside the Data value of the registry\).

## Windows Mail App

This application saves the emails in HTML or text. You can find the emails inside subfolders inside `\Users\<username>\AppData\Local\Comms\Unistore\data\3\`. The emails are saved with `.dat` extension.

The **metadata** of the emails and the **contacts** can be found inside the **EDB database**: `\Users\<username>\AppData\Local\Comms\UnistoreDB\store.vol`

**Change the extension** of the file from `.vol` to `.edb` and you can use the tool [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) to open it. Inside the `Message` table you can see the emails.

## Plug and Play Cleanup

The 'Plug and Play Cleanup' scheduled task is responsible for **clearing** legacy versions of drivers. It would appear \(based upon reports online\) that it also picks up **drivers which have not been used in 30 days**, despite its description stating that "the most current version of each driver package will be kept". As such, **removable devices which have not been connected for 30 days may have their drivers removed**.   
The scheduled task itself is located at ‘C:\Windows\System32\Tasks\Microsoft\Windows\Plug and Play\Plug and Play Cleanup’, and its content is displayed below:

![](https://2.bp.blogspot.com/-wqYubtuR_W8/W19bV5S9XyI/AAAAAAAANhU/OHsBDEvjqmg9ayzdNwJ4y2DKZnhCdwSMgCLcBGAs/s1600/xml.png)

The task references 'pnpclean.dll' which is responsible for performing the cleanup activity additionally we see that the ‘UseUnifiedSchedulingEngine’ field is set to ‘TRUE’ which specifies that the generic task scheduling engine is used to manage the task. The ‘Period’ and ‘Deadline’ values of 'P1M' and 'P2M' within ‘MaintenanceSettings’ instruct Task Scheduler to execute the task once every month during regular Automatic maintenance and if it fails for 2 consecutive months, to start attempting the task during.  
**This section was copied from** [**here**](https://blog.1234n6.com/2018/07/windows-plug-and-play-cleanup.html)**.**

## **Windows Store**

The installed applications can be found in `\ProgramData\Microsoft\Windows\AppRepository\`  
This repository has a **log** with **each application installed** in the system inside the database **`StateRepository-Machine.srd`**.

Inside the Application table of this database it's possible to find the columns: "Application ID", "PackageNumber", and "Display Name". This columns have information about pre-installed and installed applications and it can be found if some applications were uninstalled because the IDs of installed applications should be sequential.

It's also possible to **find installed application** inside the registry path: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\`  
And **uninstalled** **applications** in: `Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deleted\`

## Office AutoSaved Files

You can find the office autosaved files in : `C:\Usuarios\\AppData\Roaming\Microsoft{Excel|Word|Powerpoint}\`

## Shell Items

A shell item is an item taht contains information about how to access another file.

### Recent Documents \(LNK\)

Windows **automatically** **creates** these **shortcuts** when the user **open, uses or creates a file** in:

* Win7-Win10: `C:\Users\\AppData\Roaming\Microsoft\Windows\Recent\`
* Office: `C:\Users\\AppData\Roaming\Microsoft\Office\Recent\`

When a folder is created, a link to the folder, to the parent folder and to the grandparent folder is also created.

These automatically created link files **contain information about the origin** like if it's a **file** **or** a **folder**, **MAC** **times** of that file, **volume informatio**n of where is the file stored and **folder of the target file**.  
This information can be useful to recover those files in case they were removed.

Also, the **date created of the link** file is the first **time** the original file was **first** **used** and the **date** **modified** of the link file is the **last** **time** the origin file was used.

### Jumplists

These are the recent files that are indicated per application. It's the list of **recent files used by an application** that you can access on each application.

They can be created **automatically or be custom**.

The **jumplists** created automatically are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`.  
The jumplists are named following the format `{id}.autmaticDestinations-ms` where the initial ID is the ID of the application.

The custom jumlists are stored in `C:\Users\{username}\AppData\Roaming\Microsoft\Windows\Recent\CustomDestination\` and they are created by the application usually because something **important** has happened with the file \(maybe marked as favorite\)

The **created time** of any jumlist indicates the **first time the file was accessed** and the **modified time the last time**.

You can inspect the jumlists using [**JumplistExplorer**](https://ericzimmerman.github.io/#!index.md).

## Windows Events

Information that appears inside Windows events:

* What happened
* Timestamp \(UTC + 0\)
* Users involved
* Hosts involved \(hostname, IP\)
* Assets accessed \(files, folder, printer, services\)

The logs are located in `C:\Windows\System32\config` before Windows Vista and in `C:\Windows\System32\winevt\Logs` after Windows Vista.

Before Windows Vista the event logs were in binary format and after it, they are in **XML format** and use the **.evtx** extension.

The location of the event files can be found in the SYSTEM registry in **`HKLM\SYSTEM\CurrentControlSet\services\EventLog\{Application|System|Security}`**

They can be visualized from the Windows Event Viewer \(**`eventvwr.msc`**\) or with other tools like [**Event Log Explorer**](https://eventlogxp.com/)**.**

### Security

These event register the accesses and give information about the security configuration.  
they can be found in `C:\Windows\System32\winevt\Security.evtx`.

The **max size** of the event file is configurable, and it will start overwriting old events when the maximum size is reached.

Events that are registered:

* Login/Logoff
* Actions of the user
* Access to files, folders and shared assets
* Modification of the security configuration

Events related to the user authentication:

| EventID | Description |
| :--- | :--- |
| 4624 | Successful authentication |
| 4625 | Authentication error |
| 4634/4647 | log off |
| 4672 | Logon with admin permissions |

Inside the EventID 4634/4647 there are interesting sub-types:

* **2 \(interactive\)**: The login was interactive using the keyboard or software like VNC or `PSexec -U-`
* **3 \(network\)**: Connection to a shared folder
* **4 \(Batch\)**: Process executed
* **5 \(service\)**: Service started by the Service Control Manager
* **7**: Screen unblocked using password
* **8 \(network cleartext\)**: User authenticated sendin clear text passwords. This event use to come from the IIS
* **9 \(new credentials\)**: It's generated when the command `RunAs` is used or the user access to a network service with different credentials.
* **10 \(remote interactive\)**: Authentication via Terminal Services or RDP
* **11 \(cache interactive\)**: Access using the last cached credentials because it wasn't possible to contact the domain controller

The Status and sub status information of the event s can indicate more details about the causes of the event. For example take a look to the following Status and Sub Status Codes of the Event ID 4625:

![](../../../.gitbook/assets/image%20%28455%29.png)

### Recovering Windows Events

It's highly recommended to turn off the suspicious PC by **unplugging it** to maximize the probabilities of recovering the Windows Events. In case they were deleted, a tool that can be useful to try to recover them is [**Bulk\_extractor**](../file-extraction.md#bulk-extractor) indicating the **evtx** extension.

## Identifying Common Attacks with Windows Events

### Brute-Force Attack

A brute-force attack can be easily identifiable because **several EventIDs 4625 will appear**. **If** the attack was **successful**, after the EventIDs 4625, **an EventID 4624 will appear**.

### Time Change

This is awful for the forensics team as all the timestamps will be modified.  
This event is recorded by the EventID 4616 inside the Security Event log.

### USB devices

The following System EventIDs are useful:

* 20001 / 20003 / 10000: First time it was used
* 10100: Driver update 

The EventID 112 from DeviceSetupManager contains the timestamp of each USB device inserted.

### Turn Off / Turn On

The ID 6005 of the "Event Log" service indicates the PC was turned On. The ID 6006 indicates it was turned Off.

### Logs Deletion

The Security EventID 1102 indicates the logs were deleted.

## Windows Registry

The Windows Registry Contains a lot of **information** about the **system and the actions of the users**.

The files containing the registry are located in:

* %windir%\System32\Config\**SAM**:  `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\**SECURITY**:  `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\**SYSTEM**:  `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\**SOFTWARE**:  `HKEY_LOCAL_MACHINE`
* %windir%\System32\Config\**DEFAULT**:  `HKEY_LOCAL_MACHINE`
* %UserProfile%\{User}\**NTUSER.DAT**:  `HKEY_CURRENT_USER`

From Windows Vista and Windows 2008 Server upwards there are some backups of the `HKEY_LOCAL_MACHINE` registry files in **`%Windir%\System32\Config\RegBack\`**.  
Also from these versions, the registry file **`%UserProfile%\{User}\AppData\Local\Microsoft\Windows\USERCLASS.DAT`** is created saving information about program executions.

### Tools

Some tools are useful to analyzed the registry files:

* **Registry Editor**: It's installed in Windows. It's a GUI to navigate through the Windows registry of the current session.
* \*\*\*\*[**Registry Explorer**](https://ericzimmerman.github.io/#!index.md): It allows to load the registry file and navigate through them with a GUI. It also contains Bookmarks highlighting keys with interesting information.
* \*\*\*\*[**RegRipper**](https://github.com/keydet89/RegRipper3.0): Again, it has a GUI that allows to navigate through the loaded registry and also contains plugins that highlight interesting information inside the loaded registry.
* \*\*\*\*[**Windows Registry Recovery**](https://www.mitec.cz/wrr.html): Another GUI application capable of extracting the important information from the registry loaded.

### Recovering Deleted Element

When a key is deleted it's marked as such but until the space it's occupying is needed it won't be removed. Therefore, using tools like **Registry Explorer** it's possible to recover these deleted keys.

### Last Write Time

Each Key-Value contains a **timestamp** indicating the last time it was modified.

### SAM

The file/hive **SAM** contains the **users, groups and users passwords** hashes of the system.  
In `SAM\Domains\Account\Users` you can obtain the username, the RID, last logon, last failed logon, login counter, password policy and when the account was created. In order to get the **hashes** you also **need** the file/hive **SYSTEM**.

### Interesting entries in the Windows Registry

#### \*\*\*\*

* 
